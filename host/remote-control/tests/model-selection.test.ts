import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { PersistentCommandJournal, commandDigest } from '../src/command-journal.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand } from '../src/protocol.js'
import { relayModelSelectionDigest } from '../src/relay-client.js'
import type { InteractionRouter } from '../src/interaction-router.js'

test('model selection checkpoints one native event and reconstructs its durable receipt without selection replay', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const path = join(h.directory, 'model-journal', 'commands.sqlite')
  let journal = await PersistentCommandJournal.open(path, h.runtimeId)
  let runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
  const owner = { userId: randomUUID(), deviceId: randomUUID() }
  try {
    const created = await client.create('fixture', 'fixture')
    const command = parseCommand({ v: 0, type: 'session.model.select', request_id: randomUUID(), runtime_epoch: runtime.epoch,
      session_id: created.session_id, payload: { provider: 'fixture', model: 'fixture' } })
    assert.equal(commandDigest(command), relayModelSelectionDigest(created.session_id, runtime.epoch, { provider: 'fixture', model: 'fixture' }))
    const result = await runtime.dispatch(command, AbortSignal.timeout(5000), owner)
    assert.equal((result.payload as any).checkpoint.state, 'persisted')
    const native = await client.resolve(created.session_id, AbortSignal.timeout(5000))
    const event = h.ctx.sessions.get(native)!.snapshotEvents().find(event => event.type === 'model/selection')!
    assert.ok(event)
    assert.ok((result.payload as any).checkpoint.through_seq >= event.seq)
    assert.equal(journal.get(command.request_id, owner)?.state, 'settled')
    const epoch = runtime.epoch
    runtime.close(); journal.close()
    journal = await PersistentCommandJournal.open(path, h.runtimeId)
    runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal, epoch)
    const select = h.ctx.sessionController.selectModel.bind(h.ctx.sessionController)
    let calls = 0
    h.ctx.sessionController.selectModel = async (...args) => { calls++; return select(...args) }
    const states: string[] = []
    const replay = await runtime.dispatch(command, AbortSignal.timeout(5000), owner, state => { states.push(state) })
    assert.deepEqual(replay.payload, result.payload)
    assert.deepEqual(states, ['host_accepted', 'settled'])
    assert.equal(calls, 0)
    await assert.rejects(runtime.dispatch({ ...command, payload: { provider: 'fixture', model: 'different' } } as typeof command, AbortSignal.timeout(5000), owner), /command.request_conflict/)
    assert.notEqual(commandDigest({ ...command, runtime_epoch: randomUUID() }), commandDigest(command))
  } finally { runtime.close(); journal.close(); await h.close() }
})

test('unavailable catalog selections reject and failed model checkpoints remain unknown without native replay', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const journal = await PersistentCommandJournal.open(join(h.directory, 'model-journal', 'commands.sqlite'), h.runtimeId)
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
  try {
    const created = await client.create('fixture', 'fixture')
    const command = (payload: object) => parseCommand({ v: 0, type: 'session.model.select', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id, payload })
    for (const payload of [{ provider: 'unavailable', model: 'fixture' }, { provider: 'fixture', model: 'unavailable' }, { provider: 'fixture', model: 'fixture', reasoning_effort: 'unavailable' }]) {
      const invalid = command(payload)
      await assert.rejects(runtime.dispatch(invalid, AbortSignal.timeout(5000)), /model.not_available/)
      assert.equal(journal.get(invalid.request_id, { userId: 'local', deviceId: 'local' })?.state, 'rejected')
    }
    client.checkpoint = async () => ({ state: 'failed' })
    const selection = command({ provider: 'fixture', model: 'fixture' })
    const result = await runtime.dispatch(selection, AbortSignal.timeout(5000))
    assert.equal((result.payload as any).command_state, 'outcome_unknown')
    h.ctx.sessionController.selectModel = async () => { throw new Error('unknown selection was replayed') }
    await assert.rejects(runtime.dispatch(selection, AbortSignal.timeout(5000)), /command.outcome_unknown/)
    const interrupted = command({ provider: 'fixture', model: 'fixture' })
    const owner = { userId: 'local', deviceId: 'local' }
    journal.admit(interrupted, owner); journal.start(interrupted.request_id, owner)
    await assert.rejects(runtime.dispatch(interrupted, AbortSignal.timeout(5000)), /command.outcome_unknown/)
    assert.equal(journal.get(interrupted.request_id, owner)?.state, 'outcome_unknown')
  } finally { runtime.close(); journal.close(); await h.close() }
})
