import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { join } from 'node:path'
import { host } from './harness.js'
import { DshClient, mobileSessionId } from '../src/dsh-client.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand } from '../src/protocol.js'
import type { InteractionRouter } from '../src/interaction-router.js'

test('a persisted dispatching message retries after a host context restart without duplicating the DSH message', async t => {
  const firstHost = await host({ probe: false, retainDirectory: true })
  t.after(() => rm(firstHost.directory, { recursive: true, force: true }))
  const signal = new AbortController()
  const journalPath = join(firstHost.directory, 'journal', 'commands.sqlite')
  const owner = {
    userId: '77777777-7777-4777-8777-777777777777',
    deviceId: '22222222-2222-4222-8222-222222222222',
  }
  let journal = await PersistentCommandJournal.open(journalPath, firstHost.runtimeId)
  let secondHost: Awaited<ReturnType<typeof host>> | undefined
  let firstHostClosed = false
  try {
    const client = new DshClient(firstHost.ctx, firstHost.runtimeId, [{ id: 'fixture', cwd: firstHost.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal.signal)
    const firstAgent = firstHost.ctx.agents.get(native)!
    const requestId = randomUUID()
    const command = parseCommand({
      v: 0, type: 'message.submit', request_id: requestId, runtime_epoch: randomUUID(),
      session_id: created.session_id, payload: { mode: 'queue', text: 'crash-safe retry probe' },
    })

    journal.admit(command, owner)
    journal.start(requestId, owner)
    const original = await client.prompt(native, `${owner.deviceId}:${requestId}`, 'queue', 'crash-safe retry probe', signal.signal)
    assert.equal(original.checkpoint.state, 'persisted')
    await firstAgent.whenIdle()
    journal.close()
    await firstHost.close()
    firstHostClosed = true

    secondHost = await host({ probe: false, directory: firstHost.directory, retainDirectory: true, runtimeId: firstHost.runtimeId })
    journal = await PersistentCommandJournal.open(journalPath, secondHost.runtimeId)
    const clientAfterRestart = new DshClient(secondHost.ctx, secondHost.runtimeId, [{ id: 'fixture', cwd: secondHost.cwd }], ['fixture'])
    const interactions = { close() {} } as InteractionRouter
    const restarted = new ProbeRuntime(clientAfterRestart, interactions, journal)
    const receiptStates: string[] = []
    const retried = await restarted.dispatch({ ...command, runtime_epoch: restarted.epoch }, signal.signal, owner, state => { receiptStates.push(state) })
    assert.equal(retried.type, 'message.submit.result')
    assert.equal((retried.payload as { native_accepted: boolean }).native_accepted, true)
    assert.deepEqual(receiptStates, ['host_accepted', 'dispatching', 'agent_queued'])

    const replayReceiptStates: string[] = []
    await restarted.dispatch({ ...command, runtime_epoch: restarted.epoch }, signal.signal, owner, state => { replayReceiptStates.push(state) })
    assert.deepEqual(replayReceiptStates, ['host_accepted', 'agent_queued'])

    const restoredNative = await clientAfterRestart.resolve(created.session_id, signal.signal)
    const restoredAgent = secondHost.ctx.agents.get(restoredNative)!
    await restoredAgent.whenIdle()
    const messages = restoredAgent.session.snapshotEvents().filter(event => {
      if (event.type !== 'user/message') return false
      const source = event.data.source as unknown as { kind: string; rpcId?: string }
      return source.kind === 'user' && source.rpcId === `m0:${owner.deviceId}:${requestId}`
    })
    assert.equal(messages.length, 1)
    assert.equal(journal.get(requestId, owner)?.state, 'agent_queued')
    assert.equal(created.session_id, mobileSessionId(secondHost.runtimeId, restoredNative))

    const missingSessionCommand = parseCommand({
      v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: restarted.epoch,
      session_id: randomUUID(), payload: { mode: 'queue', text: 'uncertain after recovery' },
    })
    journal.admit(missingSessionCommand, owner)
    journal.start(missingSessionCommand.request_id, owner)
    await assert.rejects(restarted.dispatch(missingSessionCommand, signal.signal, owner), /session.not_found/)
    assert.equal(journal.get(missingSessionCommand.request_id, owner)?.state, 'outcome_unknown')
  } finally {
    signal.abort()
    journal.close()
    if (secondHost !== undefined) await secondHost.close()
    if (!firstHostClosed) await firstHost.close()
  }
})
