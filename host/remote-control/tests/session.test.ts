import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { host } from './harness.js'
import { DshClient, mobileSessionId } from '../src/dsh-client.js'
import { SessionSync } from '../src/session-sync.js'
import { parseCommand } from '../src/protocol.js'
import { ProbeRuntime } from '../src/runtime.js'
import { MemoryCommandJournal } from '../src/command-journal.js'
import type { InteractionRouter } from '../src/interaction-router.js'

test('current-process controller creates, continues and checkpoints the same Agent, then follows a gap-free log', async () => {
  const h = await host({ probe: false })
  const signal = new AbortController()
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal.signal)
    const original = h.ctx.agents.get(native)!
    assert.ok(original)
    const accepted = await client.prompt(native, randomUUID(), 'queue', 'hello', signal.signal)
    assert.equal(accepted.native_accepted, true)
    assert.equal(accepted.checkpoint.state, 'persisted')
    await original.whenIdle()
    assert.equal(h.ctx.agents.get(native), original)
    const sync = new SessionSync(client, randomUUID())
    const command = parseCommand({ v: 0, type: 'session.subscribe', request_id: randomUUID(), runtime_epoch: randomUUID(), session_id: created.session_id, payload: {} })
    assert.equal(command.type, 'session.subscribe')
    if (command.type !== 'session.subscribe') throw new Error('wrong fixture')
    const iterator = sync.follow(command, signal.signal)[Symbol.asyncIterator]()
    const snapshot = (await iterator.next()).value!
    assert.equal(snapshot.type, 'session.snapshot')
    const payload = snapshot.payload as { records: { native_seq: number; type: string }[]; cursor: number }
    assert.ok(payload.records.some(record => record.type === 'assistant/message'))
    assert.equal((await iterator.next()).value!.type, 'session.checkpoint')
    const pageCommand = parseCommand({ v: 0, type: 'session.page', request_id: randomUUID(), runtime_epoch: randomUUID(), session_id: created.session_id,
      payload: { sync_id: snapshot.sync_id, through_seq: payload.cursor, before_seq: payload.cursor + 1 } })
    if (pageCommand.type !== 'session.page') throw new Error('wrong fixture')
    const page = await sync.page(pageCommand, signal.signal)
    assert.ok(page.records.length > 0)
    await assert.rejects(sync.page({ ...pageCommand, payload: { ...pageCommand.payload, sync_id: randomUUID() } }, signal.signal), /resync_required/)
    const checkpoint = await h.ctx.sessionController.rename({ sessionId: native, title: 'live title' })
    const event = (await iterator.next()).value!
    assert.equal(event.type, 'session.event')
    assert.equal((event.payload as { native_seq: number }).native_seq, checkpoint.seq)
    signal.abort()
    await iterator.return?.()
  } finally { signal.abort(); await h.close() }
})

test('workspace and profile boundaries reject arbitrary native paths and child takeover', async () => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    await assert.rejects(client.create('/etc', 'fixture'), /access.denied/)
    await assert.rejects(client.create('fixture', 'unknown'), /access.denied/)
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, new AbortController().signal)
    const other = new DshClient(h.ctx, randomUUID(), [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    await assert.rejects(other.resolve(created.session_id, new AbortController().signal), /session.not_found/)
    assert.notEqual(created.session_id, mobileSessionId(other.runtimeId, 'opaque'))
    const hidden = new DshClient(h.ctx, h.runtimeId, [], [])
    assert.deepEqual(await hidden.list(new AbortController().signal), { items: [] })
    assert.deepEqual(await hidden.sessionCatalog(new AbortController().signal), [])
    const removal = await hidden.sessionCatalog(new AbortController().signal, [String(native)])
    assert.equal(removal.length, 1)
    assert.equal(removal[0]?.session_id, created.session_id)
    assert.equal(removal[0]?.state, 'unavailable')
    assert.equal(removal[0]?.workspace_id, null)
  } finally { await h.close() }
})

test('model catalog only exposes and selects models already registered on the desktop', async () => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, new AbortController().signal)
    const catalog = await client.modelCatalog()
    assert.ok(catalog.groups.some(group => group.id === 'fixture' && group.models.some(model => model.id === 'fixture')))
    assert.deepEqual(await client.selectModel(native, { provider: 'fixture', model: 'fixture' }), {
      selected: { provider: 'fixture', model: 'fixture' }, checkpoint: { state: 'persisted', through_seq: 0 },
    })
    await assert.rejects(client.selectModel(native, { provider: 'not-configured', model: 'arbitrary' }), /model.not_available/)
    await assert.rejects(client.selectModel(native, { provider: 'fixture', model: 'fixture', reasoning_effort: 'arbitrary' }), /model.not_available/)
  } finally { await h.close() }
})

test('active-session steer reaches the same Agent and is recorded with its stable request id', async () => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, new AbortController().signal)
    const original = h.ctx.agents.get(native)!
    const held = h.model.holdNext()
    await client.prompt(native, randomUUID(), 'queue', 'start active work', new AbortController().signal)
    await held.started
    const steerRequest = randomUUID()
    const response = await client.prompt(native, steerRequest, 'steer', 'redirect the active step', new AbortController().signal)
    assert.equal(response.native_accepted, true)
    held.release()
    await original.whenIdle()
    assert.equal(h.ctx.agents.get(native), original)
    const messages = original.session.snapshotEvents().filter(event => event.type === 'user/message')
    assert.ok(messages.some(event => {
      const source = event.data.source as unknown as { kind: string; rpcId?: string }
      return source.kind === 'user' && source.rpcId === `m0:${steerRequest}`
    }), JSON.stringify(messages.map(event => event.data)))
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})

test('cancel stops an in-flight model call and leaves the active turn settled', async () => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, new AbortController().signal)
    const original = h.ctx.agents.get(native)!
    const held = h.model.holdNext()
    await client.prompt(native, randomUUID(), 'queue', 'start cancelable work', new AbortController().signal)
    await held.started
    assert.deepEqual(client.cancel(native), { accepted: true })
    await original.whenIdle()
    const events = original.session.snapshotEvents()
    assert.ok(events.some(event => event.type === 'turn/end'))
    assert.equal(events.some(event => event.type === 'assistant/message'), false)
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})

test('in-epoch concurrent retries are serialized and conflicts cannot dispatch again', async () => {
  let calls = 0
  const client = { create: async () => { calls++; return { session_id: randomUUID() } } } as unknown as DshClient
  const interactions = { close() {} } as InteractionRouter
  const runtime = new ProbeRuntime(client, interactions)
  const command = parseCommand({ v: 0, type: 'session.create', request_id: randomUUID(), runtime_epoch: runtime.epoch, payload: { workspace: 'fixture', preset: 'fixture' } })
  const responses = await Promise.all([runtime.dispatch(command, new AbortController().signal), runtime.dispatch(command, new AbortController().signal)])
  assert.equal(calls, 1)
  assert.deepEqual(responses[0], responses[1])
  if (command.type !== 'session.create') throw new Error('wrong fixture')
  await assert.rejects(runtime.dispatch({ ...command, payload: { ...command.payload, preset: 'changed' } }, new AbortController().signal), /request_conflict/)
  await assert.rejects(runtime.dispatch({ ...command, runtime_epoch: randomUUID() }, new AbortController().signal), /runtime.changed/)
  runtime.close()
  await assert.rejects(runtime.dispatch(command, new AbortController().signal), /runtime.offline/)
})

test('a settled cancellation retries without executing again and cannot move to another runtime epoch', async () => {
  let cancels = 0
  const client = { runtimeId: randomUUID(), resolve: async () => 'native', cancel() { cancels++; return { accepted: true } } } as unknown as DshClient
  const interactions = { close() {} } as InteractionRouter
  const journal = new MemoryCommandJournal(client.runtimeId)
  const runtime = new ProbeRuntime(client, interactions, journal)
  const command = parseCommand({ v: 0, type: 'session.cancel', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: randomUUID(), payload: {} })
  const signal = new AbortController().signal
  const firstStates: string[] = [], retryStates: string[] = []
  const first = await runtime.dispatch(command, signal, undefined, state => { firstStates.push(state) })
  const retry = await runtime.dispatch(command, signal, undefined, state => { retryStates.push(state) })
  assert.deepEqual(first, retry)
  assert.equal(cancels, 1)
  assert.deepEqual(firstStates, ['host_accepted', 'dispatching', 'settled'])
  assert.deepEqual(retryStates, ['host_accepted', 'settled'])
  runtime.close()
  const restarted = new ProbeRuntime(client, interactions, journal)
  await assert.rejects(restarted.dispatch(command, signal), /runtime.changed/)
  await assert.rejects(restarted.dispatch({ ...command, runtime_epoch: restarted.epoch }, signal), /command.request_conflict/)
  assert.equal(cancels, 1)
  restarted.close()
})

test('remote creation maps one configured workspace, persists its catalog result and never replays ambiguous work', async () => {
  const h = await host({ probe: false })
  const workspaceId = randomUUID()
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', remoteId: workspaceId, cwd: h.cwd }], ['fixture'])
  const interactions = { close() {} } as InteractionRouter
  const journal = new MemoryCommandJournal(client.runtimeId)
  const runtime = new ProbeRuntime(client, interactions, journal)
  const signal = new AbortController().signal
  try {
    const command = parseCommand({ v: 0, type: 'session.create', request_id: randomUUID(), runtime_epoch: runtime.epoch, payload: { workspace_id: workspaceId, preset: 'fixture' } })
    const states: string[] = []
    let settled: unknown
    const first = await runtime.dispatch(command, signal, undefined, (state, result) => { states.push(state); if (state === 'settled') settled = result })
    assert.deepEqual(states, ['host_accepted', 'dispatching', 'settled'])
    const result = first.payload as { session_id: string; checkpoint: { state: string }; catalog_item: { session_id: string; workspace_id: string } }
    assert.equal(result.checkpoint.state, 'persisted')
    assert.equal(result.catalog_item.session_id, result.session_id)
    assert.equal(result.catalog_item.workspace_id, workspaceId)
    assert.deepEqual(settled, result)
    const retry = await runtime.dispatch(command, signal, undefined, (state, value) => { if (state === 'settled') settled = value })
    assert.deepEqual(retry, first)
    assert.deepEqual(settled, result, 'recovered receipt lost its persisted creation metadata')
    const count = (await client.list(signal)).items.length
    assert.equal(count, 1)
    await assert.rejects(runtime.dispatch({ ...command, request_id: randomUUID(), payload: { workspace_id: workspaceId, preset: 'not-configured' } } as typeof command, signal), /access.denied/)
    await assert.rejects(client.createRemote(randomUUID(), 'fixture', signal), /access.denied/)
    const ambiguous = { ...command, request_id: randomUUID() }
    journal.admit(ambiguous, { userId: 'local', deviceId: 'local' })
    journal.start(ambiguous.request_id, { userId: 'local', deviceId: 'local' })
    await assert.rejects(runtime.dispatch(ambiguous, signal), /command.outcome_unknown/)
    runtime.close()
    const restarted = new ProbeRuntime(client, interactions, journal)
    await assert.rejects(restarted.dispatch({ ...command, runtime_epoch: restarted.epoch }, signal), /command.request_conflict/)
    assert.equal((await client.list(signal)).items.length, count)
    restarted.close()
  } finally { runtime.close(); await h.close() }
})
