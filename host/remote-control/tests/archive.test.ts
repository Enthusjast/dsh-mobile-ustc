import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { SessionId } from '@deepseek-ai/dsh-session'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { WorkspaceActiveSessionError } from '@deepseek-ai/dsh-workspace'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { parseCommand } from '../src/protocol.js'
import { ProbeRuntime } from '../src/runtime.js'
import { MemoryCommandJournal } from '../src/command-journal.js'
import type { InteractionRouter } from '../src/interaction-router.js'

const signal = () => new AbortController().signal

test('native archive survives Loader recreation, drops the pin and preserves history and workspace position', async () => {
  const h = await host({ probe: false, retainDirectory: true })
  let reopened: Awaited<ReturnType<typeof host>> | undefined
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const workspace = await h.ctx.workspaceRegistry.create(h.cwd)
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    await workspace.attachSession(native)
    await client.prompt(native, randomUUID(), 'queue', 'preserve this conversation', signal())
    const agent = h.ctx.agents.get(native)!
    await agent.whenIdle()
    await client.checkpoint(native)
    const events = agent.session.snapshotEvents()
    const position = [...workspace.sessionIds]
    await h.ctx.workspaceRegistry.pinSession(native)
    await h.ctx.workspaceRegistry.archiveSession(native)
    await h.ctx.workspaceRegistry.archiveSession(native)
    assert.deepEqual(h.ctx.workspaceRegistry.archivedSessionIds, [native])
    assert.deepEqual(h.ctx.workspaceRegistry.pinnedSessionIds, [])
    assert.deepEqual(workspace.sessionIds, position)
    assert.deepEqual(agent.session.snapshotEvents(), events)
    await h.close()
    reopened = await host({ probe: false, directory: h.directory, retainDirectory: true, runtimeId: h.runtimeId })
    assert.deepEqual(reopened.ctx.workspaceRegistry.archivedSessionIds, [native])
    assert.deepEqual(reopened.ctx.workspaceRegistry.get(workspace.id)!.sessionIds, position)
    const next = new DshClient(reopened.ctx, h.runtimeId, [{ id: 'fixture', cwd: reopened.cwd }], ['fixture'])
    assert.equal(await next.resolve(created.session_id, signal()), native)
    await reopened.ctx.workspaceRegistry.unarchiveSession(native)
    await next.prompt(native, randomUUID(), 'queue', 'continue after restore', signal())
    const restored = reopened.ctx.agents.get(native)!
    await restored.whenIdle()
    assert.deepEqual(restored.session.snapshotEvents().slice(0, events.length), events)
    assert.equal(restored.session.snapshotEvents().filter(event => event.type === 'assistant/message').length, 2)
    assert.equal(reopened.errors.length, 0)
  } finally {
    if (reopened) await reopened.close()
    else await h.close()
    await rm(h.directory, { recursive: true, force: true })
  }
})

test('native idle archive refuses a running turn; archive-and-stop writes before stopping and discards queued input', async () => {
  const h = await host({ probe: false })
  const held = h.model.holdNext()
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    const agent = h.ctx.agents.get(native)!
    await client.prompt(native, randomUUID(), 'queue', 'start work', signal())
    await held.started
    await client.prompt(native, randomUUID(), 'queue', 'queued before archive', signal())
    await assert.rejects(h.ctx.workspaceRegistry.archiveSession(native), error =>
      error instanceof WorkspaceActiveSessionError && error.activity.some(item => item.kind === 'turn'))
    assert.deepEqual(h.ctx.workspaceRegistry.archivedSessionIds, [])
    assert.equal(agent.status, 'running')
    let stopRequests = 0
    const dispose = h.ctx.on('workspace/session-stop', ({ sessionId }) => {
      assert.equal(sessionId, native)
      assert.ok(h.ctx.workspaceRegistry.archivedSessionIds.includes(native), 'stop preceded archive durability')
      stopRequests++
    })
    await h.ctx.workspaceRegistry.archiveSession(native, { stopActivity: true })
    await agent.whenIdle()
    await h.ctx.workspaceRegistry.archiveSession(native, { stopActivity: true })
    dispose()
    assert.equal(stopRequests, 1)
    const events = agent.session.snapshotEvents()
    assert.equal(events.some(event => event.type === 'assistant/message'), false)
    assert.ok(events.some(event => event.type === 'turn/end'))
    assert.ok(events.some(event => event.type === 'agent/inbox/spliced' && event.data.outcome === 'canceled'))
    assert.equal(h.errors.length, 0)
  } finally { held.release(); await h.close() }
})

test('native archived-session gate blocks late model steps and admits continuation after restore', async () => {
  const h = await host({ probe: false })
  try {
    const { sessionId } = await h.ctx.sessionController.create({ cwd: h.cwd, agentPreset: 'fixture' })
    const native = SessionId(sessionId)
    const agent = h.ctx.agents.get(native)!
    await h.ctx.workspaceRegistry.archiveSession(native)
    await h.ctx.sessionController.prompt({ sessionId: native, requestId: randomUUID() as never, mode: 'queue', content: [{ type: 'text', text: 'late delivery' }] }, signal())
    await agent.whenIdle()
    assert.equal(agent.session.snapshotEvents().some(event => event.type === 'assistant/message'), false)
    assert.ok(agent.session.snapshotEvents().some(event => event.type === 'turn/end'))
    await h.ctx.workspaceRegistry.unarchiveSession(native)
    await h.ctx.sessionController.prompt({ sessionId: native, requestId: randomUUID() as never, mode: 'queue', content: [{ type: 'text', text: 'restored delivery' }] }, signal())
    await agent.whenIdle()
    assert.equal(agent.session.snapshotEvents().filter(event => event.type === 'assistant/message').length, 1)
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})

test('native archive gates subagent descendants but leaves a fork independent', async () => {
  const h = await host({ probe: false })
  try {
    const { sessionId: parent } = await h.ctx.sessionController.create({ cwd: h.cwd, agentPreset: 'fixture' })
    const child = SessionId(`child-${randomUUID()}`)
    const fork = SessionId(`fork-${randomUUID()}`)
    for (const [id, origin] of [[child, 'subagent'], [fork, undefined]] as const) {
      await h.ctx.agents.create({ sessionId: id, meta: { cwd: h.cwd, parentSession: parent, ...(origin ? { origin } : {}) }, agentOptions: { provider: 'fixture', model: 'fixture' } })
    }
    await h.ctx.workspaceRegistry.archiveSession(parent)
    for (const id of [child, fork]) {
      h.ctx.agents.get(id)!.followup(createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'lineage delivery' }] }))
      await h.ctx.agents.get(id)!.whenIdle()
    }
    assert.equal(h.ctx.agents.get(child)!.session.snapshotEvents().some(event => event.type === 'assistant/message'), false)
    assert.equal(h.ctx.agents.get(fork)!.session.snapshotEvents().some(event => event.type === 'assistant/message'), true)
    await h.ctx.workspaceRegistry.unarchiveSession(parent)
    h.ctx.agents.get(child)!.followup(createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'restored lineage' }] }))
    await h.ctx.agents.get(child)!.whenIdle()
    assert.equal(h.ctx.agents.get(child)!.session.snapshotEvents().some(event => event.type === 'assistant/message'), true)
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})

test('adapter projects durable desktop archive changes, retains history access and refuses archived writes', async () => {
  const h = await host({ probe: false })
  let stopWatching = () => {}
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    const changes: string[][] = []
    stopWatching = client.watchSessionCatalog(change => { if (change.kind === 'delta') changes.push([...change.sessionIds]) })
    await h.ctx.workspaceRegistry.archiveSession(native)
    await new Promise(resolve => setTimeout(resolve, 250))
    assert.deepEqual(changes, [[native]])
    assert.equal((await client.sessionCatalog(signal()))[0]!.state, 'archived')
    assert.equal((await client.list(signal())).items[0]!.archived, true)
    assert.equal(await client.resolve(created.session_id, signal()), native)
    await assert.rejects(client.prompt(native, randomUUID(), 'queue', 'must restore first', signal()), /session.archived/)
    await assert.rejects(client.selectModel(native, { provider: 'fixture', model: 'fixture' }), /session.archived/)
    const read = client.follow(native, 30, signal())[Symbol.asyncIterator]()
    assert.equal((await read.next()).value!.type, 'snapshot')
    await read.return?.()
    await client.archive(native, false, false)
    await new Promise(resolve => setTimeout(resolve, 250))
    assert.deepEqual(changes, [[native], [native]])
    assert.equal((await client.sessionCatalog(signal()))[0]!.state, 'available')
  } finally { stopWatching(); await h.close() }
})

test('archive journal settles only after native durability, refuses active work and never infers a crashed command from current state', async () => {
  const h = await host({ probe: false })
  const held = h.model.holdNext()
  const interactions = { close() {} } as InteractionRouter
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const journal = new MemoryCommandJournal(h.runtimeId)
  const runtime = new ProbeRuntime(client, interactions, journal)
  const owner = { userId: 'local', deviceId: 'local' }
  try {
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    const command = parseCommand({ v: 0, type: 'session.archive', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id, payload: { archived: true, stop_activity: false } })
    assert.throws(() => parseCommand({ ...command, payload: { archived: false, stop_activity: true } }), /protocol.invalid/)
    await client.prompt(native, randomUUID(), 'queue', 'running work', signal())
    await held.started
    const registry = h.ctx.workspaceRegistry
    const originalArchive = registry.archiveSession.bind(registry)
    let archiveCalls = 0
    registry.archiveSession = async (...args) => { archiveCalls++; return await originalArchive(...args) }
    await assert.rejects(runtime.dispatch(command, signal()), /session.active/)
    assert.equal(archiveCalls, 0, 'active preflight must reject before invoking the workspace mutation')
    registry.archiveSession = originalArchive
    assert.equal(journal.admit(command, owner).state, 'rejected')
    const archive = parseCommand({ ...command, request_id: randomUUID(), payload: { archived: true, stop_activity: true } })
    const states: string[] = []
    const result = await runtime.dispatch(archive, signal(), owner, state => {
      states.push(state)
      if (state === 'settled') assert.ok(h.ctx.workspaceRegistry.archivedSessionIds.includes(native))
    })
    assert.deepEqual(states, ['host_accepted', 'dispatching', 'settled'])
    await h.ctx.agents.get(native)!.whenIdle()
    // A settled retry is historical evidence, even if the desktop restored it.
    await h.ctx.workspaceRegistry.unarchiveSession(native)
    assert.deepEqual(await runtime.dispatch(archive, signal()), result)
    assert.equal(h.ctx.workspaceRegistry.archivedSessionIds.includes(native), false)
    const crashed = { ...command, request_id: randomUUID() }
    journal.admit(crashed, owner)
    journal.start(crashed.request_id, owner)
    await h.ctx.workspaceRegistry.archiveSession(native)
    await assert.rejects(runtime.dispatch(crashed, signal()), /outcome_unknown/)
    assert.equal(journal.admit(crashed, owner).state, 'outcome_unknown')
    const restarted = new ProbeRuntime(client, interactions, journal)
    await assert.rejects(restarted.dispatch({ ...archive, runtime_epoch: restarted.epoch }, signal()), /request_conflict/)
    restarted.close()
  } finally { held.release(); runtime.close(); await h.close() }
})

test('an unrecognized active-shaped error after archive is attempted remains an unknown outcome', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const journal = new MemoryCommandJournal(h.runtimeId)
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
  const owner = { userId: 'local', deviceId: 'local' }
  const originalArchive = h.ctx.workspaceRegistry.archiveSession.bind(h.ctx.workspaceRegistry)
  try {
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    const foreignError = Object.assign(new Error('foreign workspace error'), {
      name: 'WorkspaceActiveSessionError', sessionId: native, activity: [{ kind: 'turn' }],
    })
    h.ctx.workspaceRegistry.archiveSession = async () => { throw foreignError }
    const command = parseCommand({ v: 0, type: 'session.archive', request_id: randomUUID(), runtime_epoch: runtime.epoch,
      session_id: created.session_id, payload: { archived: true, stop_activity: false } })
    await assert.rejects(runtime.dispatch(command, signal()), /foreign workspace error/)
    assert.equal(journal.admit(command, owner).state, 'outcome_unknown')
  } finally {
    h.ctx.workspaceRegistry.archiveSession = originalArchive
    runtime.close()
    await h.close()
  }
})
