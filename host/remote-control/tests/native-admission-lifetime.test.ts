import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { ProbeRuntime } from '../src/runtime.js'
import { MemoryCommandJournal } from '../src/command-journal.js'
import type { InteractionRouter } from '../src/interaction-router.js'
import { parseCommand } from '../src/protocol.js'

function gate() {
  let entered!: () => void, release!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const waiting = new Promise<void>(resolve => { release = resolve })
  return { started, release, async hold() { entered(); await waiting } }
}

test('cancelled or retired commands cannot cancel a native Agent after session resolution returns late', async t => {
  for (const mode of ['request', 'runtime'] as const) await t.test(mode, { timeout: 5000 }, async () => {
    const h = await host({ probe: false })
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const journal = new MemoryCommandJournal(h.runtimeId)
    const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
    const pending = gate(), owner = new AbortController()
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, owner.signal)
    const agent = h.ctx.agents.get(native)!
    const held = h.model.holdNext()
    try {
      await client.prompt(native, randomUUID(), 'queue', 'held native work', AbortSignal.timeout(2000))
      await held.started
      const controller = h.ctx.sessionController
      const inspect = controller.inspect.bind(controller), cancel = controller.cancel.bind(controller)
      controller.inspect = async (...args) => { const value = await inspect(...args); await pending.hold(); return value }
      let cancellations = 0
      controller.cancel = (...args) => { cancellations++; return cancel(...args) }
      const result = runtime.dispatch(parseCommand({ v: 0, type: 'session.cancel', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id, payload: {} }), owner.signal)
      void result.catch(() => {})
      await pending.started
      if (mode === 'request') owner.abort()
      else runtime.close()
      pending.release()
      await assert.rejects(result)
      assert.equal(cancellations, 0, 'stale request entered native cancellation')
      assert.equal(h.ctx.agents.get(native), agent)
    } finally { pending.release(); held.release(); await agent.whenIdle(); runtime.close(); await h.close() }
  })
})

test('request cancellation during archive activity inspection cannot persist an archive', { timeout: 5000 }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter)
  const pending = gate(), owner = new AbortController()
  try {
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, owner.signal)
    h.ctx.on('workspace/session-activity', async (_input, next) => { const value = await next(); await pending.hold(); return value })
    const result = runtime.dispatch(parseCommand({ v: 0, type: 'session.archive', request_id: randomUUID(), runtime_epoch: runtime.epoch,
      session_id: created.session_id, payload: { archived: true, stop_activity: false } }), owner.signal)
    void result.catch(() => {})
    await pending.started
    owner.abort(); pending.release()
    await assert.rejects(result)
    assert.equal(h.ctx.workspaceRegistry.archivedSessionIds.includes(native), false, 'stale request persisted an archive')
  } finally { pending.release(); runtime.close(); await h.close() }
})

test('request cancellation during model catalog lookup cannot enter native selection', { timeout: 5000 }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter)
  const pending = gate(), owner = new AbortController()
  try {
    const created = await client.create('fixture', 'fixture')
    const controller = h.ctx.sessionController
    const catalog = controller.modelCatalog.bind(controller), select = controller.selectModel.bind(controller)
    controller.modelCatalog = async (...args) => { const value = await catalog(...args); await pending.hold(); return value }
    let selections = 0
    controller.selectModel = async (...args) => { selections++; return select(...args) }
    const result = runtime.dispatch(parseCommand({ v: 0, type: 'session.model.select', request_id: randomUUID(), runtime_epoch: runtime.epoch,
      session_id: created.session_id, payload: { provider: 'fixture', model: 'fixture' } }), owner.signal)
    void result.catch(() => {})
    await pending.started
    owner.abort(); pending.release()
    await assert.rejects(result)
    assert.equal(selections, 0, 'stale request entered native model selection')
  } finally { pending.release(); runtime.close(); await h.close() }
})

test('cancellation during dispatching receipt cannot create a native session afterward', { timeout: 5000 }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter)
  const pending = gate(), owner = new AbortController()
  try {
    const controller = h.ctx.sessionController, create = controller.create.bind(controller)
    let creations = 0
    controller.create = async (...args) => { creations++; return create(...args) }
    const result = runtime.dispatch(parseCommand({ v: 0, type: 'session.create', request_id: randomUUID(), runtime_epoch: runtime.epoch,
      payload: { workspace: 'fixture', preset: 'fixture' } }), owner.signal, undefined, async state => { if (state === 'dispatching') await pending.hold() })
    void result.catch(() => {})
    await pending.started
    owner.abort(); pending.release()
    await assert.rejects(result)
    assert.equal(creations, 0, 'stale request entered native session creation')
  } finally { pending.release(); runtime.close(); await h.close() }
})

test('cancellation after native entry retains a known completed result', { timeout: 5000 }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const journal = new MemoryCommandJournal(h.runtimeId)
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
  const pending = gate(), owner = new AbortController()
  const held = h.model.holdNext()
  try {
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, owner.signal)
    await client.prompt(native, randomUUID(), 'queue', 'native work cancelled before late acknowledgement', AbortSignal.timeout(2000))
    await held.started
    const controller = h.ctx.sessionController, cancel = controller.cancel.bind(controller)
    let cancellations = 0
    controller.cancel = (...args) => { cancellations++; return cancel(...args) }
    const command = parseCommand({ v: 0, type: 'session.cancel', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id, payload: {} })
    const result = runtime.dispatch(command, owner.signal, undefined, async state => { if (state === 'settled') await pending.hold() })
    void result.catch(() => {})
    await pending.started
    owner.abort(); pending.release()
    await result
    await h.ctx.agents.get(native)!.whenIdle()
    assert.equal(cancellations, 1)
    assert.equal(journal.lookup(command, { userId: 'local', deviceId: 'local' })?.state, 'settled', 'known native completion became a false cancellation')
  } finally { pending.release(); held.release(); runtime.close(); await h.close() }
})
