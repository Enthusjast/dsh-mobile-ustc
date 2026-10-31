import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { SessionId } from '@deepseek-ai/dsh-session'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { MemoryCommandJournal, PersistentCommandJournal } from '../src/command-journal.js'
import { ProbeRuntime } from '../src/runtime.js'
import { InteractionRouter } from '../src/interaction-router.js'
import { parseCommand } from '../src/protocol.js'

class RecordingClient extends DshClient {
  forkCalls = 0
  override forkNative(id: SessionId, seq: number) { this.forkCalls++; return super.forkNative(id, seq) }
}

async function fixture() {
  const h = await host({ probe: false })
  const workspaceId = randomUUID()
  const workspace = await h.ctx.workspaceRegistry.create(h.cwd)
  const client = new RecordingClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd, remoteId: workspaceId }], ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const signal = AbortSignal.timeout(15_000)
  const native = await client.resolve(created.session_id, signal)
  await workspace.attachSession(native)
  await client.prompt(native, randomUUID(), 'queue', 'visible original source message', signal)
  await h.ctx.agents.get(native)!.whenIdle()
  await client.checkpoint(native)
  const original = h.ctx.agents.get(native)!.session.snapshotEvents()
  const target = original.find(event => event.type === 'user/message')!
  const journal = new MemoryCommandJournal(h.runtimeId)
  const runtime = new ProbeRuntime(client, new InteractionRouter(h.ctx, h.runtimeId, () => true, [], 1000), journal)
  const owner = { userId: randomUUID(), deviceId: randomUUID() }
  const binding = { runtimeId: h.runtimeId, runtimeEpoch: runtime.epoch, sessionId: created.session_id, subscriptionId: randomUUID(), syncId: randomUUID(), ...owner }
  const preview = await runtime.messageActions.preview(binding, { sync_id: binding.syncId, native_seq: target.seq }, () => true, signal)
  const command = parseCommand({ v: 0, type: 'session.fork', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id,
    payload: { workspace_id: workspaceId, anchor: preview.anchor } })
  return { h, client, runtime, owner, binding, preview, command, journal, native, workspace, original, target, signal }
}

test('real native fork clones inclusive persisted prefix, leaves source unchanged and original runs once', async () => {
  const f = await fixture()
  try {
    const first = await f.runtime.dispatch(f.command, f.signal, f.owner)
    const result = first.payload as { child_session_id: string; checkpoint: { state: string }; catalog_item: { dsh_session_id: SessionId } }
    assert.equal(result.checkpoint.state, 'persisted')
    const child = f.h.ctx.agents.get(result.catalog_item.dsh_session_id)!
    assert.ok(child)
    assert.deepEqual(child.session.snapshotEvents().slice(0, f.target.seq + 1), f.original.slice(0, f.target.seq + 1))
    assert.deepEqual(f.h.ctx.agents.get(f.native)!.session.snapshotEvents(), f.original)
    assert.notEqual(result.child_session_id, f.command.type === 'session.fork' ? f.command.session_id : '')
    assert.equal((await f.runtime.dispatch(f.command, f.signal, f.owner)).payload, first.payload)
    assert.equal(f.client.forkCalls, 1)
  } finally { f.runtime.close(); f.journal.close(); await f.h.close() }
})

test('actual workspace attach failure retains created child and never forks original again', async t => {
  const f = await fixture()
  try {
    t.mock.method(f.workspace, 'attachSession', async () => { throw new Error('controlled workspace attach failure') })
    const result = (await f.runtime.dispatch(f.command, f.signal, f.owner)).payload as { child_session_id: string; fork_outcome: { workspace_attachment: string; checkpoint: string } }
    assert.equal(result.fork_outcome.workspace_attachment, 'failed')
    assert.equal(result.fork_outcome.checkpoint, 'persisted')
    assert.ok(result.child_session_id)
    await f.runtime.dispatch(f.command, f.signal, f.owner)
    assert.equal(f.client.forkCalls, 1)
    assert.deepEqual(f.h.ctx.agents.get(f.native)!.session.snapshotEvents(), f.original)
  } finally { f.runtime.close(); f.journal.close(); await f.h.close() }
})

test('preview authority is owner/version bound and share confirmation returns only explicit current text', async () => {
  const f = await fixture()
  try {
    const confirmed = await f.runtime.messageActions.confirm(f.binding, { sync_id: f.binding.syncId, anchor: f.preview.anchor }, () => true, f.signal)
    assert.equal(confirmed.text, 'visible original source message')
    await assert.rejects(f.runtime.messageActions.validateFork(f.binding.sessionId, randomUUID(), f.preview.anchor, f.owner, f.signal), /access.denied/)
    await assert.rejects(f.runtime.messageActions.validateFork(f.binding.sessionId, f.command.type === 'session.fork' ? f.command.payload.workspace_id : '', f.preview.anchor, { ...f.owner, deviceId: randomUUID() }, f.signal), /message.stale/)
    await assert.rejects(f.runtime.messageActions.confirm(f.binding, { sync_id: f.binding.syncId, anchor: { ...f.preview.anchor, message_version_sha256: '0'.repeat(64) } }, () => true, f.signal), /message.stale/)
    assert.equal(f.client.forkCalls, 0)
  } finally { f.runtime.close(); f.journal.close(); await f.h.close() }
})

test('durable dispatch partial child survives restart and uncertain original can never dispatch again', async t => {
  const root = await mkdtemp(join(tmpdir(), 'session-fork-journal-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtime = randomUUID(), owner = { userId: randomUUID(), deviceId: randomUUID() }
  const command = parseCommand({ v: 0, type: 'session.fork', request_id: randomUUID(), runtime_epoch: randomUUID(), session_id: randomUUID(), payload: { workspace_id: randomUUID(),
    anchor: { v: 1, subscription_id: randomUUID(), sync_id: randomUUID(), native_seq: 5, message_version_sha256: 'a'.repeat(64), anchor_sha256: 'b'.repeat(64) } } })
  const path = join(root, 'commands.sqlite')
  let journal = await PersistentCommandJournal.open(path, runtime)
  const partial = { child_session_id: randomUUID(), fork_outcome: { v: 1, workspace_attachment: 'failed', checkpoint: 'unknown' } }
  journal.admit(command, owner); journal.start(command.request_id, owner); journal.noteResult(command.request_id, owner, partial); journal.close()
  journal = await PersistentCommandJournal.open(path, runtime)
  try {
    assert.equal(journal.lookup(command, owner)?.state, 'outcome_unknown')
    assert.deepEqual(journal.lookup(command, owner)?.result, partial)
    journal.fail(command.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
    assert.deepEqual(journal.lookup(command, owner)?.result, partial)
    assert.throws(() => journal.start(command.request_id, owner), /invalid_transition/)
    assert.throws(() => journal.noteResult(command.request_id, owner, { ...partial, child_session_id: randomUUID() }), /invalid_transition/)
  } finally { journal.close() }
})
