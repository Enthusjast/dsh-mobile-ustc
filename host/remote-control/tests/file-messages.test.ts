import test from 'node:test'
import type { TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { readFile } from 'node:fs/promises'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { MemoryCommandJournal, PersistentCommandJournal, type CommandJournal, type CommandState } from '../src/command-journal.js'
import { InteractionRouter } from '../src/interaction-router.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand, type Command } from '../src/protocol.js'
import type { FileOffer } from '../src/file-protocol.js'

async function fixture(t: TestContext) {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const owner = { userId: randomUUID(), deviceId: randomUUID() }
  const life = new AbortController()
  let journal: CommandJournal = new MemoryCommandJournal(h.runtimeId)
  const makeRuntime = () => new ProbeRuntime(client, new InteractionRouter(h.ctx, h.runtimeId, () => true, [], 1000), journal)
  let runtime = makeRuntime()
  t.after(async () => { runtime.close(); journal.close(); life.abort(); await h.close() })
  const body = Buffer.from('file message source bytes\x00\xff')
  const stage = async (confirm = true) => {
    const file: FileOffer = { file_id: randomUUID(), handoff_id: randomUUID(), user_id: owner.userId, device_id: owner.deviceId, key_version: 1, grant_version: 1,
      name: 'message.txt', size_bytes: body.length, sha256: createHash('sha256').update(body).digest('hex'), download_token: 'A'.repeat(43),
      lease_until: new Date(Date.now() + 5000).toISOString(), expires_at: new Date(Date.now() + 300_000).toISOString() }
    await runtime.files.stage(created.session_id, file, (async function* () { yield body })(), life.signal, () => !life.signal.aborted)
    if (confirm) runtime.files.confirm(file.file_id)
    return file
  }
  const command = (files: string[], request: string = randomUUID(), session = created.session_id): Command => parseCommand({
    v: 0, type: 'message.submit', request_id: request, runtime_epoch: runtime.epoch, session_id: session,
    payload: { mode: 'queue', content: [{ type: 'text', text: 'Inspect these files.' }, ...files.map(file_id => ({ type: 'file', file_id }))] },
  })
  const human = async () => {
    const native = await client.resolve(created.session_id, life.signal)
    await h.ctx.agents.get(native)!.whenIdle()
    return h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message').filter(event => event.data.source.kind === 'user')
  }
  return { h, client, owner, life, session: created.session_id, body, stage, command, human,
    get runtime() { return runtime }, get journal() { return journal },
    replace(next: CommandJournal) { runtime.close(); journal.close(); journal = next; runtime = makeRuntime() },
  }
}

test('native message resolves only confirmed file IDs for the exact actor/session and retires receipts after one prompt', async t => {
  const f = await fixture(t)
  const file = await f.stage()
  const part = f.runtime.files.resolve(file.file_id, f.session, f.owner)
  assert.equal(part.type, 'file')
  for (const actor of [{ ...f.owner, userId: randomUUID() }, { ...f.owner, deviceId: randomUUID() }]) {
    const states: CommandState[] = []
    await assert.rejects(f.runtime.dispatch(f.command([file.file_id]), f.life.signal, actor, state => { states.push(state) }), /file.staging_required/)
    assert.deepEqual(states, ['host_accepted', 'dispatching', 'rejected'])
    assert.equal(f.runtime.files.available(file.file_id), true)
  }
  await assert.rejects(f.runtime.dispatch(f.command([file.file_id], randomUUID(), (await f.client.create('fixture', 'fixture')).session_id), f.life.signal, f.owner), /file.staging_required/)
  const command = f.command([file.file_id])
  const accepted = await f.runtime.dispatch(command, f.life.signal, f.owner)
  assert.equal(f.journal.admit(command, f.owner).state, 'agent_queued')
  const messages = await f.human()
  assert.equal(messages.length, 1)
  assert.ok(messages[0]!.data.content.some(content => content.type === 'file' && content.attachment.attachmentId === `sha256:${file.sha256}`))
  assert.equal(f.runtime.files.available(file.file_id), false)
  assert.deepEqual(await f.runtime.dispatch(command, f.life.signal, f.owner), accepted)
  assert.equal((await f.human()).length, 1)
  await assert.rejects(f.runtime.dispatch(f.command([file.file_id]), f.life.signal, f.owner), /file.staging_required/)
  await assert.rejects(f.runtime.dispatch(f.command([randomUUID()], command.request_id), f.life.signal, f.owner), /command.request_conflict/)
  if (part.type === 'file') assert.equal(JSON.stringify(accepted).includes(part.receiptId), false)
})

test('unconfirmed or cancelled mappings and missing file parts reject the whole message before native admission', async t => {
  const f = await fixture(t), file = await f.stage(false)
  await assert.rejects(f.runtime.dispatch(f.command([file.file_id]), f.life.signal, f.owner), /file.staging_required/)
  f.runtime.files.confirm(file.file_id)
  await assert.rejects(f.runtime.dispatch(f.command([file.file_id, randomUUID()]), f.life.signal, f.owner), /file.staging_required/)
  assert.equal(f.runtime.files.available(file.file_id), true)
  const rejected = f.command([file.file_id])
  f.life.abort()
  await assert.rejects(f.runtime.dispatch(rejected, new AbortController().signal, f.owner), /file.staging_required/)
  const native = await f.client.resolve(f.session, new AbortController().signal)
  assert.equal(f.h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message').filter(event => event.data.source.kind === 'user').length, 0)
})

test('persistent dispatch recovery reconciles a native file message after losing every staged receipt', async t => {
  const f = await fixture(t)
  const path = join(f.h.directory, 'file-command.sqlite')
  f.replace(await PersistentCommandJournal.open(path, f.h.runtimeId))
  const file = await f.stage(), original = f.command([file.file_id])
  const part = f.runtime.files.resolve(file.file_id, f.session, f.owner)
  f.journal.admit(original, f.owner); f.journal.start(original.request_id, f.owner)
  const native = await f.client.resolve(f.session, f.life.signal)
  await f.client.prompt(native, `${f.owner.deviceId}:${original.request_id}`, 'queue', [{ type: 'text', text: 'Inspect these files.' }, part], f.life.signal)
  await f.h.ctx.agents.get(native)!.whenIdle()
  f.runtime.close(); f.journal.close()
  f.replace(await PersistentCommandJournal.open(path, f.h.runtimeId))
  const retried = { ...original, runtime_epoch: f.runtime.epoch }
  const states: CommandState[] = []
  const result = await f.runtime.dispatch(retried, f.life.signal, f.owner, state => { states.push(state) })
  assert.deepEqual(states, ['host_accepted', 'dispatching', 'agent_queued'])
  assert.equal(f.journal.admit(retried, f.owner).state, 'agent_queued')
  assert.equal((await f.human()).length, 1)
  assert.deepEqual(await f.runtime.dispatch(retried, f.life.signal, f.owner), result)
  const onDisk = await readFile(path)
  if (part.type === 'file') assert.equal(onDisk.includes(Buffer.from(part.receiptId)), false)
})

test('an ambiguous file dispatch without native evidence stays unknown and cannot enqueue with a placeholder receipt', async t => {
  const f = await fixture(t), file = await f.stage()
  const original = f.command([file.file_id])
  f.journal.admit(original, f.owner); f.journal.start(original.request_id, f.owner)
  const journal = f.journal
  f.runtime.close()
  // A new Runtime uses the durable dispatch state, with no native receipt map.
  const runtime = new ProbeRuntime(f.client, new InteractionRouter(f.h.ctx, f.h.runtimeId, () => true, [], 1000), journal)
  t.after(() => runtime.close())
  const retried = { ...original, runtime_epoch: runtime.epoch }
  await assert.rejects(runtime.dispatch(retried, f.life.signal, f.owner))
  assert.equal(journal.admit(retried, f.owner).state, 'outcome_unknown')
  await assert.rejects(runtime.dispatch(retried, f.life.signal, f.owner), /command.outcome_unknown/)
  assert.equal((await f.human()).length, 0)
})

test('local file references reject duplicates, native receipts and paths', () => {
  const frame = { v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: randomUUID(), session_id: randomUUID() }
  const file = { type: 'file', file_id: randomUUID() }
  for (const content of [[file, file], [{ ...file, receiptId: randomUUID() }], [{ ...file, path: '/private/file' }]]) {
    assert.throws(() => parseCommand({ ...frame, payload: { mode: 'queue', content } }), /protocol.invalid/)
  }
})
