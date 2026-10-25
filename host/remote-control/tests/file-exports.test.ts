import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { mkdir, writeFile, symlink, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { crc32, deflateSync } from 'node:zlib'
import { host } from './harness.js'
import { DshClient, type Workspace } from '../src/dsh-client.js'
import { FileExportRegistry, type ExportAuthority } from '../src/file-export-registry.js'
import { PinnedExportSource } from '../src/file-export-source.js'
import { sessionAttachmentSource } from '../src/session-file-export.js'
import { ProbeError } from '../src/protocol.js'
import { ProbeRuntime } from '../src/runtime.js'
import type { InteractionRouter } from '../src/interaction-router.js'

const signal = () => new AbortController().signal
const current = () => {}
const authority = (): ExportAuthority => ({ owner: { userId: randomUUID(), deviceId: randomUUID() }, signal: signal(), current })
const supported = await PinnedExportSource.supported()
async function read(registry: FileExportRegistry, id: string, session: string, actor: ExportAuthority) {
  const chunks: Uint8Array[] = []
  for await (const chunk of registry.read(id, session, actor)) chunks.push(chunk)
  return Buffer.concat(chunks)
}

test('workspace exports require an explicit root and bind opaque IDs to the exact Session and device', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const workspace: Workspace = { id: 'fixture', cwd: h.cwd, exportRoots: [{ id: 'deliverables', directory: 'reports' }] }
  const client = new DshClient(h.ctx, h.runtimeId, [workspace], ['fixture'])
  const registry = new FileExportRegistry(client)
  try {
    const session = (await client.create('fixture', 'fixture')).session_id
    await mkdir(join(h.cwd, 'reports')); await writeFile(join(h.cwd, 'reports', '结果.bin'), Buffer.from([0, 1, 255]))
    await writeFile(join(h.cwd, 'private'), 'outside the allowed export root')
    const actor = authority()
    const entry = await registry.registerWorkspaceArtifact(session, 'deliverables', ['结果.bin'], actor)
    assert.deepEqual(Object.keys(entry).sort(), ['export_id', 'expires_at', 'name', 'origin', 'sha256', 'size_bytes'].sort())
    assert.equal(entry.name, '结果.bin'); assert.equal(entry.origin, 'workspace_artifact')
    assert.equal(JSON.stringify(entry).includes(h.cwd), false); assert.equal(JSON.stringify(registry), '{}')
    assert.throws(() => registry.describe(entry.export_id, session, { ...actor, owner: { ...actor.owner, deviceId: randomUUID() } }), /file.export_unavailable/)
    assert.throws(() => registry.describe(entry.export_id, randomUUID(), actor), /file.export_unavailable/)
    await assert.rejects(registry.registerWorkspaceArtifact(session, 'unregistered', ['private'], actor), /access.denied/)
    await assert.rejects(registry.registerWorkspaceArtifact(session, 'deliverables', ['..', 'private'], actor), /file.export_invalid/)
    await symlink(join(h.cwd, 'private'), join(h.cwd, 'reports', 'linked'))
    await assert.rejects(registry.registerWorkspaceArtifact(session, 'deliverables', ['linked'], actor), /file.export_unavailable/)
    assert.deepEqual(await read(registry, entry.export_id, session, actor), Buffer.from([0, 1, 255]))
    await assert.rejects(read(registry, entry.export_id, session, actor), /file.export_unavailable/)
    const revoked = await registry.registerWorkspaceArtifact(session, 'deliverables', ['结果.bin'], actor)
    workspace.exportRoots = []
    await assert.rejects(read(registry, revoked.export_id, session, actor), /access.denied/)
    assert.equal(h.errors.length, 0)
  } finally { await registry.close(); await h.close() }
})

test('a real persisted DSH file reference exports exact bytes without a new Agent or prompt', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new FileExportRegistry(client)
  try {
    const session = (await client.create('fixture', 'fixture')).session_id
    const native = await client.resolve(session, signal()), original = h.ctx.agents.get(native)!
    const body = Buffer.from('session-scoped binary\0file')
    const manifest = { name: '持久附件.bin', size_bytes: body.length, sha256: createHash('sha256').update(body).digest('hex') }
    const upload = await client.uploadFile(session, manifest, (async function* () { yield body })(), signal())
    await client.prompt(native, randomUUID(), 'queue', [{ type: 'file', receiptId: upload.receiptId }], signal())
    await original.whenIdle()
    const message = original.session.snapshotEvents().find(event => event.type === 'user/message' && event.data.source.kind === 'user')!
    const actor = authority(), entry = await registry.registerSessionAttachment(session, message.seq, 0, actor)
    assert.equal(entry.origin, 'session_attachment'); assert.equal(entry.sha256, manifest.sha256)
    assert.deepEqual(await read(registry, entry.export_id, session, actor), body)
    assert.equal(h.ctx.agents.get(native), original)
    assert.equal(original.session.snapshotEvents().filter(event => event.type === 'user/message' && event.data.source.kind === 'user').length, 1)
    const other = (await client.create('fixture', 'fixture')).session_id
    await assert.rejects(registry.registerSessionAttachment(other, message.seq, 0, actor), /file.export_unavailable|session.persistence_unavailable/)
    const foreign = new DshClient(h.ctx, randomUUID(), [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    await assert.rejects(foreign.attachmentExportSource(session, message.seq, 0, signal(), current), /session.not_found/)
    const injected = { type: 'user/message', seq: 0, time: 1, data: { source: { kind: 'model-selection' }, content: [{ type: 'file', attachment: { ...upload.file } }] } }
    await assert.rejects(sessionAttachmentSource(h.ctx, injected, 0, signal(), current), /file.export_unavailable/)
    assert.equal(h.errors.length, 0)
  } finally { await registry.close(); await h.close() }
})

test('Loader recreation discards source IDs but can re-export a cold persisted attachment without activating an Agent', { skip: !supported }, async () => {
  const first = await host({ probe: false, retainDirectory: true })
  const client = new DshClient(first.ctx, first.runtimeId, [{ id: 'fixture', cwd: first.cwd }], ['fixture'])
  const registry = new FileExportRegistry(client)
  let second: Awaited<ReturnType<typeof host>> | undefined
  let firstClosed = false
  try {
    const session = (await client.create('fixture', 'fixture')).session_id, native = await client.resolve(session, signal())
    const body = Buffer.from('cold attachment bytes'), actor = authority()
    const upload = await client.uploadFile(session, { name: 'cold.bin', size_bytes: body.length, sha256: createHash('sha256').update(body).digest('hex') }, (async function* () { yield body })(), signal())
    await client.prompt(native, randomUUID(), 'queue', [{ type: 'file', receiptId: upload.receiptId }], signal())
    await first.ctx.agents.get(native)!.whenIdle(); assert.equal((await client.checkpoint(native)).state, 'persisted')
    const event = first.ctx.agents.get(native)!.session.snapshotEvents().find(item => item.type === 'user/message' && item.data.source.kind === 'user')!
    const old = await registry.registerSessionAttachment(session, event.seq, 0, actor)
    await registry.close(); await first.close(); firstClosed = true
    second = await host({ probe: false, retainDirectory: true, directory: first.directory, runtimeId: first.runtimeId })
    const fresh = new FileExportRegistry(new DshClient(second.ctx, first.runtimeId, [{ id: 'fixture', cwd: second.cwd }], ['fixture']))
    try {
      assert.equal(second.ctx.agents.get(native), undefined)
      assert.throws(() => fresh.describe(old.export_id, session, actor), /file.export_unavailable/)
      const entry = await fresh.registerSessionAttachment(session, event.seq, 0, actor)
      assert.notEqual(old.export_id, entry.export_id)
      assert.deepEqual(await read(fresh, entry.export_id, session, actor), body)
      assert.equal(second.ctx.agents.get(native), undefined); assert.equal(second.errors.length, 0)
    } finally { await fresh.close() }
  } finally {
    await registry.close(); if (second) await second.close(); if (!firstClosed) await first.close()
    await rm(first.directory, { recursive: true, force: true })
  }
})

test('invalid or ambiguous export policy is rejected before a filesystem source can be created', () => {
  for (const roots of [
    [{ id: 'reports', directory: '../private' }], [{ id: 'reports', directory: '/private' }], [{ id: 'reports', directory: 'a\\b' }],
    [{ id: 'reports', directory: '' }], [{ id: 'reports', directory: 'good' }, { id: 'reports', directory: 'other' }],
  ]) assert.throws(() => new DshClient({} as never, randomUUID(), [{ id: 'fixture', cwd: '/workspace', exportRoots: roots }], []), /file.export_invalid/)
})

test('closing the actual runtime drains prepared export sources and invalidates their identities', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd, exportRoots: [{ id: 'outputs', directory: 'outputs' }] }], ['fixture'])
  let closed = 0
  const runtime = new ProbeRuntime(client, { close() { closed++ } } as InteractionRouter)
  try {
    await mkdir(join(h.cwd, 'outputs')); await writeFile(join(h.cwd, 'outputs', 'result'), 'runtime owned source')
    const session = (await client.create('fixture', 'fixture')).session_id, actor = authority()
    const entry = await runtime.exports.registerWorkspaceArtifact(session, 'outputs', ['result'], actor)
    runtime.close(); await runtime.exports.close()
    await assert.rejects(read(runtime.exports, entry.export_id, session, actor), /access.denied/)
    assert.equal(closed, 1)
  } finally { await runtime.exports.close(); await h.close() }
})

test('the pinned native sandbox keeps its read-only policy while a declared artifact is exported', { skip: !supported }, async () => {
  const h = await host({ probe: false, filesystem: 'sandbox' })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd, exportRoots: [{ id: 'output', directory: 'output' }] }], ['fixture'])
  const registry = new FileExportRegistry(client)
  try {
    await mkdir(join(h.cwd, 'output')); await writeFile(join(h.cwd, 'output', 'result'), 'read-only artifact')
    const target = await h.ctx.fs.resolve(join(h.cwd, 'output', 'result'))
    const denied = (error: unknown) => (error as { code?: string }).code === 'FS_SANDBOX_DENIED'
    await assert.rejects(h.ctx.fs.writeText(target, 'must remain denied'), denied)
    const session = (await client.create('fixture', 'fixture')).session_id, actor = authority()
    const entry = await registry.registerWorkspaceArtifact(session, 'output', ['result'], actor)
    assert.equal((await read(registry, entry.export_id, session, actor)).toString(), 'read-only artifact')
    assert.equal(h.ctx.fs.sandboxMode, 'read-only')
    await assert.rejects(h.ctx.fs.writeText(target, 'still denied'), denied)
    assert.equal(h.errors.length, 0)
  } finally { await registry.close(); await h.close() }
})

test('a different filesystem execution world cannot export a coincidentally matching Host path', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  try {
    await mkdir(join(h.cwd, 'output')); await writeFile(join(h.cwd, 'output', 'result'), 'Host bytes outside the other world')
    const context = new Proxy(h.ctx, { get(target, key) {
      if (key === 'fs') return { readBytes() { throw new Error('foreign-world read denied') } }
      return Reflect.get(target, key, target)
    } })
    const client = new DshClient(context, h.runtimeId, [{ id: 'fixture', cwd: h.cwd, exportRoots: [{ id: 'output', directory: 'output' }] }], ['fixture'])
    const session = (await client.create('fixture', 'fixture')).session_id
    await assert.rejects(client.workspaceExportSource(session, 'output', ['result'], signal(), current), /file.export_unsupported/)
  } finally { await h.close() }
})

function pixelPNG(): Buffer {
  function chunk(type: string, value: Buffer) {
    const name = Buffer.from(type), header = Buffer.alloc(4), tail = Buffer.alloc(4)
    header.writeUInt32BE(value.length); tail.writeUInt32BE(crc32(Buffer.concat([name, value])))
    return Buffer.concat([header, name, value, tail])
  }
  const info = Buffer.alloc(13); info.writeUInt32BE(1, 0); info.writeUInt32BE(1, 4); info[8] = 8; info[9] = 6
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', info), chunk('IDAT', deflateSync(Buffer.from([0, 255, 0, 0, 255]))), chunk('IEND', Buffer.alloc(0))])
}

test('image export uses the persisted normalized image reference, not its input encoding or local path', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new FileExportRegistry(client)
  try {
    const session = (await client.create('fixture', 'fixture')).session_id, native = await client.resolve(session, signal())
    await h.ctx.sessionController.prompt({ sessionId: native, requestId: randomUUID() as never, mode: 'queue', content: [{ type: 'image', mediaType: 'image/png', data: pixelPNG().toString('base64'), name: '图片.png' }] }, signal())
    const agent = h.ctx.agents.get(native)!; await agent.whenIdle()
    const message = agent.session.snapshotEvents().find(event => event.type === 'user/message' && event.data.source.kind === 'user')!
    if (message.type !== 'user/message') throw new Error('missing native image')
    const image = message.data.content.find(part => part.type === 'image')!
    if (image.type !== 'image') throw new Error('missing image block')
    const expected = await h.ctx.attachments.readImage(image.attachment)
    const actor = authority(), entry = await registry.registerSessionAttachment(session, message.seq, 0, actor)
    assert.equal(entry.size_bytes, image.attachment.bytes)
    assert.deepEqual(await read(registry, entry.export_id, session, actor), Buffer.from(expected.data))
    assert.equal(h.errors.length, 0)
  } finally { await registry.close(); await h.close() }
})

test('registry resources drain on cancellation and shutdown, with bounded entries and hash concurrency', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  let calls = 0
  try {
    await writeFile(join(h.cwd, 'file'), 'bytes')
    const controller = new AbortController()
    const actor = { ...authority(), signal: controller.signal }
    const source = async (_session: string, _root: string, _parts: readonly string[], lifetime: AbortSignal, guard: () => void) => {
      calls++
      return PinnedExportSource.open({ root: h.cwd, parts: ['file'] }, lifetime, guard)
    }
    const registry = new FileExportRegistry({ workspaceExportSource: source, attachmentExportSource: async () => { throw new ProbeError('file.export_unavailable') } })
    try {
      const session = randomUUID()
      const entries = []
      for (let index = 0; index < 32; index++) entries.push(await registry.registerWorkspaceArtifact(session, 'root', ['file'], actor))
      await assert.rejects(registry.registerWorkspaceArtifact(session, 'root', ['file'], actor), /rate.limited/)
      assert.equal(calls, 32)
      controller.abort()
      await assert.rejects(read(registry, entries[0]!.export_id, session, actor), { name: 'AbortError' })
    } finally { await registry.close() }
    const fresh = new FileExportRegistry({ workspaceExportSource: source, attachmentExportSource: async () => { throw new ProbeError('file.export_unavailable') } })
    let resume!: () => void
    const held = new Promise<void>(resolve => { resume = resolve })
    const blocking = new FileExportRegistry({ workspaceExportSource: async (...args) => { await held; return source(...args) }, attachmentExportSource: async () => { throw new ProbeError('file.export_unavailable') } })
    try {
      const a = authority(), session = randomUUID()
      const pending = [blocking.registerWorkspaceArtifact(session, 'r', ['file'], a), blocking.registerWorkspaceArtifact(session, 'r', ['file'], a)]
      await assert.rejects(blocking.registerWorkspaceArtifact(session, 'r', ['file'], a), /rate.limited/)
      const closing = blocking.close(); resume()
      const results = await Promise.allSettled(pending); assert.ok(results.every(result => result.status === 'rejected'))
      await closing
      await assert.rejects(fresh.registerWorkspaceArtifact(session, 'r', ['file'], { ...a, current() { throw new ProbeError('access.denied') } }), /access.denied/)
    } finally { resume(); await blocking.close(); await fresh.close() }
  } finally { await h.close() }
})
