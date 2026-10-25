import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { access, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { MAX_FILE_CHUNK_BYTES, MAX_UPLOAD_FILE_BYTES, type FileManifest } from '../src/file-admission.js'
import { parseCommand, ProbeError } from '../src/protocol.js'
import { projectEvent } from '../src/projection.js'

const signal = () => new AbortController().signal
const manifest = (bytes: Uint8Array, name = '资料?.bin'): FileManifest => ({
  name, size_bytes: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex'),
})
async function* chunks(bytes: Uint8Array): AsyncIterable<Uint8Array> {
  for (let at = 0; at < bytes.byteLength; at += 4096) yield bytes.subarray(at, at + 4096)
}
const unavailableReceipt = (error: unknown) => (error as { code?: string }).code === 'session/attachment-invalid'

test('verified native file intake preserves exact bytes and admits only the receiving Session receipt', async () => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture'), other = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal()), foreign = await client.resolve(other.session_id, signal())
    const bytes = Buffer.from(Array.from({ length: 200_123 }, (_, i) => i % 256))
    const expected = manifest(bytes)
    const uploaded = await client.uploadFile(created.session_id, expected, chunks(bytes), signal())
    assert.equal(uploaded.file.bytes, bytes.length)
    assert.equal(uploaded.file.attachmentId, `sha256:${expected.sha256}`)
    assert.equal(uploaded.file.name, '资料_.bin')
    await assert.rejects(access(join(h.cwd, uploaded.file.name)), { code: 'ENOENT' })
    assert.equal(h.ctx.fileUploads.resolve(h.ctx.agents.get(foreign)!, uploaded.receiptId), undefined)
    await assert.rejects(client.prompt(foreign, randomUUID(), 'queue', [{ type: 'file', receiptId: uploaded.receiptId }], signal()), unavailableReceipt)
    const read: Buffer[] = []
    for await (const part of h.ctx.attachments.readFileStream(uploaded.file)) {
      assert.ok(part.byteLength <= MAX_FILE_CHUNK_BYTES)
      read.push(Buffer.from(part))
    }
    assert.deepEqual(Buffer.concat(read), bytes)
    const request = randomUUID()
    const content = [{ type: 'text' as const, text: 'inspect the uploaded binary' }, { type: 'file' as const, receiptId: uploaded.receiptId }]
    const accepted = await client.prompt(native, request, 'queue', content, signal())
    assert.equal(accepted.checkpoint.state, 'persisted')
    await h.ctx.agents.get(native)!.whenIdle()
    const messages = h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message').filter(event => event.data.source.kind === 'user')
    assert.equal(messages.length, 1)
    assert.ok(messages[0]!.data.content.some(part => part.type === 'file' && part.attachment.attachmentId === uploaded.file.attachmentId))
    const follower = client.follow(native, 30, signal())[Symbol.asyncIterator]()
    const opening = await follower.next()
    if (opening.done) throw new Error('native file follower ended before its snapshot')
    const snapshot = opening.value
    assert.equal(snapshot.type, 'snapshot')
    if (snapshot.type !== 'snapshot') throw new Error('expected native file snapshot')
    const projected = JSON.stringify(snapshot.records.map(record => projectEvent(record.event)))
    await follower.return?.()
    assert.equal(projected.includes(h.cwd), false)
    assert.equal(projected.includes(uploaded.receiptId), false)
    assert.equal(h.ctx.fileUploads.resolve(h.ctx.agents.get(native)!, uploaded.receiptId), undefined)
    await client.prompt(native, request, 'queue', content, signal())
    assert.equal(h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message').filter(event => event.data.source.kind === 'user').length, 1)
    await assert.rejects(client.prompt(native, randomUUID(), 'queue', content, signal()), unavailableReceipt)
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})

test('file metadata limits and literal session boundaries reject before consuming the source', async () => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const body = Buffer.from('intake')
    let reads = 0
    const source = async function* () { reads++; yield body }
    for (const bad of [
      { ...manifest(body), name: '../workspace.txt' }, { ...manifest(body), name: 'C:\\mobile\\source.txt' },
      { ...manifest(body), name: 'bad\u0000' }, { ...manifest(body), name: '\ud800' }, { ...manifest(body), name: '中'.repeat(200) },
      { ...manifest(body), size_bytes: -1 }, { ...manifest(body), sha256: 'A'.repeat(64) },
    ]) await assert.rejects(client.uploadFile(created.session_id, bad, source(), signal()), /file.invalid/)
    await assert.rejects(client.uploadFile(created.session_id, { ...manifest(body), size_bytes: MAX_UPLOAD_FILE_BYTES + 1 }, source(), signal()), /file.too_large/)
    const hidden = new DshClient(h.ctx, h.runtimeId, [], [])
    await assert.rejects(hidden.uploadFile(created.session_id, manifest(body), source(), signal()), /session.not_found/)
    const different = new DshClient(h.ctx, randomUUID(), [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    await assert.rejects(different.uploadFile(created.session_id, manifest(body), source(), signal()), /session.not_found/)
    const cancelled = new AbortController(); cancelled.abort()
    await assert.rejects(client.uploadFile(created.session_id, manifest(body), source(), cancelled.signal), /file.cancelled/)
    const native = await client.resolve(created.session_id, signal())
    await h.ctx.workspaceRegistry.archiveSession(native)
    await assert.rejects(client.uploadFile(created.session_id, manifest(body), source(), signal()), /session.archived/)
    await h.ctx.workspaceRegistry.unarchiveSession(native)
    assert.equal(reads, 0)
    const empty = await client.uploadFile(created.session_id, manifest(Buffer.alloc(0), 'empty.txt'), chunks(Buffer.alloc(0)), signal())
    assert.equal(empty.file.bytes, 0)
  } finally { await h.close() }
})

test('an archive after native storage completion retires the unpublished receipt', async () => {
  const h = await host({ probe: false })
  const original = h.ctx.fileUploads.uploadStream.bind(h.ctx.fileUploads)
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    let staged: Awaited<ReturnType<typeof original>> | undefined
    h.ctx.fileUploads.uploadStream = async request => {
      staged = await original(request)
      await h.ctx.workspaceRegistry.archiveSession(native)
      return staged
    }
    const bytes = Buffer.from('archive at the storage boundary')
    await assert.rejects(client.uploadFile(created.session_id, manifest(bytes), chunks(bytes), signal()), /session.archived/)
    assert.ok(staged)
    assert.equal(h.ctx.fileUploads.resolve(h.ctx.agents.get(native)!, staged.receiptId), undefined)
    assert.equal(h.errors.length, 0)
  } finally { h.ctx.fileUploads.uploadStream = original; await h.close() }
})

test('stream faults, length/hash mismatches and cancellation cannot publish a staged receipt', async t => {
  const h = await host({ probe: false })
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const body = Buffer.from('verified bytes')
    for (const variant of ['hash', 'short', 'long', 'chunk', 'empty-chunk', 'source', 'cancel'] as const) await t.test(variant, async () => {
      const controller = new AbortController()
      let closed = false
      const data = async function* () {
        try {
          if (variant === 'source') throw new Error('PRIVATE_SOURCE_FAILURE')
          if (variant === 'chunk') { yield Buffer.alloc(MAX_FILE_CHUNK_BYTES + 1); return }
          if (variant === 'empty-chunk') { yield Buffer.alloc(0); return }
          if (variant === 'cancel') { yield body.subarray(0, 1); controller.abort(); yield body.subarray(1); return }
          yield body
        } finally { closed = true }
      }
      const expected = { ...manifest(body), ...(variant === 'hash' ? { sha256: '0'.repeat(64) } : {}),
        ...(variant === 'short' ? { size_bytes: body.length + 1 } : variant === 'long' ? { size_bytes: body.length - 1 } : {}) }
      const want = variant === 'chunk' || variant === 'empty-chunk' ? 'file.chunk_invalid'
        : variant === 'source' ? 'file.admission_failed' : variant === 'cancel' ? 'file.cancelled' : 'file.integrity_mismatch'
      await assert.rejects(client.uploadFile(created.session_id, expected, data(), controller.signal), error => error instanceof ProbeError && error.code === want)
      assert.equal(closed, true)
    })
    assert.equal(h.ctx.agents.get(await client.resolve(created.session_id, signal()))!.session.snapshotEvents().filter(event => event.type === 'user/message').length, 0)
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})

test('an archive racing file streaming refuses admission and explicit receipt retirement leaves admitted queue content intact', async () => {
  const h = await host({ probe: false })
  const held = h.model.holdNext()
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture'), other = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal()), foreign = await client.resolve(other.session_id, signal())
    const bytes = Buffer.from('a queued file')
    const racing = async function* () {
      yield bytes.subarray(0, 1)
      await h.ctx.workspaceRegistry.archiveSession(native)
      yield bytes.subarray(1)
    }
    await assert.rejects(client.uploadFile(created.session_id, manifest(bytes), racing(), signal()), /session.archived/)
    await h.ctx.workspaceRegistry.unarchiveSession(native)
    await client.prompt(native, randomUUID(), 'queue', 'hold the current turn', signal())
    await held.started
    const uploaded = await client.uploadFile(created.session_id, manifest(bytes), chunks(bytes), signal())
    const request = randomUUID()
    await client.prompt(native, request, 'queue', [{ type: 'file', receiptId: uploaded.receiptId }], signal())
    assert.ok(h.ctx.fileUploads.resolve(h.ctx.agents.get(native)!, uploaded.receiptId))
    assert.equal(client.releaseFile(foreign, uploaded.receiptId), false)
    assert.equal(client.releaseFile(native, uploaded.receiptId), true)
    assert.equal(client.releaseFile(native, uploaded.receiptId), false)
    held.release()
    await h.ctx.agents.get(native)!.whenIdle()
    assert.ok(h.ctx.agents.get(native)!.session.snapshotEvents().some(event => event.type === 'user/message'
      && event.data.content.some(part => part.type === 'file' && part.attachment.attachmentId === uploaded.file.attachmentId)))
    await client.prompt(native, request, 'queue', [{ type: 'file', receiptId: uploaded.receiptId }], signal())
    assert.equal(h.errors.length, 0)
  } finally { held.release(); await h.close() }
})

test('Loader recreation preserves native file history but invalidates unused staged receipts until a fresh handoff', async () => {
  const h = await host({ probe: false, retainDirectory: true })
  let reopened: Awaited<ReturnType<typeof host>> | undefined
  let firstClosed = false
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal())
    const body = Buffer.from('persistent attachment')
    const used = await client.uploadFile(created.session_id, manifest(body), chunks(body), signal())
    const unused = await client.uploadFile(created.session_id, manifest(body, 'unused.txt'), chunks(body), signal())
    const request = randomUUID()
    await client.prompt(native, request, 'queue', [{ type: 'file', receiptId: used.receiptId }], signal())
    await h.ctx.agents.get(native)!.whenIdle()
    await client.checkpoint(native)
    await h.close(); firstClosed = true
    reopened = await host({ probe: false, directory: h.directory, retainDirectory: true, runtimeId: h.runtimeId })
    const next = new DshClient(reopened.ctx, h.runtimeId, [{ id: 'fixture', cwd: reopened.cwd }], ['fixture'])
    await next.prompt(native, request, 'queue', [{ type: 'file', receiptId: used.receiptId }], signal())
    await assert.rejects(next.prompt(native, randomUUID(), 'queue', [{ type: 'file', receiptId: unused.receiptId }], signal()), unavailableReceipt)
    const read: Buffer[] = []
    for await (const part of reopened.ctx.attachments.readFileStream(used.file)) read.push(Buffer.from(part))
    assert.deepEqual(Buffer.concat(read), body)
    const fresh = await next.uploadFile(created.session_id, manifest(body, 'unused.txt'), chunks(body), signal())
    assert.notEqual(fresh.receiptId, unused.receiptId)
    await next.prompt(native, randomUUID(), 'queue', [{ type: 'file', receiptId: fresh.receiptId }], signal())
    await reopened.ctx.agents.get(native)!.whenIdle()
    assert.equal(reopened.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message').filter(event => event.data.source.kind === 'user').length, 2)
    assert.equal(reopened.errors.length, 0)
  } finally {
    if (reopened) await reopened.close()
    if (!firstClosed) await h.close()
    await rm(h.directory, { recursive: true, force: true })
  }
})

test('unnegotiated mobile commands cannot smuggle native receipts or host file paths through text content', () => {
  const base = { v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: randomUUID(), session_id: randomUUID() }
  for (const content of [[{ type: 'file', receiptId: randomUUID() }], [{ type: 'file', path: '/etc/passwd' }]]) {
    assert.throws(() => parseCommand({ ...base, payload: { mode: 'queue', content } }), /protocol.invalid/)
  }
})
