import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { Command, encodeFrames, MAX_FRAME_BYTES, parseCommand } from '../src/protocol.js'
import { mobileSessionId } from '../src/dsh-client.js'
import { projectChunk, projectEvent, projectStream } from '../src/projection.js'
import { validateSocketPath } from '../src/debug-server.js'
import { z } from 'zod'

test('strict local protocol rejects extra fields, native identifiers, wrong versions and whitespace prompts', () => {
  const base = { v: 0, runtime_epoch: randomUUID(), request_id: randomUUID() }
  const list = { ...base, type: 'session.list', payload: {} }
  assert.equal(parseCommand(list).type, 'session.list')
  for (const input of [
    { ...list, secret: true }, { ...list, v: 1 }, { ...list, payload: { cwd: '/etc' } },
    { ...base, type: 'message.submit', session_id: 'native:opaque', payload: { mode: 'queue', text: 'hi' } },
    { ...base, type: 'message.submit', session_id: randomUUID(), payload: { mode: 'queue', text: '  \t' } },
    { ...base, type: 'session.model.select', session_id: randomUUID(), payload: { provider: 'unknown', model: 'arbitrary', credentials: 'secret' } },
  ]) assert.throws(() => parseCommand(input), /protocol.invalid/)
  const blocks = parseCommand({ ...base, type: 'message.submit', session_id: randomUUID(), payload: {
    mode: 'steer', content: [{ type: 'text', text: 'first' }, { type: 'text', text: 'second' }],
  } })
  assert.equal(blocks.type, 'message.submit')
  for (const payload of [
    { mode: 'queue', text: 'both shapes', content: [{ type: 'text', text: 'not allowed' }] },
    { mode: 'queue', content: [{ type: 'image', url: 'file:///etc/passwd' }] },
  ]) assert.throws(() => parseCommand({ ...base, type: 'message.submit', session_id: randomUUID(), payload }), /protocol.invalid/)
  assert.ok(z.toJSONSchema(Command).oneOf ?? z.toJSONSchema(Command).anyOf)
})

test('session UUID mapping is stable, preserves opaque input and isolates profiles', () => {
  const namespace = randomUUID()
  assert.equal(mobileSessionId(namespace, 'native:中文/42'), mobileSessionId(namespace, 'native:中文/42'))
  assert.equal(mobileSessionId('33333333-3333-4333-8333-333333333333', 'native:中文/42'), '1c6bb930-979b-5043-8b44-71f62e126939')
  assert.notEqual(mobileSessionId(namespace, 'native:中文/42'), mobileSessionId(randomUUID(), 'native:中文/42'))
  assert.match(mobileSessionId(namespace, 'native:中文/42'), /^[a-f0-9-]{14}5/)
})

test('large Unicode snapshot fragments round-trip within the byte frame limit', () => {
  const frame = { v: 0 as const, type: 'session.snapshot', runtime_epoch: randomUUID(), sync_id: randomUUID(), payload: { text: '👩‍💻中文'.repeat(7000) } }
  const lines = encodeFrames(frame)
  assert.ok(lines.length > 1)
  for (const line of lines) assert.ok(Buffer.byteLength(line.trimEnd()) <= MAX_FRAME_BYTES)
  const restored = Buffer.concat(lines.map(line => Buffer.from(JSON.parse(line).payload.data, 'base64'))).toString('utf8')
  assert.deepEqual(JSON.parse(restored), frame)
  assert.throws(() => encodeFrames({ ...frame, payload: 'x'.repeat(300_000) }), /protocol.snapshot_too_large/)
})

test('display projection strips configuration, metadata and provider replay credentials', () => {
  const event = projectEvent({ type: 'request/header', seq: 5, time: 1, data: { apiKey: 'sensitive' } })
  assert.equal(event.type, 'cursor')
  assert.ok(!JSON.stringify(event).includes('sensitive'))
  const message = projectEvent({ type: 'user/message', seq: 6, time: 2, data: {
    id: 'm', source: { kind: 'user', credential: 'sensitive' }, content: [{ type: 'text', text: 'hello', secret: 'sensitive' }],
  } })
  assert.deepEqual(message.data, { id: 'm', content: [{ type: 'text', text: 'hello' }] })
  const finish = { type: 'finish', reason: 'stop', replayState: { credential: 'sensitive' } }
  assert.deepEqual(projectChunk(finish), { type: 'finish', reason: 'stop' })
  assert.ok(!JSON.stringify(projectStream([{ type: 'chunk', time: 1, chunk: finish }])).includes('sensitive'))
})

test('injected and unattributed user-role input only advances the mobile cursor', () => {
  for (const source of [undefined, {}, { kind: 'model-selection' }, { kind: 'future-context-producer' },
    { kind: 'user-question-reply', outcome: 'answered' }, { kind: 'user-question-reply', outcome: 'cancelled', callId: 'call' }]) {
    const projected = projectEvent({ type: 'user/message', seq: 8, time: 1, surfaceOp: 'append', sourceEventSeqs: [7], data: {
      id: 'context', ...(source === undefined ? {} : { source }), content: [{ type: 'text', text: 'model-only-sensitive' }],
    } })
    assert.deepEqual(projected, { native_seq: 8, time: 1, type: 'cursor', data: {} })
  }
})

test('file-only history keeps a safe display summary without exporting attachment authority', () => {
  const projected = projectEvent({ type: 'user/message', seq: 7, time: 1, data: {
    source: { kind: 'user' }, content: [{ type: 'file', receiptId: 'private-receipt', attachment: {
      attachmentId: 'sha256:private-storage-id', name: '资料.txt', bytes: 12, path: '/private/source', url: 'https://private.example/capability',
    } }],
  } })
  assert.deepEqual(projected.data, { content: [{ type: 'text', text: '[附件：资料.txt（12 字节）]' }] })
  assert.equal(JSON.stringify(projected).includes('private'), false)
  for (const attachment of [{ name: '/private/source', bytes: 1 }, { name: '..', bytes: 0 }, { name: 'bad\nname', bytes: 1 },
    { name: '\ud800', bytes: 1 }, { name: 'x'.repeat(513), bytes: 1 }, { name: 'fine', bytes: -1 }, { name: 'fine', bytes: 1.5 }]) {
    const hidden = projectEvent({ type: 'user/message', seq: 8, time: 1, data: { source: { kind: 'user' }, content: [{ type: 'file', attachment }] } })
    assert.deepEqual(hidden.data, { content: [{ type: 'text', text: '[附件：请在电脑端查看]' }] })
  }
  const injected = projectEvent({ type: 'user/message', seq: 9, time: 1, data: {
    source: { kind: 'model-selection' }, content: [{ type: 'file', attachment: { name: 'private.txt', bytes: 1 } }],
  } })
  assert.equal(injected.type, 'cursor'); assert.deepEqual(injected.data, {})
})

test('answered native late questions remain human input without exporting source metadata', () => {
  const projected = projectEvent({ type: 'user/message', seq: 9, time: 2, surfaceOp: 'append', data: {
    id: 'reply', source: { kind: 'user-question-reply', callId: 'call', outcome: 'answered', credential: 'sensitive' },
    content: [{ type: 'text', text: 'late human answer' }],
  } })
  assert.deepEqual(projected.data, { id: 'reply', content: [{ type: 'text', text: 'late human answer' }] })
  assert.equal(projected.type, 'user/message'); assert.equal(projected.surface_op, 'append')
  assert.equal(JSON.stringify(projected).includes('sensitive'), false)
})

test('local IPC paths are bound to private Unix sockets or one runtime-scoped Windows pipe', () => {
  assert.doesNotThrow(() => validateSocketPath('/run/user/1000/dsh/probe.sock', 'linux'))
  assert.doesNotThrow(() => validateSocketPath('/tmp/dsh-mobile.sock', 'darwin'))
  assert.doesNotThrow(() => validateSocketPath('\\\\.\\pipe\\dsh-mobile-ustc-44444444-4444-4444-8444-444444444444', 'win32'))
  for (const path of ['/tmp/dsh.sock', '127.0.0.1:3030', '\\\\.\\pipe\\other-service']) {
    assert.throws(() => validateSocketPath(path, 'win32'))
  }
  assert.throws(() => validateSocketPath('relative.sock', 'linux'))
})
