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
  assert.ok(z.toJSONSchema(Command).oneOf ?? z.toJSONSchema(Command).anyOf)
})

test('session UUID mapping is stable, preserves opaque input and isolates profiles', () => {
  const namespace = randomUUID()
  assert.equal(mobileSessionId(namespace, 'native:中文/42'), mobileSessionId(namespace, 'native:中文/42'))
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
    id: 'm', source: { credential: 'sensitive' }, content: [{ type: 'text', text: 'hello', secret: 'sensitive' }],
  } })
  assert.deepEqual(message.data, { id: 'm', content: [{ type: 'text', text: 'hello' }] })
  const finish = { type: 'finish', reason: 'stop', replayState: { credential: 'sensitive' } }
  assert.deepEqual(projectChunk(finish), { type: 'finish', reason: 'stop' })
  assert.ok(!JSON.stringify(projectStream([{ type: 'chunk', time: 1, chunk: finish }])).includes('sensitive'))
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
