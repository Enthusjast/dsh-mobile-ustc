import test from 'node:test'
import assert from 'node:assert/strict'
import type { SessionWireEvent } from '@deepseek-ai/dsh-api-session-controller/types'
import { projectEvent } from '../src/projection.js'
import { mediaEventVersion, visibleMediaReference } from '../src/media-protocol.js'

function event(source: unknown, type = 'user/message'): SessionWireEvent {
  const content = [{ type: 'text', text: 'visible' }, { type: 'image', attachment: { attachmentId: `sha256:${'a'.repeat(64)}`,
    name: 'image.png', mediaType: 'image/png', bytes: 80, width: 1, height: 1, path: '/private/hidden', url: 'https://invalid.example/private' } }]
  return { seq: 3, time: 1, type, data: type === 'user/message' ? { id: 'visible-message', source, content } : { message: { id: 'visible-message', content } } } as SessionWireEvent
}

test('media is explicit versioned image projection; ordinary file blocks stay ordinary text summaries', () => {
  const native = event({ kind: 'user' })
  const legacy = projectEvent(native), current = projectEvent(native, true)
  assert.equal(JSON.stringify(legacy).includes('"reference"'), false)
  const data = current.data.content as Array<Record<string, unknown>>
  assert.equal(data[1]!.type, 'image')
  const ref = visibleMediaReference.parse(data[1]!.reference)
  assert.equal(ref.native_seq, native.seq); assert.equal(ref.part_index, 1)
  assert.equal(ref.event_version_sha256, mediaEventVersion(legacy)); assert.equal(ref.manifest.sha256, 'a'.repeat(64))
  const serialized = JSON.stringify(current)
  for (const hidden of ['sha256:', 'attachmentId', '/private/hidden', 'https://', 'receiptId']) assert.equal(serialized.includes(hidden), false)
  const file = event({ kind: 'user' })
  const body = file.data as { content: Array<Record<string, unknown>> }
  body.content[1]!.type = 'file'
  assert.equal(JSON.stringify(projectEvent(file, true)).includes('"reference"'), false)
})

test('native nonhuman user-role producers cannot acquire image references through display projection', () => {
  for (const source of [{ kind: 'system' }, { kind: 'developer' }, { kind: 'tool' }, { kind: 'inbox' }, { kind: 'compaction' },
    { kind: 'model-selection' }, { kind: 'user-question-reply', outcome: 'dismissed', callId: 'call' }, { kind: 'user-question-reply', outcome: 'answered' }]) {
    const projected = projectEvent(event(source), true)
    assert.equal(projected.type, 'cursor'); assert.deepEqual(projected.data, {})
    assert.equal(JSON.stringify(projected).includes('"reference"'), false)
  }
  assert.equal(JSON.stringify(projectEvent(event({ kind: 'user-question-reply', outcome: 'answered', callId: 'call' }), true)).includes('"reference"'), true)
})

test('strict media references refuse extra authority, MIME forgery and over-budget dimensions', () => {
  const projected = projectEvent(event({ kind: 'user' }), true)
  const content = projected.data.content as Array<Record<string, unknown>>
  const valid = visibleMediaReference.parse(content[1]!.reference)
  for (const changed of [{ ...valid, v: 2 }, { ...valid, origin: 'workspace_artifact' }, { ...valid, url: 'https://invalid.example/image.png' },
    { ...valid, attachment_id: `sha256:${'a'.repeat(64)}` }, { ...valid, media_type: 'image/svg+xml' }, { ...valid, width: 8000, height: 8000 },
    { ...valid, manifest: { ...valid.manifest, size_bytes: 16 * 1024 * 1024 + 1 } }]) assert.equal(visibleMediaReference.safeParse(changed).success, false)
})
