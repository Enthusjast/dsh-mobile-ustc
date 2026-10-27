import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'

const load = async (path: string) => JSON.parse(await readFile(fileURLToPath(new URL(path, import.meta.url)), 'utf8')) as unknown
const ajv = new Ajv2020({ allErrors: true, strict: true })
const schema = await load('../../../contracts/ws/v1/relay.schema.json') as object
const validate = ajv.compile(schema)

test('WSS relay schema accepts command, catalog and scoped session-read goldens', async () => {
  for (const path of [
    '../../../contracts/ws/v1/golden/host-observations.json',
    '../../../contracts/ws/v1/golden/host-observations-next.json',
    '../../../contracts/ws/v1/golden/message-submit.json',
    '../../../contracts/ws/v1/golden/message-submit.forwarded.json',
    '../../../contracts/ws/v1/golden/message-file-submit.json',
    '../../../contracts/ws/v1/golden/message-file-submit.forwarded.json',
    '../../../contracts/ws/v1/golden/message-file-reconcile.forwarded.json',
    '../../../contracts/ws/v1/golden/session-cancel.json',
    '../../../contracts/ws/v1/golden/session-cancel.forwarded.json',
    '../../../contracts/ws/v1/golden/session-archive.json',
    '../../../contracts/ws/v1/golden/session-archive.forwarded.json',
    '../../../contracts/ws/v1/golden/session-archive-stop.json',
    '../../../contracts/ws/v1/golden/session-archive-stop.forwarded.json',
    '../../../contracts/ws/v1/golden/session-restore.json',
    '../../../contracts/ws/v1/golden/session-restore.forwarded.json',
    '../../../contracts/ws/v1/golden/question-answer.json',
    '../../../contracts/ws/v1/golden/question-answer.forwarded.json',
    '../../../contracts/ws/v1/golden/question-snapshot.json',
    '../../../contracts/ws/v1/golden/question-timed-answer.json',
    '../../../contracts/ws/v1/golden/question-timed-answer.forwarded.json',
    '../../../contracts/ws/v1/golden/question-timed-snapshot.json',
    '../../../contracts/ws/v1/golden/question-claim.json',
    '../../../contracts/ws/v1/golden/question-claimed.json',
    '../../../contracts/ws/v1/golden/question-claim-closed.json',
    '../../../contracts/ws/v1/golden/question-release.json',
    '../../../contracts/ws/v1/golden/question-released.json',
    '../../../contracts/ws/v1/golden/session-create.json',
    '../../../contracts/ws/v1/golden/session-create-options.publish.json',
    '../../../contracts/ws/v1/golden/session-create-options.get.json',
    '../../../contracts/ws/v1/golden/session-create-options.result.json',
    '../../../contracts/ws/v1/golden/session-create-options.ack.json',
    '../../../contracts/ws/v1/golden/session-create.forwarded.json',
    '../../../contracts/ws/v1/golden/host-session-create.host_accepted.json',
    '../../../contracts/ws/v1/golden/host-session-create.settled.json',
    '../../../contracts/ws/v1/golden/device-session-create.received.json',
    '../../../contracts/ws/v1/golden/device-session-create.settled.json',
    '../../../contracts/ws/v1/golden/host-command-receipt.json',
    '../../../contracts/ws/v1/golden/host-session-catalog.json',
    '../../../contracts/ws/v1/golden/host-session-catalog.ack.json',
    '../../../contracts/push/v1/golden/question-references.json',
    '../../../contracts/push/v1/golden/question-references-ack.json',
    '../../../contracts/ws/v1/golden/session-subscribe.json',
    '../../../contracts/ws/v1/golden/session-subscribe.forwarded.json',
    '../../../contracts/ws/v1/golden/session-snapshot.json',
    '../../../contracts/ws/v1/golden/session-page.json',
  ]) {
    const value = await load(path)
    assert.equal(validate(value), true, ajv.errorsText(validate.errors))
  }
  const invalid = await load('../../../contracts/ws/v1/golden/invalid-message-submit.json')
  assert.equal(validate(invalid), false)
  const files = await load('../../../contracts/ws/v1/golden/message-file-submit.forwarded.json') as Record<string, unknown>
  assert.equal(files.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: files.type, session_id: files.session_id, payload: files.payload }))).digest('hex'))
  const reconcile = await load('../../../contracts/ws/v1/golden/message-file-reconcile.forwarded.json') as Record<string, unknown>
  assert.equal(reconcile.payload_sha256, files.payload_sha256)
  assert.equal(validate({ ...reconcile, payload: { mode: 'queue', content: [{ type: 'text', text: 'not a file intent' }] } }), false)
  assert.equal(validate({ ...reconcile, user_id: undefined, device_id: undefined, payload_sha256: undefined }), false)
  for (const part of [{ type: 'file', file_id: files.request_id, text: '' }, { type: 'file', receiptId: files.request_id }, { type: 'file', path: '/private' }]) {
    assert.equal(validate({ ...files, payload: { mode: 'queue', content: [part] } }), false)
  }

  const forwarded = await load('../../../contracts/ws/v1/golden/message-submit.forwarded.json') as {
    request_id: string
    session_id: string
    payload: { mode: string; content: Array<{ type: string; text: string }> }
    payload_sha256: string
  }
  const body = canonicalValue({ type: 'message.submit', session_id: forwarded.session_id, payload: forwarded.payload })
  const digest = createHash('sha256').update(JSON.stringify(body)).digest('hex')
  assert.equal(forwarded.payload_sha256, digest)
  const cancel = await load('../../../contracts/ws/v1/golden/session-cancel.forwarded.json') as Record<string, unknown>
  assert.equal(cancel.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: cancel.type, runtime_epoch: cancel.runtime_epoch, session_id: cancel.session_id, payload: {} }))).digest('hex'))
  const deviceCancel = await load('../../../contracts/ws/v1/golden/session-cancel.json') as Record<string, unknown>
  const { runtime_epoch: _epoch, ...missingEpoch } = deviceCancel
  assert.equal(validate(missingEpoch), false)
  assert.equal(validate({ ...deviceCancel, payload: { all: true } }), false)
  for (const name of ['session-archive', 'session-archive-stop', 'session-restore']) {
    const archive = await load(`../../../contracts/ws/v1/golden/${name}.forwarded.json`) as Record<string, unknown>
    assert.equal(archive.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: archive.type, runtime_epoch: archive.runtime_epoch, session_id: archive.session_id, payload: archive.payload }))).digest('hex'))
    assert.equal(validate({ ...archive, payload: { archived: false, stop_activity: true } }), false)
    assert.equal(validate({ ...archive, payload: { archived: true } }), false)
    assert.equal(validate({ ...archive, runtime_epoch: undefined }), false)
  }
  const question = await load('../../../contracts/ws/v1/golden/question-answer.forwarded.json') as Record<string, unknown>
  assert.equal(question.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: question.type, runtime_epoch: question.runtime_epoch, session_id: question.session_id, payload: question.payload }))).digest('hex'))
  assert.equal(validate({ ...question, payload: { question_id: question.request_id, decision: 'allow_once' } }), false)
  const timed = await load('../../../contracts/ws/v1/golden/question-timed-answer.forwarded.json') as Record<string, unknown>
  assert.equal(timed.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: timed.type, runtime_epoch: timed.runtime_epoch, session_id: timed.session_id, payload: timed.payload }))).digest('hex'))
  const creation = await load('../../../contracts/ws/v1/golden/session-create.forwarded.json') as Record<string, unknown>
  assert.equal(creation.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: creation.type, runtime_epoch: creation.runtime_epoch, payload: creation.payload }))).digest('hex'))
  assert.equal(validate({ ...creation, session_id: creation.request_id }), false)
  assert.equal(validate({ ...creation, payload: { workspace_id: creation.request_id, preset: '../standard' } }), false)
  const settledCreation = await load('../../../contracts/ws/v1/golden/host-session-create.settled.json') as { payload: Record<string, unknown> }
  assert.equal(validate({ ...settledCreation, payload: { ...settledCreation.payload, created_session: { ...(settledCreation.payload.created_session as object), state: 'archived' } } }), true)
  assert.equal(validate({ ...settledCreation, payload: { ...settledCreation.payload, created_session: undefined } }), false)
})

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (typeof value !== 'object' || value === null) return value
  const object = value as Record<string, unknown>
  return Object.fromEntries(Object.keys(object).sort().map(key => [key, canonicalValue(object[key])]))
}
