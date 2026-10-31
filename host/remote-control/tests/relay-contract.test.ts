import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { z } from 'zod'

const load = async (path: string) => JSON.parse(await readFile(fileURLToPath(new URL(path, import.meta.url)), 'utf8')) as unknown
const ajv = new Ajv2020({ allErrors: true, strict: true })
const schema = await load('../../../contracts/ws/v1/relay.schema.json') as object
const validate = ajv.compile(schema)

test('WSS relay schema accepts command, catalog and scoped session-read goldens', async () => {
  for (const path of [
    '../../../contracts/ws/v1/golden/host-observations.json',
    '../../../contracts/ws/v1/golden/host-observations-next.json',
    '../../../contracts/ws/v1/golden/host-observations-journal.json',
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
    '../../../contracts/ws/v1/golden/session-models.get.json',
    '../../../contracts/ws/v1/golden/session-models.result.json',
    '../../../contracts/ws/v1/golden/session-model-select.json',
    '../../../contracts/ws/v1/golden/session-model-select.forwarded.json',
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
    '../../../contracts/ws/v1/golden/session-catalog.metadata.json',
    '../../../contracts/ws/v1/golden/message-image-submit.json',
    '../../../contracts/ws/v1/golden/message-image-submit.forwarded.json',
    '../../../contracts/ws/v1/golden/message-image-reconcile.forwarded.json',
    '../../../contracts/ws/v1/golden/session-snapshot.media.json',
    '../../../contracts/ws/v1/golden/session-media-resolve.json',
    '../../../contracts/ws/v1/golden/session-media-resolve.forwarded.json',
    '../../../contracts/ws/v1/golden/session-media-result.json',
    '../../../contracts/ws/v1/golden/session-media-error.json',
    '../../../contracts/ws/v1/golden/session-changes-get.json',
    '../../../contracts/ws/v1/golden/session-changes-result.json',
    '../../../contracts/ws/v1/golden/session-changes-patch-get.json',
    '../../../contracts/ws/v1/golden/session-changes-patch-result.json',
    '../../../contracts/ws/v1/golden/session-changes-error.json',
    '../../../contracts/ws/v1/golden/session-changes-patch-error.json',
    '../../../contracts/ws/v1/golden/session-message-preview-get.json',
    '../../../contracts/ws/v1/golden/session-message-preview-get.forwarded.json',
    '../../../contracts/ws/v1/golden/session-message-preview-confirm.json',
    '../../../contracts/ws/v1/golden/session-message-preview-confirm.forwarded.json',
    '../../../contracts/ws/v1/golden/session-message-preview-result.json',
    '../../../contracts/ws/v1/golden/session-message-preview-result.unshareable.json',
    '../../../contracts/ws/v1/golden/session-message-preview-error.json',
    '../../../contracts/ws/v1/golden/session-fork.json',
    '../../../contracts/ws/v1/golden/session-fork.forwarded.json',
    '../../../contracts/ws/v1/golden/host-session-fork.host_accepted.json',
    '../../../contracts/ws/v1/golden/host-session-fork.partial-receipt.json',
    '../../../contracts/ws/v1/golden/host-session-fork.settled.json',
    '../../../contracts/ws/v1/golden/device-session-fork.partial-receipt.json',
    '../../../contracts/ws/v1/golden/device-session-fork.settled.json',
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
  const modelSelection = await load('../../../contracts/ws/v1/golden/session-model-select.forwarded.json') as Record<string, unknown>
  assert.equal(modelSelection.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: modelSelection.type, runtime_epoch: modelSelection.runtime_epoch, session_id: modelSelection.session_id, payload: modelSelection.payload }))).digest('hex'))
  assert.equal(validate({ ...modelSelection, payload: { provider: 'fixture', model: 'fixture', api_key: 'forbidden' } }), false)
  assert.equal(validate({ ...modelSelection, payload: { provider: 'fixture', model: 'fixture', reasoning_effort: null } }), false)
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

const record = z.record(z.string(), z.unknown())
const wireFrame = z.looseObject({ payload: record })
const wire = async (name: string) => wireFrame.parse(await load(`../../../contracts/ws/v1/golden/${name}.json`))

test('versioned metadata is opt-in, bounded and absent from legacy catalog/create shapes', async () => {
  const catalog = await wire('session-catalog.metadata')
  const items = z.array(record).parse(catalog.payload.items)
  const item = items[0]
  assert.ok(item, 'metadata catalog golden requires a session item')
  const metadata = record.parse(item.metadata)
  const changed = (updatedItem: unknown) => ({ ...catalog, payload: { ...catalog.payload, items: [updatedItem] } })
  assert.equal(validate({ ...catalog, payload: { ...catalog.payload, metadata_version: undefined } }), false)
  assert.equal(validate({ ...catalog, payload: { ...catalog.payload, metadata_version: 2 } }), false)
  assert.equal(validate(changed({ ...item, metadata: undefined })), false)
  for (const name of ['x'.repeat(257), '  ', 'bad\nname', 'bad\u202ename']) {
    assert.equal(validate(changed({ ...item, metadata: { ...metadata, title: name } })), false)
  }
  assert.equal(validate(changed({ ...item, metadata: { ...metadata, path: '/private' } })), false)
  assert.equal(validate(changed({ ...item, metadata: { ...metadata, title: null } })), false)
  assert.equal(validate(changed({ ...item, workspace_id: null })), false)
  assert.equal(validate(changed({ ...item, state: 'unavailable' })), false)
  const cleared = { v: 1, title: null, workspace_title: null, title_source: null, title_as_of_seq: null }
  assert.equal(validate(changed({ ...item, state: 'unavailable', workspace_id: null, metadata: cleared })), true)
  const legacy = await wire('host-session-catalog')
  const legacyItems = z.array(record).parse(legacy.payload.items)
  assert.equal(validate({ ...legacy, payload: { ...legacy.payload, items: [{ ...legacyItems[0], metadata }] } }), false)
  const creation = await wire('host-session-create.settled')
  assert.equal(validate({ ...creation, payload: { ...creation.payload, created_session: { ...record.parse(creation.payload.created_session), metadata } } }), false)
})

test('typed images do not admit URLs/native identities or broaden phone subscriptions', async () => {
  const submit = await wire('message-image-submit.forwarded')
  const image = z.array(record).parse(submit.payload.content)[1]
  assert.ok(image, 'image submit golden requires the uploaded image part')
  for (const extra of [{ url: 'https://invalid.example/image' }, { path: '/private/image' }, { media_type: 'image/png' }, { data: 'base64' }, { attachment_id: 'native-private' }]) {
    assert.equal(validate({ ...submit, payload: { ...submit.payload, content: [{ ...image, ...extra }] } }), false)
  }
  const reconcile = await wire('message-image-reconcile.forwarded')
  assert.equal(reconcile.payload_sha256, submit.payload_sha256)
  const deviceSubscribe = await wire('session-subscribe')
  assert.equal(validate({ ...deviceSubscribe, payload: { ...deviceSubscribe.payload, media_refs: true } }), false)
  const hostSubscribe = await wire('session-subscribe.forwarded')
  assert.equal(validate({ ...hostSubscribe, payload: { ...hostSubscribe.payload, media_refs: true } }), true)
  const resolve = await wire('session-media-resolve')
  const reference = record.parse(resolve.payload.reference)
  const manifest = record.parse(reference.manifest)
  for (const changedReference of [{ ...reference, attachment_id: 'private-native' }, { ...reference, origin: 'workspace_artifact' },
    { ...reference, v: 2 }, { ...reference, width: 16385 }, { ...reference, manifest: { ...manifest, url: 'https://invalid.example' } },
    { ...reference, manifest: { ...manifest, size_bytes: 16777217 } }]) {
    assert.equal(validate({ ...resolve, payload: { ...resolve.payload, reference: changedReference } }), false)
  }
  const snapshot = await wire('session-snapshot.media')
  const visibleRecord = z.array(record).parse(snapshot.payload.records)[0]
  assert.ok(visibleRecord, 'media snapshot golden requires a visible message record')
  const visibleData = record.parse(visibleRecord.data)
  for (const block of [{ type: 'image', file_id: image.file_id }, { type: 'image', reference, url: 'https://invalid.example' },
    { type: 'image', reference: { ...reference, attachment_id: 'native-private' } }]) {
    assert.equal(validate({ ...snapshot, payload: { ...snapshot.payload, records: [{ ...visibleRecord, data: { ...visibleData, content: [block] } }] } }), false)
  }
  const result = await wire('session-media-result')
  const source = record.parse(result.payload.source)
  for (const changedSource of [{ ...source, kind: 'directory' }, { ...source, origin: 'workspace_artifact' }, { ...source, unavailable: 'file.too_large' }, { ...source, url: 'https://invalid.example' }]) {
    assert.equal(validate({ ...result, payload: { ...result.payload, source: changedSource } }), false)
  }
  for (const name of ['session-media-result', 'session-media-error']) {
    const frame = await wire(name)
    assert.equal(validate({ ...frame, sync_id: undefined }), false)
    assert.equal(validate({ ...frame, subscription_id: undefined }), false)
  }
})

test('changes and previews keep exact bounded current-reader request/result shapes', async () => {
  for (const name of ['session-changes-get', 'session-changes-patch-get', 'session-message-preview-get', 'session-message-preview-confirm']) {
    const frame = await wire(name)
    assert.equal(validate({ ...frame, runtime_epoch: undefined }), false)
    assert.equal(validate({ ...frame, subscription_id: undefined }), false)
    assert.equal(validate({ ...frame, payload: { ...frame.payload, sync_id: undefined } }), false)
    for (const extra of [{ path: '/private' }, { cwd: '/private' }, { url: 'https://invalid.example' }, { command: 'git diff' }]) {
      assert.equal(validate({ ...frame, payload: { ...frame.payload, ...extra } }), false)
    }
  }
  const get = await wire('session-changes-get')
  assert.equal(validate({ ...get, payload: { ...get.payload, limit: 21 } }), false)
  assert.equal(validate({ ...get, payload: { ...get.payload, cursor: 'arbitrary-selector' } }), false)
  const changes = await wire('session-changes-result')
  for (const excluded of [[], ['untracked', 'ignored'], ['untracked', 'ignored', 'submodule_contents', 'extra'], ['ignored', 'untracked', 'submodule_contents']]) {
    assert.equal(validate({ ...changes, payload: { ...changes.payload, excluded } }), false)
  }
  const patch = await wire('session-changes-patch-result')
  for (const changed of [{ partial: true }, { complete: false }, { kind: 'binary' }, { next_cursor: get.request_id }, { patch_utf8: null }]) {
    assert.equal(validate({ ...patch, payload: { ...patch.payload, ...changed } }), false)
  }
  assert.equal(validate({ ...patch, payload: { ...patch.payload, complete: false, copyable: false, partial: true, next_cursor: get.request_id } }), true)
  const preview = await wire('session-message-preview-result')
  assert.equal(validate({ ...preview, payload: { ...preview.payload, text: 'x'.repeat(32769) } }), false)
  assert.equal(validate({ ...preview, payload: { ...preview.payload, text: null } }), false)
  assert.equal(validate({ ...preview, payload: { ...preview.payload, shareable: false } }), false)
  const unshareable = await wire('session-message-preview-result.unshareable')
  assert.equal(validate({ ...unshareable, payload: { ...unshareable.payload, shareable: true } }), false)
  assert.equal(validate({ ...preview, payload: { ...preview.payload, account: 'private' } }), false)
})

test('fork preserves source identity and confines child/outcome fields to explicit fork receipts', async () => {
  const fork = await wire('session-fork.forwarded')
  assert.equal(fork.payload_sha256, createHash('sha256').update(JSON.stringify(canonicalValue({ type: fork.type, runtime_epoch: fork.runtime_epoch, session_id: fork.session_id, payload: fork.payload }))).digest('hex'))
  for (const extra of [{ model: 'unselected' }, { cwd: '/private' }, { at_seq: 7 }]) assert.equal(validate({ ...fork, payload: { ...fork.payload, ...extra } }), false)
  const anchor = record.parse(fork.payload.anchor)
  assert.equal(validate({ ...fork, payload: { ...fork.payload, anchor: { ...anchor, native_seq: -1 } } }), false)
  assert.equal(validate({ ...fork, payload: { ...fork.payload, anchor: { ...anchor, text: 'not an anchor' } } }), false)
  const partial = await wire('host-session-fork.partial-receipt')
  const settled = await wire('host-session-fork.settled')
  const deviceSettled = await wire('device-session-fork.settled')
  assert.equal(partial.session_id, fork.session_id)
  assert.notEqual(partial.payload.child_session_id, partial.session_id)
  assert.equal(validate({ ...partial, payload: { ...partial.payload, command_type: undefined } }), false)
  assert.equal(validate({ ...partial, payload: { ...partial.payload, command_type: 'message.submit' } }), false)
  assert.equal(validate({ ...partial, payload: { ...partial.payload, fork_outcome: undefined } }), false)
  assert.equal(validate({ ...partial, payload: { ...partial.payload, child_session_id: undefined } }), false)
  assert.equal(validate({ ...partial, payload: { ...partial.payload, state: 'rejected' } }), false)
  assert.equal(validate({ ...partial, payload: { ...partial.payload, state: 'agent_queued' } }), false)
  assert.equal(validate({ ...settled, payload: { ...settled.payload, created_session: undefined } }), false)
  assert.equal(validate({ ...settled, payload: { ...settled.payload, fork_outcome: { ...record.parse(settled.payload.fork_outcome), checkpoint: 'unknown' } } }), false)
  assert.equal(validate({ ...deviceSettled, payload: { ...deviceSettled.payload, created_session: settled.payload.created_session } }), false)
  assert.equal(validate({ ...deviceSettled, payload: { ...deviceSettled.payload, child_session_id: undefined, fork_outcome: undefined } }), false)
  const legacy = await wire('host-command-receipt')
  assert.equal(validate({ ...legacy, payload: { ...legacy.payload, child_session_id: partial.payload.child_session_id, fork_outcome: partial.payload.fork_outcome } }), false)
})

test('focused generated feature schemas accept the same strict central goldens', async () => {
  const groups = {
    media: ['session-media-resolve', 'session-media-resolve.forwarded', 'session-media-result', 'session-media-error'],
    changes: ['session-changes-get', 'session-changes-patch-get', 'session-changes-result', 'session-changes-patch-result', 'session-changes-error', 'session-changes-patch-error'],
    'message-actions': ['session-message-preview-get', 'session-message-preview-get.forwarded', 'session-message-preview-confirm', 'session-message-preview-confirm.forwarded', 'session-message-preview-result', 'session-message-preview-result.unshareable', 'session-message-preview-error'],
    fork: ['session-fork', 'session-fork.forwarded', 'host-session-fork.host_accepted', 'host-session-fork.partial-receipt', 'host-session-fork.settled', 'device-session-fork.partial-receipt', 'device-session-fork.settled'],
  }
  for (const [name, samples] of Object.entries(groups)) {
    const focused = ajv.compile(record.parse(await load(`../../../contracts/ws/v1/${name}.schema.json`)))
    for (const sample of samples) {
      const frame = await wire(sample)
      assert.equal(focused(frame), true, `${sample}: ${ajv.errorsText(focused.errors)}`)
      assert.equal(focused({ ...frame, path: '/private' }), false)
    }
  }
})
