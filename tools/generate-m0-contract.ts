import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { Command } from '../host/remote-control/src/protocol.js'
import { imageReference } from '../host/remote-control/src/image-protocol.js'
import { visibleMediaReference, mediaResolveRequest, hostMediaFrame, mediaResolveResult, mediaErrors } from '../host/remote-control/src/media-protocol.js'
import { directoryMetadataSchema } from '../host/remote-control/src/directory-metadata.js'
import { changesRequest, changesPatchRequest, changesPageSchema, changesPatchSchema } from '../host/remote-control/src/changes-protocol.js'
import { forkAnchorSchema, forkPayloadSchema, forkOutcomeSchema, messagePreviewRequest, messagePreviewConfirmRequest, messagePreviewSchema, relayForkDigest, canonicalForkJson } from '../host/remote-control/src/fork-protocol.js'

const output = fileURLToPath(new URL('../contracts/m0/command.schema.json', import.meta.url))
const schema = z.toJSONSchema(Command, { target: 'draft-2020-12' })
schema.$id = 'urn:dsh-mobile-ustc:m0:command:v0'
const generated = `${JSON.stringify(schema, null, 2)}\n`

if (process.argv.includes('--check')) {
  const current = await readFile(output, 'utf8').catch(() => '')
  if (current !== generated) {
    console.error('contracts/m0/command.schema.json is stale; run npm run contracts')
    process.exitCode = 1
  }
} else {
  await writeFile(output, generated)
}

// Feature schemas share the exact bounded producer parsers. The base model
// catalog/select and legacy frame definitions remain independently maintained.
type JsonSchema = Record<string, unknown>
function isObject(value: unknown): value is JsonSchema { return value !== null && typeof value === 'object' && !Array.isArray(value) }
function at(value: unknown, ...keys: Array<string | number>): JsonSchema {
  for (const key of keys) {
    if (typeof key === 'number' && Array.isArray(value)) value = value[key]
    else if (isObject(value)) value = value[key]
    else throw new Error(`Missing contract schema node: ${keys.join('.')}`)
  }
  if (!isObject(value)) throw new Error(`Expected contract schema object: ${keys.join('.')}`)
  return value
}
function schemaList(value: unknown): JsonSchema[] {
  if (!Array.isArray(value)) throw new Error('Expected contract schema alternatives')
  return value.map(item => at(item))
}
function relaySchema(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(relaySchema)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .filter(([key]) => key !== '$schema' && key !== 'format')
    .map(([key, item]) => [key, relaySchema(item)]))
  return value
}
const jsonSchema = (value: z.ZodType): JsonSchema => at(relaySchema(z.toJSONSchema(value, { target: 'draft-2020-12' })))
const ref = (name: string) => ({ $ref: `#/$defs/${name}` })
const object = (properties: JsonSchema, required = Object.keys(properties)): JsonSchema => ({ type: 'object', additionalProperties: false, required, properties })
const readerRoute = { v: { const: 1 }, request_id: ref('uuid'), runtime_id: ref('uuid'), runtime_epoch: ref('uuid'), session_id: ref('uuid'), subscription_id: ref('uuid') }
const reader = (type: string, payload: string, reply = false, owner = false) => object({ ...readerRoute, type: { const: type },
  ...(reply ? { sync_id: ref('uuid') } : {}), ...(owner ? { user_id: ref('uuid'), device_id: ref('uuid') } : {}), payload: ref(payload) })
const commandRoute = { v: { const: 1 }, request_id: ref('uuid'), runtime_id: ref('uuid'), runtime_epoch: ref('uuid'), session_id: ref('uuid') }
const readerErrors = ['session.not_found', 'runtime.changed', 'runtime.offline', 'access.denied', 'protocol.invalid',
  'protocol.snapshot_too_large', 'protocol.resync_required', 'rate.limited', 'message.stale', 'message.unavailable',
  'message.not_persisted', 'changes.stale', 'changes.unavailable', 'changes.not_git', 'changes.limit']
const definitions: Record<string, JsonSchema> = {
  imageContent: jsonSchema(imageReference), visibleMediaReference: jsonSchema(visibleMediaReference),
  visibleImageBlock: object({ type: { const: 'image' }, reference: ref('visibleMediaReference') }),
  projectedTextBlock: object({ type: { enum: ['text', 'reasoning'] }, text: { type: 'string' } }),
  projectedContent: { type: 'array', items: { oneOf: [ref('projectedTextBlock'), ref('visibleImageBlock')] } },
  directoryMetadata: jsonSchema(directoryMetadataSchema),
  mediaResolvePayload: jsonSchema(mediaResolveRequest), hostMediaResolve: jsonSchema(hostMediaFrame),
  mediaResultPayload: jsonSchema(mediaResolveResult), mediaErrorPayload: object({ code: jsonSchema(mediaErrors) }),
  mediaResolve: reader('session.media.resolve', 'mediaResolvePayload'),
  mediaResult: reader('session.media.result', 'mediaResultPayload', true), mediaError: reader('session.media.error', 'mediaErrorPayload', true),
  changesRequest: jsonSchema(changesRequest), changesPatchRequest: jsonSchema(changesPatchRequest),
  changesPage: jsonSchema(changesPageSchema), changesPatch: jsonSchema(changesPatchSchema), readerErrorPayload: object({ code: { enum: readerErrors } }),
  changesGet: reader('session.changes.get', 'changesRequest'), changesPatchGet: reader('session.changes.patch.get', 'changesPatchRequest'),
  changesResult: reader('session.changes.result', 'changesPage', true), changesPatchResult: reader('session.changes.patch.result', 'changesPatch', true),
  changesError: reader('session.changes.error', 'readerErrorPayload', true), changesPatchError: reader('session.changes.patch.error', 'readerErrorPayload', true),
  forkAnchor: jsonSchema(forkAnchorSchema), forkPayload: jsonSchema(forkPayloadSchema), forkOutcome: jsonSchema(forkOutcomeSchema),
  messagePreviewRequest: jsonSchema(messagePreviewRequest), messagePreviewConfirmRequest: jsonSchema(messagePreviewConfirmRequest),
  messagePreview: jsonSchema(messagePreviewSchema),
  messagePreviewGet: reader('session.message.preview.get', 'messagePreviewRequest'), hostMessagePreviewGet: reader('session.message.preview.get', 'messagePreviewRequest', false, true),
  messagePreviewConfirm: reader('session.message.preview.confirm', 'messagePreviewConfirmRequest'), hostMessagePreviewConfirm: reader('session.message.preview.confirm', 'messagePreviewConfirmRequest', false, true),
  messagePreviewResult: reader('session.message.preview.result', 'messagePreview', true), messagePreviewError: reader('session.message.preview.error', 'readerErrorPayload', true),
  sessionFork: object({ ...commandRoute, type: { const: 'session.fork' }, payload: ref('forkPayload') }),
  sessionForkToHost: object({ ...commandRoute, type: { const: 'session.fork' }, user_id: ref('uuid'), device_id: ref('uuid'), payload_sha256: ref('sha256'), payload: ref('forkPayload') }),
  hostForkReceipt: object({ ...commandRoute, type: { const: 'command.receipt' }, device_id: ref('uuid'), payload: ref('hostForkReceiptPayload') }),
  deviceForkReceipt: object({ ...commandRoute, type: { const: 'command.receipt' }, payload: ref('deviceForkReceiptPayload') }),
}
// Refinements involving byte counts, cross-field equality, live authorization,
// native visibility and pixel products remain mandatory runtime checks.
at(definitions, 'visibleMediaReference').description = 'Versioned visible-event provenance, not download authority. At most 16 MiB, 32 million pixels and 16384 pixels per dimension; runtime validates event/manifest digests, current reader sync/epoch, MIME, bytes and independently authorized export/download.'
at(definitions.mediaResultPayload, 'properties').source = object({ source_id: ref('uuid'), kind: { const: 'file' }, origin: { const: 'session_attachment' },
  name: at(definitions.visibleMediaReference, 'properties', 'manifest', 'properties').name, size_bytes: { type: 'integer', minimum: 1, maximum: 16 * 1024 * 1024 },
  expires_at: at(definitions.hostMediaResolve, 'properties', 'payload', 'properties').expires_at })
at(definitions, 'mediaResultPayload').description = 'Source name and size must exactly equal the current reference manifest. No unavailable/directory source, native attachment identity, path or URL. A source reference is not export or download authority.'
const previewText = schemaList(at(definitions.messagePreview, 'properties', 'text').anyOf).find(item => item.type === 'string')
if (!previewText) throw new Error('Expected nullable shareable preview text schema')
previewText.maxLength = 32 * 1024
at(definitions, 'messagePreview').allOf = [{ if: { required: ['shareable'], properties: { shareable: { const: true } } },
  then: { properties: { text: { type: 'string', minLength: 1, maxLength: 32 * 1024 } } }, else: { properties: { text: { type: 'null' } } } }]
at(definitions, 'messagePreview').description = 'Exact authorized persisted visible subset; <=32768 UTF-8 text bytes and <=48KiB serialized payload. Image/file-only messages retain real anchors with text=null/shareable=false. Share confirmation requires unchanged current-reader authorization; no invented text.'
at(definitions, 'changesPage').description = 'Current configured-workspace Git HEAD to tracked index/worktree snapshot, never attributed to a turn. Maximum 32768 serialized UTF-8 bytes per page; version/manifest and connection-local cursors expire after 30 seconds. Runtime checks current reader/grant, exact source and byte budgets.'
const excludedTuple = at(definitions, 'changesPage', 'properties', 'excluded')
const excludedCount = schemaList(excludedTuple.prefixItems).length
excludedTuple.minItems = excludedCount
excludedTuple.maxItems = excludedCount
excludedTuple.items = false
at(definitions, 'changesPatch').description = 'At most 16384 serialized UTF-8 bytes per page and 20000 lines across the bounded snapshot. Byte-exact full copy only when complete, nonbinary, not partial, with no next cursor and exact UTF-8 patch bytes.'
at(definitions, 'changesPatch').allOf = [{ if: { required: ['copyable'], properties: { copyable: { const: true } } }, then: {
  properties: { complete: { const: true }, partial: { const: false }, next_cursor: { type: 'null' }, patch_utf8: { type: 'string', maxLength: 16_384 }, kind: { enum: ['text', 'symlink', 'gitlink'] } } } }]
const nullableTitle = schemaList(at(definitions.directoryMetadata, 'properties', 'title').anyOf).find(item => item.type === 'string')
if (!nullableTitle) throw new Error('Expected nullable directory title schema')
nullableTitle.pattern = '^(?![\\s\\S]*[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069])(?!\\s*$)[\\s\\S]+$'
at(definitions.directoryMetadata, 'properties').workspace_title = structuredClone(at(definitions.directoryMetadata, 'properties').title)
at(definitions, 'directoryMetadata').description = 'Plain untrusted native projection names, never paths or first-message fallbacks. Runtime enforces scalar Unicode, <=256 UTF-16 code units and <=1024 UTF-8 bytes; title source/cut describe cached or sequenced evidence, not live freshness.'
at(definitions, 'directoryMetadata').allOf = [{ if: { required: ['title'], properties: { title: { type: 'null' } } }, then: {
  properties: { title_source: { type: 'null' }, title_as_of_seq: { type: 'null' } } }, else: {
  properties: { title_source: { enum: ['cached', 'sequenced'] }, title_as_of_seq: { type: 'integer', minimum: -1, maximum: Number.MAX_SAFE_INTEGER } } } }]
function forkReceiptPayload(host: boolean): JsonSchema {
  const properties: JsonSchema = { command_type: { const: 'session.fork' }, workspace_id: ref('uuid'),
    state: { enum: [...(host ? [] : ['received']), 'host_accepted', 'dispatching', 'settled', 'rejected', 'outcome_unknown'] }, payload_sha256: ref('sha256'),
    ...(host ? {} : { updated_at: { type: 'string' } }), child_session_id: ref('uuid'), fork_outcome: ref('forkOutcome'),
    ...(host ? { created_session: ref('sessionCatalogItem') } : {}) }
  return { ...object(properties, ['command_type', 'workspace_id', 'state', 'payload_sha256', ...(host ? [] : ['updated_at'])]),
    dependentRequired: { child_session_id: ['fork_outcome'], fork_outcome: ['child_session_id'] }, allOf: [
      { if: { required: ['state'], properties: { state: { const: 'settled' } } }, then: { required: ['child_session_id', 'fork_outcome', ...(host ? ['created_session'] : [])],
        properties: { child_session_id: {}, ...(host ? { created_session: {} } : {}), fork_outcome: { type: 'object', properties: { checkpoint: { const: 'persisted' } } } } } },
      { if: { required: ['state'], properties: { state: { const: 'rejected' } } }, then: { not: { anyOf: [{ required: ['child_session_id'], properties: { child_session_id: {} } }, { required: ['fork_outcome'], properties: { fork_outcome: {} } }, ...(host ? [{ required: ['created_session'], properties: { created_session: {} } }] : [])] } } },
      ...(host ? [{ if: { required: ['created_session'], properties: { created_session: {} } }, then: { required: ['child_session_id', 'fork_outcome'], properties: { child_session_id: {}, fork_outcome: { type: 'object', properties: { checkpoint: { const: 'persisted' } } } } } }] : []),
    ], description: 'Negotiated session.fork.v1 only. Envelope session_id always remains the source; child differs from source. Runtime enforces exact anchor/workspace, original-once journal, monotone retained outcome, child catalog identity and checkpoint evidence. Unknown outcome must never replay the native fork.' }
}
definitions.hostForkReceiptPayload = forkReceiptPayload(true)
definitions.deviceForkReceiptPayload = forkReceiptPayload(false)

const relayPath = new URL('../contracts/ws/v1/relay.schema.json', import.meta.url)
let relayText = await readFile(relayPath, 'utf8')
const relayRoot = z.object({ $defs: z.record(z.string(), z.record(z.string(), z.unknown())), oneOf: z.array(z.object({ $ref: z.string() })) }).parse(JSON.parse(relayText))
const legacyItem = at(relayRoot.$defs, 'sessionCatalogItem')
definitions.sessionCatalogMetadataItem = { ...structuredClone(legacyItem), required: [...z.array(z.string()).parse(legacyItem.required), 'metadata'],
  properties: { ...structuredClone(at(legacyItem, 'properties')), metadata: ref('directoryMetadata') }, allOf: [
    { if: { required: ['workspace_id'], properties: { workspace_id: { type: 'null' } } }, then: { properties: { metadata: { type: 'object', properties: { workspace_title: { type: 'null' } } } } } },
    { if: { required: ['state'], properties: { state: { const: 'unavailable' } } }, then: { properties: { metadata: { type: 'object', properties: {
      title: { type: 'null' }, workspace_title: { type: 'null' }, title_source: { type: 'null' }, title_as_of_seq: { type: 'null' } } } } } },
  ] }
const catalog = structuredClone(at(relayRoot.$defs, 'hostSessionCatalog'))
const catalogProperties = { mode: { enum: ['snapshot', 'delta'] }, index: { type: 'integer', minimum: 0 }, complete: { type: 'boolean' } }
at(catalog, 'properties').payload = { oneOf: [object({ ...catalogProperties, items: { type: 'array', maxItems: 256, items: ref('sessionCatalogItem') } }),
  object({ ...catalogProperties, metadata_version: { const: 1 }, items: { type: 'array', maxItems: 256, items: ref('sessionCatalogMetadataItem') } })] }
catalog.description = 'Identifier-only legacy shape unless session.metadata.v1 is negotiated and metadata_version=1 is explicit. Version remains invariant across a catalog chunk sequence. Names do not grant session.metadata.read or replace current authorization.'
definitions.hostSessionCatalog = catalog
const submit = structuredClone(at(relayRoot.$defs, 'submitPayload'))
at(submit, 'properties', 'content').items = { oneOf: [ref('textContent'), ref('fileContent'), ref('imageContent')] }
definitions.submitPayload = submit
const reconcile = structuredClone(at(relayRoot.$defs, 'fileMessageReconcileToHost'))
at(schemaList(at(reconcile, 'properties', 'payload').allOf)[1], 'properties', 'content').contains = { anyOf: [ref('fileContent'), ref('imageContent')] }
definitions.fileMessageReconcileToHost = reconcile
const hostSubscribe = structuredClone(at(relayRoot.$defs, 'hostSessionSubscribe'))
at(hostSubscribe, 'properties', 'payload', 'properties').media_refs = { type: 'boolean' }
definitions.hostSessionSubscribe = hostSubscribe
const record = structuredClone(at(relayRoot.$defs, 'sessionRecord'))
at(record, 'properties', 'data').properties = { ...(isObject(at(record, 'properties', 'data').properties) ? at(record, 'properties', 'data', 'properties') : {}), content: ref('projectedContent'),
  message: { type: 'object', properties: { content: ref('projectedContent') } } }
definitions.sessionRecord = record

const frameGroups = {
  media: ['mediaResolve', 'hostMediaResolve', 'mediaResult', 'mediaError'],
  changes: ['changesGet', 'changesPatchGet', 'changesResult', 'changesPatchResult', 'changesError', 'changesPatchError'],
  'message-actions': ['messagePreviewGet', 'hostMessagePreviewGet', 'messagePreviewConfirm', 'hostMessagePreviewConfirm', 'messagePreviewResult', 'messagePreviewError'],
  fork: ['sessionFork', 'sessionForkToHost', 'hostForkReceipt', 'deviceForkReceipt'],
} as const
const frameNames = Object.values(frameGroups).flat()
for (const [name, definition] of Object.entries(definitions)) {
  if (JSON.stringify(relayRoot.$defs[name]) === JSON.stringify(definition)) continue
  if (process.argv.includes('--check')) { console.error(`Relay ${name} is stale; run npm run contracts`); process.exitCode = 1; continue }
  const entry = `    "${name}": ` + JSON.stringify(definition, null, 2).replaceAll('\n', '\n    ')
  const pattern = new RegExp(`^    "${name}": \\{[\\s\\S]*?^    \\},?`, 'm')
  relayText = pattern.test(relayText) ? relayText.replace(pattern, () => entry + ',') : relayText.replace('  "$defs": {', '  "$defs": {\n' + entry + ',')
}
for (const name of frameNames) if (!relayRoot.oneOf.some(item => item.$ref === ref(name).$ref)) {
  if (process.argv.includes('--check')) { console.error(`Relay ${name} frame is stale; run npm run contracts`); process.exitCode = 1 }
  else relayText = relayText.replace('  "oneOf": [', '  "oneOf": [\n    ' + JSON.stringify(ref(name)) + ',')
}
if (!process.argv.includes('--check')) await writeFile(relayPath, relayText)

async function featureOutput(path: string, value: unknown) {
  const target = new URL(`../contracts/${path}`, import.meta.url), body = JSON.stringify(value, null, 2) + '\n'
  if (process.argv.includes('--check')) {
    if (await readFile(target, 'utf8').catch(() => '') !== body) { console.error(`contracts/${path} is stale; run npm run contracts`); process.exitCode = 1 }
  } else await writeFile(target, body)
}
const allDefinitions = { ...relayRoot.$defs, ...definitions }
function referencedDefinitions(frames: readonly string[]): Record<string, JsonSchema> {
  const pending = [...frames], selected: Record<string, JsonSchema> = {}
  function visit(value: unknown): void {
    if (Array.isArray(value)) { for (const item of value) visit(item) }
    else if (isObject(value)) {
      if (typeof value.$ref === 'string' && value.$ref.startsWith('#/$defs/')) pending.push(value.$ref.slice('#/$defs/'.length))
      for (const item of Object.values(value)) visit(item)
    }
  }
  while (pending.length) {
    const name = pending.pop()
    if (name === undefined) throw new Error('Missing pending contract definition')
    if (selected[name]) continue
    const definition = allDefinitions[name]
    if (!definition) throw new Error(`Unknown contract definition: ${name}`)
    selected[name] = definition
    visit(definition)
  }
  return Object.fromEntries(Object.entries(selected).sort(([left], [right]) => left.localeCompare(right)))
}
for (const [name, frames] of Object.entries(frameGroups)) await featureOutput(`ws/v1/${name}.schema.json`, {
  $schema: 'https://json-schema.org/draft/2020-12/schema', $id: `urn:dsh-mobile-ustc:ws:${name}:v1`,
  description: 'Negotiated strict feature frames; references convey no authority. Current owner, resource, runtime epoch, reader sync, exact manifest/anchor and independent action/export grants remain runtime requirements.',
  oneOf: frames.map(ref), $defs: referencedDefinitions(frames),
})

const ids = { request: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', runtime: '66666666-6666-4666-8666-666666666666', epoch: '99999999-9999-4999-8999-999999999999',
  session: '22222222-2222-4222-8222-222222222222', subscription: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', sync: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  user: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', device: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', workspace: '88888888-8888-4888-8888-888888888888',
  child: '33333333-3333-4333-8333-333333333333', file: '44444444-4444-4444-8444-444444444444', snapshot: '55555555-5555-4555-8555-555555555555' }
const route = { v: 1, request_id: ids.request, runtime_id: ids.runtime, runtime_epoch: ids.epoch, session_id: ids.session }
const readRoute = { ...route, subscription_id: ids.subscription }
const expires = '2026-10-31T12:00:30.000Z'
const reference = { v: 1, origin: 'session_attachment', native_seq: 7, part_index: 0, event_version_sha256: 'a'.repeat(64),
  manifest: { name: 'image.png', size_bytes: 68, sha256: 'b'.repeat(64) }, media_type: 'image/png', width: 1, height: 1 }
const imagePayload = { mode: 'queue', content: [{ type: 'text', text: 'Describe this image' }, { type: 'image', file_id: ids.file }] }
const imageDigest = createHash('sha256').update(canonicalForkJson({ type: 'message.submit', session_id: ids.session, payload: imagePayload })).digest('hex')
const imageSubmit = { v: 1, type: 'message.submit', request_id: ids.request, runtime_id: ids.runtime, session_id: ids.session, payload: imagePayload }
const imageForwarded = { ...imageSubmit, runtime_epoch: ids.epoch, user_id: ids.user, device_id: ids.device, payload_sha256: imageDigest }
const mediaResolve = { ...readRoute, type: 'session.media.resolve', payload: { sync_id: ids.sync, reference } }
const mediaForwarded = { ...mediaResolve, payload: { ...mediaResolve.payload, user_id: ids.user, device_id: ids.device, key_version: 1,
  grant_version: 7, allow_workspace: false, lease_until: '2026-10-31T12:00:05.000Z', expires_at: expires } }
const imageRecord = { native_seq: 7, time: 1793448000000, type: 'user/message', data: { id: 'visible-message', content: [{ type: 'image', reference }] } }
const patch = 'diff --git a/example.txt b/example.txt\nindex 1111111..2222222 100644\n--- a/example.txt\n+++ b/example.txt\n@@ -1 +1 @@\n-old\n+new\n'
const path = { bytes_base64: Buffer.from('example.txt').toString('base64'), display: 'example.txt' }
const changeFile = { file_id: ids.file, status: 'modified', old_path: path, new_path: path, old_mode: '100644', new_mode: '100644',
  kind: 'text', patch_bytes: Buffer.byteLength(patch), complete: true, copyable: true }
const changesGet = { ...readRoute, type: 'session.changes.get', payload: { sync_id: ids.sync, limit: 20 } }
const changesPatchGet = { ...readRoute, type: 'session.changes.patch.get', payload: { sync_id: ids.sync, snapshot_id: ids.snapshot, file_id: ids.file } }
const changesResult = { ...readRoute, type: 'session.changes.result', sync_id: ids.sync, payload: {
  v: 1, sync_id: ids.sync, snapshot_id: ids.snapshot, source: 'configured_workspace_git', base: { kind: 'git_head', oid: '1'.repeat(40) },
  version: 'c'.repeat(64), manifest_sha256: 'd'.repeat(64), expires_at: expires, scope: 'tracked_head_to_index_worktree',
  excluded: ['untracked', 'ignored', 'submodule_contents'], complete: true, truncated: false, files: [changeFile], next_cursor: null } }
const changesPatchResult = { ...readRoute, type: 'session.changes.patch.result', sync_id: ids.sync, payload: {
  v: 1, sync_id: ids.sync, snapshot_id: ids.snapshot, file_id: ids.file, version: 'c'.repeat(64), kind: 'text', complete: true, copyable: true,
  partial: false, patch_base64: Buffer.from(patch).toString('base64'), patch_utf8: patch, hunks: [{ old_start: 1, old_count: 1, new_start: 1, new_count: 1,
    lines: [{ kind: 'delete', bytes_base64: Buffer.from('old\n').toString('base64'), text: 'old\n', old_line: 1, new_line: null },
      { kind: 'add', bytes_base64: Buffer.from('new\n').toString('base64'), text: 'new\n', old_line: null, new_line: 1 }] }], next_cursor: null } }
const anchor = { v: 1 as const, subscription_id: ids.subscription, sync_id: ids.sync, native_seq: 7, message_version_sha256: 'e'.repeat(64), anchor_sha256: 'f'.repeat(64) }
const forkPayload = { workspace_id: ids.workspace, anchor }
const forkDigest = relayForkDigest(ids.epoch, ids.session, forkPayload)
const fork = { ...route, type: 'session.fork', payload: forkPayload }
const forkForwarded = { ...fork, user_id: ids.user, device_id: ids.device, payload_sha256: forkDigest }
const partialPayload = { command_type: 'session.fork', workspace_id: ids.workspace, state: 'outcome_unknown', payload_sha256: forkDigest,
  child_session_id: ids.child, fork_outcome: { v: 1, workspace_attachment: 'failed', checkpoint: 'persisted' } }
const settledPayload = { ...partialPayload, state: 'settled' }
const hostForkSettled = { ...route, type: 'command.receipt', device_id: ids.device, payload: { ...settledPayload,
  created_session: { session_id: ids.child, dsh_session_id: 'fixture-native-child', workspace_id: ids.workspace, state: 'available', last_persisted_seq: 9 } } }
const previewGet = { ...readRoute, type: 'session.message.preview.get', payload: { sync_id: ids.sync, native_seq: 7 } }
const previewConfirm = { ...readRoute, type: 'session.message.preview.confirm', payload: { sync_id: ids.sync, anchor } }
for (const [name, sample] of Object.entries({
  'message-image-submit': imageSubmit, 'message-image-submit.forwarded': imageForwarded,
  'message-image-reconcile.forwarded': { ...imageForwarded, type: 'message.files.reconcile' },
  'session-media-resolve': mediaResolve, 'session-media-resolve.forwarded': mediaForwarded,
  'session-media-result': { ...readRoute, type: 'session.media.result', sync_id: ids.sync, payload: { reference,
    source: { source_id: ids.file, kind: 'file', origin: 'session_attachment', name: reference.manifest.name, size_bytes: reference.manifest.size_bytes, expires_at: expires } } },
  'session-media-error': { ...readRoute, type: 'session.media.error', sync_id: ids.sync, payload: { code: 'file.export_changed' } },
  'session-snapshot.media': { ...readRoute, type: 'session.snapshot', sync_id: ids.sync, payload: { cursor: 7, has_more: false, records: [imageRecord], assistant: null } },
  'session-changes-get': changesGet, 'session-changes-result': changesResult, 'session-changes-patch-get': changesPatchGet, 'session-changes-patch-result': changesPatchResult,
  'session-changes-error': { ...readRoute, type: 'session.changes.error', sync_id: ids.sync, payload: { code: 'changes.stale' } },
  'session-changes-patch-error': { ...readRoute, type: 'session.changes.patch.error', sync_id: ids.sync, payload: { code: 'changes.stale' } },
  'session-message-preview-get': previewGet, 'session-message-preview-get.forwarded': { ...previewGet, user_id: ids.user, device_id: ids.device },
  'session-message-preview-confirm': previewConfirm, 'session-message-preview-confirm.forwarded': { ...previewConfirm, user_id: ids.user, device_id: ids.device },
  'session-message-preview-result': { ...readRoute, type: 'session.message.preview.result', sync_id: ids.sync, payload: { v: 1, anchor, text: 'Exact authorized visible message', shareable: true, complete: true } },
  'session-message-preview-result.unshareable': { ...readRoute, type: 'session.message.preview.result', sync_id: ids.sync, payload: { v: 1, anchor, text: null, shareable: false, complete: true } },
  'session-message-preview-error': { ...readRoute, type: 'session.message.preview.error', sync_id: ids.sync, payload: { code: 'message.stale' } },
  'session-fork': fork, 'session-fork.forwarded': forkForwarded,
  'host-session-fork.host_accepted': { ...route, type: 'command.receipt', device_id: ids.device, payload: { command_type: 'session.fork', workspace_id: ids.workspace, state: 'host_accepted', payload_sha256: forkDigest } },
  'host-session-fork.partial-receipt': { ...route, type: 'command.receipt', device_id: ids.device, payload: partialPayload },
  'host-session-fork.settled': hostForkSettled,
  'device-session-fork.partial-receipt': { ...route, type: 'command.receipt', payload: { ...partialPayload, updated_at: '2026-10-31T12:00:01.000Z' } },
  'device-session-fork.settled': { ...route, type: 'command.receipt', payload: { ...settledPayload, updated_at: '2026-10-31T12:00:01.000Z' } },
})) await featureOutput(`ws/v1/golden/${name}.json`, sample)
await featureOutput('m0/golden/message-image-submit.request.json', { v: 0, type: 'message.submit', request_id: ids.request, runtime_epoch: ids.epoch, session_id: ids.session, payload: imagePayload })
await featureOutput('m0/golden/session-fork.request.json', { v: 0, type: 'session.fork', request_id: ids.request, runtime_epoch: ids.epoch, session_id: ids.session, payload: forkPayload })
