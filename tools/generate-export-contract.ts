import { readFile, writeFile } from 'node:fs/promises'
import { z } from 'zod'
import { ExportFrame } from '../host/remote-control/src/export-protocol.js'

async function output(path: string, value: unknown) {
  const url = new URL(`../${path}`, import.meta.url), body = JSON.stringify(value, null, 2) + '\n'
  if (process.argv.includes('--check')) { if (await readFile(url, 'utf8').catch(() => '') !== body) { console.error(`${path} is stale; run npm run contracts`); process.exitCode = 1 } }
  else await writeFile(url, body)
}
const schema = z.toJSONSchema(ExportFrame, { target: 'draft-2020-12' })
schema.$id = 'urn:dsh-mobile-ustc:ws:file-export:v1'
schema.description = 'file.export.v1. Phone selectors are opaque connection-local source/directory/cursor UUIDs, never paths or native attachment identities. Host operations use fresh server operation IDs, exact authenticated device/key/grant scope and renewable five-second leases. Source URLs are Host-only and never forwarded to phones. Implementations separately enforce direction, owner, lifetime, manifest, page byte budget, one-shot source integrity and current workspace authority.'
await output('contracts/ws/v1/file-export.schema.json', schema)
const route = { v: 1, request_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', runtime_id: '66666666-6666-4666-8666-666666666666', runtime_epoch: '99999999-9999-4999-8999-999999999999', session_id: '22222222-2222-4222-8222-222222222222' }
const source = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const lease = { user_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', device_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', key_version: 1, grant_version: 7, allow_workspace: false,
  lease_until: '2026-10-26T12:00:05.000Z', expires_at: '2026-10-26T12:05:00.000Z' }
const file = { file_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', runtime_id: route.runtime_id, session_id: route.session_id, direction: 'from_host', name: '资料.txt', size_bytes: 3,
  sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', state: 'uploading', created_at: '2026-10-26T12:00:00.000Z', upload_expires_at: lease.expires_at, expires_at: lease.expires_at }
const frames: Record<string, unknown> = {
  'file.exports.list': { ...route, type: 'file.exports.list', payload: {} },
  'file.exports.list.forwarded': { ...route, type: 'file.exports.list', payload: lease },
  'file.exports.result': { ...route, type: 'file.exports.result', payload: { items: [{ source_id: source, kind: 'file', origin: 'session_attachment', name: file.name, size_bytes: 3, expires_at: lease.expires_at }], directory_id: source, cursor: null } },
  'file.export.request': { ...route, type: 'file.export.request', payload: { source_id: source } },
  'file.export.request.forwarded': { ...route, type: 'file.export.request', payload: { ...lease, source_id: source, origin_request_id: route.request_id } },
  'file.export.manifest': { ...route, type: 'file.export.manifest', payload: { source_id: source, origin: 'session_attachment', name: file.name, size_bytes: 3, sha256: file.sha256, source_expires_at: lease.expires_at } },
  'file.export.upload': { ...route, type: 'file.export.upload', payload: { file, upload: { url: 'https://objects.example.edu/private?signature=fixture-only', method: 'PUT', headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': '3' }, expires_at: lease.expires_at } } },
  'file.export.uploaded': { ...route, type: 'file.export.uploaded', payload: { file_id: file.file_id } },
  'file.export.committed': { ...route, type: 'file.export.committed', payload: { file_id: file.file_id } },
  'file.export.accepted': { ...route, type: 'file.export.accepted', payload: { file: { ...file, state: 'scanning', expires_at: '2026-10-27T12:00:00.000Z' } } },
  'file.export.abort': { ...route, type: 'file.export.abort', payload: { code: 'access.denied' } },
  'file.export.error': { ...route, type: 'file.export.error', payload: { code: 'file.export_changed' } },
  'file.export.cancel': { ...route, type: 'file.export.cancel', payload: {} },
}
const { session_id: _session, ...global } = route
frames['file.export.renew'] = { ...global, type: 'file.export.renew', payload: { operation_ids: [route.request_id] } }
frames['file.export.renewed'] = { ...global, type: 'file.export.renewed', payload: { leases: [{ operation_id: route.request_id, lease_until: lease.lease_until, expires_at: lease.expires_at }] } }
for (const [name, frame] of Object.entries(frames)) { ExportFrame.parse(frame); await output(`contracts/ws/v1/golden/${name}.json`, frame) }
