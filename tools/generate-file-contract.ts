import { readFile, writeFile } from 'node:fs/promises'
import { z } from 'zod'
import { FileFrame, type FileOffer } from '../host/remote-control/src/file-protocol.js'
import { relayPayloadDigest } from '../host/remote-control/src/relay-client.js'

async function output(path: string, value: unknown) {
  const url = new URL(`../${path}`, import.meta.url), encoded = `${JSON.stringify(value, null, 2)}\n`
  if (process.argv.includes('--check')) {
    if (await readFile(url, 'utf8').catch(() => '') !== encoded) { console.error(`${path} is stale; run npm run contracts`); process.exitCode = 1 }
  } else await writeFile(url, encoded)
}
const schema = z.toJSONSchema(FileFrame, { target: 'draft-2020-12' })
schema.$id = 'urn:dsh-mobile-ustc:ws:file-handoff:v1'
schema.description = 'Host-only file.handoff.v1 extension, negotiated with session.catalog.v1. Five-second renewable authority is fenced to the exact installation key/runtime epoch/connection. File reads additionally require a one-use ticket and registered-key ES256 proof. Runtime validators enforce name byte budgets, cross-field lifetime/route/ack correlation, current uploader grant/device/scope and content SHA-256. Staged acknowledges temporary receipt availability, not agent queue admission. Native receipts and paths never cross this protocol.'
await output('contracts/ws/v1/file-handoff.schema.json', schema)
const runtime_id = '66666666-6666-4666-8666-666666666666', runtime_epoch = '99999999-9999-4999-8999-999999999999'
const session_id = '22222222-2222-4222-8222-222222222222', request_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const offer: FileOffer = { handoff_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', file_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  user_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', device_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', key_version: 1, grant_version: 3,
  name: '资料.txt', size_bytes: 3, sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  download_token: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE', lease_until: '2026-10-25T12:00:05.000Z', expires_at: '2026-10-25T12:05:00.000Z' }
const base = { v: 1 as const, request_id, runtime_id, runtime_epoch }
const ids = { handoff_id: offer.handoff_id, file_id: offer.file_id }
const frames = [
  { ...base, session_id, type: 'file.offer', payload: offer },
  { ...base, type: 'file.renew', payload: { handoff_ids: [offer.handoff_id] } },
  { ...base, type: 'file.renewed', payload: { leases: [{ handoff_id: offer.handoff_id, lease_until: offer.lease_until, expires_at: offer.expires_at }] } },
  { ...base, session_id, type: 'file.staged', payload: { ...ids, name: offer.name, size_bytes: offer.size_bytes, sha256: offer.sha256 } },
  ...['file.staged.ack', 'file.release', 'file.release.ack'].map(type => ({ ...base, session_id, type, payload: ids })),
]
for (const frame of frames) { FileFrame.parse(frame); await output(`contracts/ws/v1/golden/${frame.type}.json`, frame) }
const message = { v: 1, type: 'message.submit', request_id, runtime_id, session_id,
  payload: { mode: 'queue' as const, content: [{ type: 'text' as const, text: '请检查附件。' }, { type: 'file' as const, file_id: offer.file_id }] } }
await output('contracts/ws/v1/golden/message-file-submit.json', message)
await output('contracts/ws/v1/golden/message-file-submit.forwarded.json', { ...message, runtime_epoch,
  user_id: offer.user_id, device_id: offer.device_id, payload_sha256: relayPayloadDigest(session_id, message.payload) })
