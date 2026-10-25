import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { parse } from 'yaml'
import { Ajv2020 } from 'ajv/dist/2020.js'

const api = parse(await readFile(new URL('../../../contracts/openapi/remote.yaml', import.meta.url), 'utf8')) as { components: { schemas: object }; paths: Record<string, unknown> }
const defs = JSON.parse(JSON.stringify(api.components.schemas).replaceAll('#/components/schemas/', '#/$defs/')) as object
const ajv = new Ajv2020({ strict: true, allErrors: true })
ajv.addFormat('uuid', /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
ajv.addFormat('date-time', value => Number.isFinite(Date.parse(value)))
ajv.addFormat('uri', value => { try { return Boolean(new URL(value).protocol) } catch { return false } })
const request = ajv.compile({ $defs: defs, $ref: '#/$defs/FileRegistration' })
const prepared = ajv.compile({ $defs: defs, $ref: '#/$defs/FilePreparedResponse' })
const status = ajv.compile({ $defs: defs, $ref: '#/$defs/FileStatusResponse' })
const load = async (name: string) => JSON.parse(await readFile(new URL(`../../../contracts/files/v1/golden/${name}.json`, import.meta.url), 'utf8'))

test('file HTTP OpenAPI accepts public goldens and rejects authority/path smuggling', async () => {
  const registration = await load('registration')
  assert.equal(request(registration), true, ajv.errorsText(request.errors))
  for (const payload of [
    { ...registration, name: '../private.txt' }, { ...registration, name: 'C:\\private.txt' },
    { ...registration, name: '.' }, { ...registration, name: ' ' }, { ...registration, name: 'bad\u0000' },
    { ...registration, size_bytes: null }, { ...registration, size_bytes: -1 }, { ...registration, size_bytes: 200_000_001 },
    { ...registration, device_id: registration.request_id }, { ...registration, object_key: 'client-owned' },
  ]) assert.equal(request(payload), false, JSON.stringify(payload))
  const { size_bytes: _size, ...missingSize } = registration
  assert.equal(request(missingSize), false)
  const capability = await load('prepared')
  assert.equal(prepared(capability), true, ajv.errorsText(prepared.errors))
  assert.equal(prepared({ ...capability, data: { ...capability.data, upload: { ...capability.data.upload, url: 'http://objects.example.edu/file' } } }), false)
  assert.equal(prepared({ ...capability, data: { ...capability.data, lease_id: registration.request_id } }), false)
  const settled = await load('clean')
  assert.equal(status(settled), true, ajv.errorsText(status.errors))
  assert.equal(status({ ...settled, data: { file: { ...settled.data.file, receipt_id: registration.request_id } } }), false)
  for (const delivery of [{ state: 'waiting' }, { state: 'ready', expires_at: settled.data.file.expires_at }, { state: 'bound', request_id: registration.request_id, command_state: 'received' }]) {
    assert.equal(status({ ...settled, data: { file: { ...settled.data.file, delivery } } }), true, ajv.errorsText(status.errors))
  }
  for (const delivery of [{ state: 'ready' }, { state: 'bound', request_id: registration.request_id, command_state: 'invented' }, { state: 'waiting', receipt_id: 'private' }]) {
    assert.equal(status({ ...settled, data: { file: { ...settled.data.file, delivery } } }), false)
  }
  for (const path of ['/v1/runtimes/{id}/sessions/{session_id}/files', '/v1/files/{id}', '/v1/files/{id}/upload-url', '/v1/files/{id}/commit']) assert.ok(api.paths[path])
})
