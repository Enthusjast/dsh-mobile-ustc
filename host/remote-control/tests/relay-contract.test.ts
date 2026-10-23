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
    '../../../contracts/ws/v1/golden/message-submit.json',
    '../../../contracts/ws/v1/golden/message-submit.forwarded.json',
    '../../../contracts/ws/v1/golden/host-command-receipt.json',
    '../../../contracts/ws/v1/golden/host-session-catalog.json',
    '../../../contracts/ws/v1/golden/host-session-catalog.ack.json',
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

  const forwarded = await load('../../../contracts/ws/v1/golden/message-submit.forwarded.json') as {
    request_id: string
    session_id: string
    payload: { mode: string; content: Array<{ type: string; text: string }> }
    payload_sha256: string
  }
  const body = canonicalValue({ type: 'message.submit', session_id: forwarded.session_id, payload: forwarded.payload })
  const digest = createHash('sha256').update(JSON.stringify(body)).digest('hex')
  assert.equal(forwarded.payload_sha256, digest)
})

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (typeof value !== 'object' || value === null) return value
  const object = value as Record<string, unknown>
  return Object.fromEntries(Object.keys(object).sort().map(key => [key, canonicalValue(object[key])]))
}
