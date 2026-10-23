import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'

const load = async (path: string) => JSON.parse(await readFile(fileURLToPath(new URL(path, import.meta.url)), 'utf8')) as unknown
const ajv = new Ajv2020({ allErrors: true, strict: true })
const schema = await load('../../../contracts/ws/v1/relay.schema.json') as object
const validate = ajv.compile(schema)

test('WSS relay business-frame schema accepts golden requests and receipts only', async () => {
  for (const path of [
    '../../../contracts/ws/v1/golden/message-submit.json',
    '../../../contracts/ws/v1/golden/message-submit.forwarded.json',
    '../../../contracts/ws/v1/golden/host-command-receipt.json',
  ]) {
    const value = await load(path)
    assert.equal(validate(value), true, ajv.errorsText(validate.errors))
  }
  const invalid = await load('../../../contracts/ws/v1/golden/invalid-message-submit.json')
  assert.equal(validate(invalid), false)
})
