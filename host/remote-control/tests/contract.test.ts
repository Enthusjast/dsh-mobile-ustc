import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { parseCommand } from '../src/protocol.js'

const load = async (path: string) => JSON.parse(await readFile(fileURLToPath(new URL(path, import.meta.url)), 'utf8')) as unknown
const ajv = new Ajv2020({ allErrors: true, strict: true })
ajv.addFormat('uuid', {
  type: 'string',
  validate: value => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value),
})
const schema = await load('../../../contracts/m0/command.schema.json') as object
const validate = ajv.compile(schema)

test('generated JSON Schema and runtime parser agree on cross-language golden requests', async () => {
  for (const path of [
    '../../../contracts/m0/golden/session-list.request.json',
    '../../../contracts/m0/golden/message-submit.request.json',
  ]) {
    const value = await load(path)
    assert.equal(validate(value), true, ajv.errorsText(validate.errors))
    assert.doesNotThrow(() => parseCommand(value))
  }
  const invalid = await load('../../../contracts/m0/golden/invalid-unknown-field.request.json')
  assert.equal(validate(invalid), false)
  assert.throws(() => parseCommand(invalid), /protocol.invalid/)
})
