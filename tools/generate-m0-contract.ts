import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { Command } from '../host/remote-control/src/protocol.js'

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
