import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { ApprovalContext, ApprovalDecision } from '../host/remote-control/src/approval-contract.js'

const output = fileURLToPath(new URL('../contracts/security/approval.schema.json', import.meta.url))
const schema = z.toJSONSchema(z.union([ApprovalContext, ApprovalDecision]), { target: 'draft-2020-12' })
schema.$id = 'urn:dsh-mobile-ustc:security:approval:v1'
schema.description = 'Approval binding and signed decision shapes. Implementations additionally enforce RFC 8785 bytes, UTF-8 byte budgets, scalar Unicode, canonical 32-byte nonces, valid UTC millisecond dates, unique resource facts, a maximum 180-second request lifetime and decision freshness. This contract alone grants no execution authority.'
const generated = `${JSON.stringify(schema, null, 2)}\n`
if (process.argv.includes('--check')) {
  if ((await readFile(output, 'utf8').catch(() => '')) !== generated) {
    console.error('contracts/security/approval.schema.json is stale; run npm run contracts')
    process.exitCode = 1
  }
} else await writeFile(output, generated)
