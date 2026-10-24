import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { ApprovalContext, ApprovalDecision } from '../host/remote-control/src/approval-contract.js'
import { ApprovalLease } from '../host/remote-control/src/approval-lease.js'
import { ApprovalWireFrame, approvalResultDigest, type ApprovalResultFacts } from '../host/remote-control/src/approval-protocol.js'
import { canonicalObject } from '../host/remote-control/src/canonical.js'

const output = fileURLToPath(new URL('../contracts/security/approval.schema.json', import.meta.url))
const schema = z.toJSONSchema(z.union([ApprovalContext, ApprovalDecision, ApprovalLease]), { target: 'draft-2020-12' })
schema.$id = 'urn:dsh-mobile-ustc:security:approval:v1'
schema.description = 'Approval binding, signed decision and authority lease shapes. Implementations additionally enforce RFC 8785 bytes, UTF-8 byte budgets, scalar Unicode, canonical 32-byte nonces, valid UTC millisecond dates, unique resource facts, a maximum 180-second request lifetime, decision freshness, pinned authority keys and a maximum three-second connection-bound lease. This contract alone grants no execution authority.'
const generated = `${JSON.stringify(schema, null, 2)}\n`
if (process.argv.includes('--check')) {
  if ((await readFile(output, 'utf8').catch(() => '')) !== generated) {
    console.error('contracts/security/approval.schema.json is stale; run npm run contracts')
    process.exitCode = 1
  }
} else await writeFile(output, generated)

const wireOutput = fileURLToPath(new URL('../contracts/ws/v1/approval.schema.json', import.meta.url))
const wireSchema = z.toJSONSchema(ApprovalWireFrame, { target: 'draft-2020-12' })
wireSchema.$id = 'urn:dsh-mobile-ustc:ws:approval:v1'
wireSchema.description = 'Negotiated approval.signed.v1 extension to the base Relay contract. Host actor invalidations additionally negotiate approval.invalidation.v1 and bind the exact connection. Phone decisions use fresh HTTPS JWT/DPoP admission before the Relay forwards approval.decision to the host. Context fragments contain at most 128 KiB in total, at most four ordered parts, with a three-second assembly deadline. Host result hashes cover JCS type/runtime/epoch/session/payload, excluding request_id, v and payload_sha256. Runtime validators enforce cross-field state/result and fragment bounds beyond JSON Schema.'
const wireGenerated = `${JSON.stringify(wireSchema, null, 2)}\n`
if (process.argv.includes('--check')) {
  if ((await readFile(wireOutput, 'utf8').catch(() => '')) !== wireGenerated) { console.error('contracts/ws/v1/approval.schema.json is stale; run npm run contracts'); process.exitCode = 1 }
} else await writeFile(wireOutput, wireGenerated)

const source = JSON.parse(await readFile(new URL('../contracts/security/approval-signatures.json', import.meta.url), 'utf8'))
const facts: ApprovalResultFacts = {
  type: 'approval.result', runtime_id: source.context.runtime_id, runtime_epoch: source.context.runtime_epoch, session_id: source.context.session_id,
  payload: { approval_id: source.context.approval_id, execution_id: source.context.execution_id, binding_sha256: source.binding_sha256,
    decision_payload_sha256: source.vectors.find((item: { name: string }) => item.name === 'node-signed-allow').payload_sha256, state: 'settled', execution_outcome: 'succeeded' },
}
const goldenOutput = fileURLToPath(new URL('../contracts/ws/v1/approval-result.golden.json', import.meta.url))
const golden = `${JSON.stringify({ facts, canonical: Buffer.from(canonicalObject(facts)).toString(), sha256: approvalResultDigest(facts) }, null, 2)}\n`
if (process.argv.includes('--check')) {
  if ((await readFile(goldenOutput, 'utf8').catch(() => '')) !== golden) { console.error('contracts/ws/v1/approval-result.golden.json is stale; run npm run contracts'); process.exitCode = 1 }
} else await writeFile(goldenOutput, golden)
