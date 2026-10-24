import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { ApprovalWireFrame, approvalResultDigest, encodeApprovalContextFrames } from '../src/approval-protocol.js'
import { approvalBinding, type ApprovalContext } from '../src/approval-contract.js'

const fixture = JSON.parse(await readFile(new URL('../../../contracts/security/approval-signatures.json', import.meta.url), 'utf8'))
const context = fixture.context as ApprovalContext
const route = { v: 1, request_id: context.approval_id, runtime_id: context.runtime_id, runtime_epoch: context.runtime_epoch, session_id: context.session_id }
const status = { approval_id: context.approval_id, runtime_id: context.runtime_id, runtime_epoch: context.runtime_epoch, session_id: context.session_id, execution_id: context.execution_id,
  binding_sha256: fixture.binding_sha256, state: 'pending', expires_at: context.expires_at }
const resultGolden = JSON.parse(await readFile(new URL('../../../contracts/ws/v1/approval-result.golden.json', import.meta.url), 'utf8'))

test('negotiated approval wire contract keeps decision admission and execution facts distinct', async () => {
  const schema = JSON.parse(await readFile(new URL('../../../contracts/ws/v1/approval.schema.json', import.meta.url), 'utf8'))
  const ajv = new Ajv2020({ strict: true })
  ajv.addFormat('date-time', value => Number.isFinite(Date.parse(value)))
  const validate = ajv.compile(schema)
  const frames = [
    ...encodeApprovalContextFrames('approval.request', context.approval_id, context),
    { ...route, type: 'approval.registered', payload: { status } },
    { v: 1, request_id: context.approval_id, runtime_id: context.runtime_id, type: 'approval.subscribe', payload: {} },
    { v: 1, request_id: context.approval_id, runtime_id: context.runtime_id, type: 'approval.snapshot', payload: { items: [status] } },
    { ...route, type: 'approval.reference', payload: { status } },
    { ...route, type: 'approval.details.get', payload: { approval_id: context.approval_id } },
    { ...route, type: 'approval.details', payload: { context } },
    { ...route, type: 'approval.decision', payload: { approval_id: context.approval_id, decision_jws: fixture.vectors[0].compact, authorization_jws: fixture.vectors[0].compact } },
    { ...route, type: 'approval.result', payload_sha256: 'a'.repeat(64), payload: { approval_id: context.approval_id, execution_id: context.execution_id,
      binding_sha256: fixture.binding_sha256, state: 'settled', decision_payload_sha256: 'b'.repeat(64), execution_outcome: 'failed' } },
    { ...route, type: 'approval.result.ack', payload_sha256: 'a'.repeat(64), payload: { status: { ...status, state: 'allowed', host_state: 'settled', execution_outcome: 'failed' } } },
  ]
  for (const frame of frames) { assert.ok(ApprovalWireFrame.safeParse(frame).success); assert.equal(validate(frame), true, JSON.stringify(validate.errors)) }
  for (const frame of [
    { ...route, type: 'approval.decision', payload: { decision: 'allow_once' } },
    { ...frames[8]!, payload: { ...(frames[8]!.payload as object), execution_outcome: undefined } },
    { ...frames[8]!, payload: { ...(frames[8]!.payload as object), state: 'consumed' } },
    { ...route, type: 'approval.details.get', user_id: fixture.registered.user_id, payload: { approval_id: context.approval_id } },
  ]) assert.equal(ApprovalWireFrame.safeParse(frame).success, false)
})

test('large Unicode approval contexts fragment only bounded canonical body bytes', () => {
  const large = structuredClone(context)
  large.arguments = { command: '中文🙂'.repeat(10_000) }
  const frames = encodeApprovalContextFrames('approval.request', context.approval_id, large)
  assert.ok(frames.length > 1 && frames.length <= 4)
  const chunks = frames.map(frame => { assert.equal(frame.type, 'approval.fragment'); assert.ok(Buffer.byteLength(JSON.stringify(frame)) <= 64 * 1024); return frame.type === 'approval.fragment' ? Buffer.from(frame.payload.data, 'base64') : Buffer.alloc(0) })
  assert.deepEqual(Buffer.concat(chunks), Buffer.from(approvalBinding(large).canonical))
  const tooLarge = structuredClone(context)
  tooLarge.arguments = { command: 'x'.repeat(128 * 1024) }
  assert.throws(() => encodeApprovalContextFrames('approval.request', context.approval_id, tooLarge))
})

test('approval result fingerprints bind the historical target and final native outcome', () => {
	assert.equal(approvalResultDigest(resultGolden.facts), resultGolden.sha256)
  const result = { type: 'approval.result' as const, runtime_id: context.runtime_id, runtime_epoch: context.runtime_epoch, session_id: context.session_id,
    payload: { approval_id: context.approval_id, execution_id: context.execution_id, binding_sha256: fixture.binding_sha256 as string,
      decision_payload_sha256: 'b'.repeat(64), state: 'settled' as const, execution_outcome: 'succeeded' as const } }
  const digest = approvalResultDigest(result)
  assert.match(digest, /^[0-9a-f]{64}$/)
  assert.notEqual(approvalResultDigest({ ...result, runtime_epoch: context.host_id }), digest)
  assert.notEqual(approvalResultDigest({ ...result, payload: { ...result.payload, execution_outcome: 'failed' } }), digest)
})
