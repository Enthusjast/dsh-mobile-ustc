import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { CompactSign, calculateJwkThumbprint } from 'jose'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { SignedApprovals } from '../src/signed-approvals.js'
import { RelayApprovals } from '../src/relay-approvals.js'
import { ApprovalWireFrame, type ApprovalResultFrame } from '../src/approval-protocol.js'
import { approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalContext, type ApprovalDecision } from '../src/approval-contract.js'
import { canonicalObject } from '../src/canonical.js'

async function until<Value>(read: () => Value | undefined): Promise<Value> {
  const deadline = Date.now() + 2000
  while (Date.now() < deadline) { const value = read(); if (value !== undefined) return value; await new Promise(resolve => setTimeout(resolve, 5)) }
  throw new Error('approval fixture did not progress')
}

async function fixture(t: import('node:test').TestContext) {
  const h = await host({ probe: false }), epoch = randomUUID(), hostID = randomUUID(), installID = randomUUID(), workspaceID = randomUUID()
  const parent = await PersistentCommandJournal.open(join(h.directory, 'reports', 'commands.sqlite'), h.runtimeId), journal = parent.approvals(epoch)
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), publicJWK = keys.publicKey.export({ format: 'jwk' }) as { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  const jkt = await calculateJwkThumbprint(publicJWK), actor = { user_id: randomUUID(), device_id: randomUUID() }
  const workspaces = [{ id: 'fixture', cwd: h.cwd, remoteId: workspaceID }]
  const client = new DshClient(h.ctx, h.runtimeId, workspaces, ['fixture']), created = await client.create('fixture', 'fixture')
  const agent = h.ctx.agents.get(await client.resolve(created.session_id, new AbortController().signal))!
  agent.session.append('turn/start', { turn: 1 })
  const owner = new SignedApprovals(h.ctx, h.runtimeId, epoch, journal, workspaces, value => value === agent, 3000, { hostId: hostID, installationId: installID,
    policyVersion: 7, requiredAssurance: { profile: 'fixture/verified', max_auth_age_seconds: 60 }, authorities: [{ issuer: 'https://remote.example.edu', key_id: 'dsh-approval-authority/peer-test',
      public_jwk: publicJWK, key_jkt: jkt, active: true, valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString() }] })
  const peers: RelayApprovals[] = []
  t.after(async () => { for (const peer of peers) peer.close(); owner.close(); parent.close(); await h.close() })
  const connect = (frames: ApprovalWireFrame[], catalog = async (_id: string, _signal: AbortSignal) => {}) => {
    const peer = new RelayApprovals(owner, { installationId: installID, connectionId: randomUUID(), signal: new AbortController().signal,
      async send(value) { frames.push(ApprovalWireFrame.parse(value)) }, publishCatalog: catalog, fail() {} })
    peers.push(peer)
    return peer
  }
  const context = (): ApprovalContext => ({ domain: 'dsh-mobile-ustc/approval-context/v1', protocol_version: 1, host_id: hostID, installation_id: installID, runtime_id: h.runtimeId, runtime_epoch: epoch,
    session_id: created.session_id, dsh_session_id: String(agent.id), approval_id: randomUUID(), execution_id: randomUUID(), call_id: randomUUID(), tool: 'protected', arguments: { value: 'private-report-fixture' },
    workspace: { workspace_id: workspaceID, root_sha256: 'a'.repeat(64) }, resources: [], nonce: randomBytes(32).toString('base64url'), policy_version: 7,
    required_assurance: { profile: 'fixture/verified', max_auth_age_seconds: 60 }, created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 120_000).toISOString() })
  const approve = async (context: ApprovalContext) => {
    journal.register(context)
    const decision: ApprovalDecision = { domain: 'dsh-mobile-ustc/approval-decision/v1', protocol_version: 1, host_id: hostID, installation_id: installID, runtime_id: h.runtimeId, runtime_epoch: epoch,
      session_id: context.session_id, approval_id: context.approval_id, execution_id: context.execution_id, binding_sha256: approvalBinding(context).sha256, decision: 'allow_once', ...actor, key_version: 1,
      policy_version: 7, nonce: context.nonce, issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 25_000).toISOString() }
    const proof = await new CompactSign(canonicalObject(decision)).setProtectedHeader({ alg: 'ES256', kid: approvalKeyID(actor.device_id, 1), typ: APPROVAL_JWS_TYPE }).sign(keys.privateKey)
    const authority = (request: ApprovalContext, claims: ApprovalDecision) => ({ lease_id: randomUUID(), action: 'approval.decide', role: 'owner', runtime_id: h.runtimeId, runtime_epoch: epoch,
      session_id: request.session_id, approval_id: request.approval_id, execution_id: request.execution_id, binding_sha256: claims.binding_sha256, policy_version: 7, ...actor, key_version: 1,
      approval_key_jkt: jkt, grant_version: 1, assurance_profile: 'fixture/verified', authenticated_at: new Date(Date.now() - 1000).toISOString(), issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 2000).toISOString() })
    await journal.decide(context.approval_id, proof, { ...actor, key_version: 1, approval_key_jkt: jkt, public_jwk: publicJWK, active: true }, authority)
    return authority
  }
  const ack = (report: ApprovalResultFrame) => ({ ...report, type: 'approval.result.ack', payload: { status: {
    approval_id: report.payload.approval_id, runtime_id: report.runtime_id, runtime_epoch: report.runtime_epoch, session_id: report.session_id, execution_id: report.payload.execution_id,
    binding_sha256: report.payload.binding_sha256, state: report.payload.state === 'approved' ? 'decision_received' : 'allowed', decision: 'allow_once', decision_payload_sha256: report.payload.decision_payload_sha256,
    expires_at: new Date(Date.now() + 120_000).toISOString(), host_state: report.payload.state, ...(report.payload.execution_outcome ? { execution_outcome: report.payload.execution_outcome } : {}),
  } } })
  return { h, agent, owner, journal, connect, context, approve, ack }
}

test('the host sender retains a newer native result across old or invalid acknowledgements', async t => {
  const h = await fixture(t), context = h.context(), authority = await h.approve(context), sent: ApprovalWireFrame[] = []
  const peer = h.connect(sent)
  const approved = await until(() => sent.find(frame => frame.type === 'approval.result' && frame.payload.state === 'approved')) as ApprovalResultFrame
  h.journal.consume(context.approval_id, context, authority); h.journal.settle(context.approval_id, 'failed')
  await peer.handle(h.ack(approved))
  const settled = await until(() => sent.find(frame => frame.type === 'approval.result' && frame.payload.state === 'settled')) as ApprovalResultFrame
  await assert.rejects(peer.handle({ ...h.ack(settled), payload_sha256: 'b'.repeat(64) }), /acknowledgement mismatch/)
  const contradictory = h.ack(settled)
  contradictory.payload.status.execution_outcome = 'succeeded'
  await assert.rejects(peer.handle(contradictory), /acknowledgement mismatch/)
  await peer.handle(h.ack(settled))
  h.journal.retryReports()
  assert.deepEqual(h.journal.takeReports(), [])
  assert.equal(JSON.stringify(sent).includes('private-report-fixture'), false)
})

test('a replacement sender retries the same durable fact and fences the old connection ack', async t => {
  const h = await fixture(t), context = h.context(), authority = await h.approve(context), first: ApprovalWireFrame[] = []
  h.journal.consume(context.approval_id, context, authority); h.journal.settle(context.approval_id, 'succeeded')
  const old = h.connect(first)
  const original = await until(() => first.find(frame => frame.type === 'approval.result')) as ApprovalResultFrame
  old.close()
  const second: ApprovalWireFrame[] = [], current = h.connect(second)
  const retried = await until(() => second.find(frame => frame.type === 'approval.result')) as ApprovalResultFrame
  assert.deepEqual(retried, original)
  await assert.rejects(old.handle(h.ack(original)), /connection closed/)
  await current.handle(h.ack(retried))
  assert.deepEqual(h.journal.takeReports(), [])
})

test('disconnect cancels a native approval even when catalog publication ignores cancellation', async t => {
  const h = await fixture(t), sent: ApprovalWireFrame[] = []
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const peer = h.connect(sent, async () => { entered(); await new Promise<void>(() => {}) })
  let calls = 0
  h.h.ctx.tools.register(defineContentToolFixture({ name: 'protected', description: 'Disconnected fixture', parameters: {}, async execute() { calls++; return [] } }))
  const execution = h.h.ctx.tools.execute({ agent: h.agent, callId: ToolCallId(randomUUID()), name: 'protected', arguments: {}, signal: new AbortController().signal })
  await started
  peer.close()
  const result = await execution
  assert.equal(result.isError, true)
  assert.equal(calls, 0)
  assert.equal(sent.length, 0)
})
