import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { CompactSign, calculateJwkThumbprint } from 'jose'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import { setApprovalPolicy } from '@deepseek-ai/dsh-user-approval'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { SignedApprovals, type NativeApprovalSession } from '../src/signed-approvals.js'
import { approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalContext, type ApprovalDecision } from '../src/approval-contract.js'
import { canonicalObject } from '../src/canonical.js'
import { APPROVAL_AUTHORIZATION_DOMAIN, APPROVAL_AUTHORIZATION_AUDIENCE, APPROVAL_AUTHORIZATION_JWS_TYPE } from '../src/approval-lease.js'

test('normal native approval owner requires both phone proof and native policy at the actual body boundary', async t => {
  for (const mode of ['allow', 'reject', 'invalid-proof', 'no-phone', 'auto-allow', 'auto-with-phone', 'pre-allow', 'guard-before', 'guard-after',
    'changed-file', 'changed-directory', 'late-directory', 'call-swap', 'agent-swap', 'token-swap', 'expired-around', 'long-body', 'native-never', 'disconnect', 'disconnect-running', 'dispose-around'] as const) await t.test(mode, async () => {
    const h = await host({ probe: false })
    const workspaceID = randomUUID(), epoch = randomUUID(), hostID = randomUUID(), installationID = randomUUID(), connectionID = randomUUID()
    const parent = await PersistentCommandJournal.open(join(h.directory, 'signed', 'commands.sqlite'), h.runtimeId), journal = parent.approvals(epoch)
    const authorityKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), approvalKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicAuthority = authorityKeys.publicKey.export({ format: 'jwk' }) as { kty: 'EC'; crv: 'P-256'; x: string; y: string }
    const publicPhone = approvalKeys.publicKey.export({ format: 'jwk' })
    const authority = { issuer: 'https://remote.example.edu', key_id: 'dsh-approval-authority/native-owner', public_jwk: publicAuthority,
      key_jkt: await calculateJwkThumbprint(publicAuthority), active: true, valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString() }
    const workspaces = [{ id: 'fixture', cwd: h.cwd, remoteId: workspaceID }]
    const client = new DshClient(h.ctx, h.runtimeId, workspaces, ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const agent = h.ctx.agents.get(await client.resolve(created.session_id, new AbortController().signal))!
    agent.session.append('turn/start', { turn: 1 })
    const other = mode === 'agent-swap' ? await client.create('fixture','fixture') : undefined
    const otherAgent = other ? h.ctx.agents.get(await client.resolve(other.session_id,new AbortController().signal))! : undefined
    const file = join(h.cwd, 'reviewed.txt'), subdir = join(h.cwd, 'subdirectory')
    await writeFile(file, 'before'); await mkdir(subdir)
    let calls = 0, published = 0, around = false, captured: ApprovalContext | undefined, session!: NativeApprovalSession
    const errors: unknown[] = []
    h.ctx.tools.register(defineContentToolFixture({ name: 'protected', description: 'Signed owner fixture', parameters: { value: { type: 'string' } }, async execute(_args,execution) {
      calls++
      if (mode === 'long-body') { await new Promise(resolve=>setTimeout(resolve,400)); assert.equal(execution.signal.aborted,false) }
      if (mode === 'disconnect-running') session.close()
      return [{ type: 'text', text: 'executed' }]
    } }))
    if (mode === 'guard-before') h.ctx.tools.guard(exec => exec.name === 'protected' ? 'earlier native deny' : undefined)
    const owner = new SignedApprovals(h.ctx, h.runtimeId, epoch, journal, workspaces, value => value === agent,
      ['no-phone', 'auto-allow'].includes(mode) ? 120 : 3000, {
        hostId: hostID, installationId: installationID, policyVersion: 7, requiredAssurance: { profile: 'school/step-up', max_auth_age_seconds: 60 }, authorities: [authority],
        requiresApproval: execution => execution.name === 'protected', resourceFacts: () => [{ kind: 'file', resource_id: 'reviewed.txt', version_sha256: createHash('sha256').update(readFileSync(file)).digest('hex') }],
      })
    if (mode === 'guard-after') h.ctx.tools.guard(exec => exec.name === 'protected' ? 'later native deny' : undefined)
    if (mode === 'auto-allow' || mode === 'auto-with-phone') h.ctx.on('approval/request', async () => 'allowed-once', { prepend: true })
    if (mode === 'pre-allow') h.ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }), { prepend: true })
    if (mode === 'native-never') setApprovalPolicy(agent.session, 'never')
    h.ctx.on('tools/execute', async (exec, next) => {
      if (exec.name !== 'protected') return next()
      around = true
      if (mode === 'late-directory') await h.ctx.workingDirectory.set(agent, subdir)
      if (mode === 'expired-around') { await new Promise(resolve => setTimeout(resolve, 400)); exec.signal = new AbortController().signal }
      if (mode === 'dispose-around') owner.close()
      if (mode === 'call-swap') (exec as unknown as { callId: string }).callId = randomUUID()
      if (mode === 'agent-swap') (exec as unknown as { agent: typeof agent }).agent = otherAgent!
      if (mode === 'token-swap') (exec as unknown as { token: symbol }).token = Symbol('other execution')
      return next()
    }, { prepend: true })
    session = owner.attach({ ...owner.identity, connection_id: connectionID }, async context => {
      captured = context; published++
      journal.confirmRegistration({ approval_id: context.approval_id, runtime_id: h.runtimeId, runtime_epoch: epoch, session_id: context.session_id,
        execution_id: context.execution_id, binding_sha256: approvalBinding(context).sha256, state: 'pending', expires_at: context.expires_at })
      if (mode === 'no-phone' || mode === 'auto-allow' || mode === 'native-never') return
      const now = Date.now(), decision: ApprovalDecision = { domain: 'dsh-mobile-ustc/approval-decision/v1', protocol_version: 1,
        host_id: hostID, installation_id: installationID, runtime_id: h.runtimeId, runtime_epoch: epoch, session_id: context.session_id, approval_id: context.approval_id,
        execution_id: context.execution_id, binding_sha256: approvalBinding(context).sha256, decision: mode === 'reject' ? 'reject' : 'allow_once', user_id: randomUUID(),
        device_id: randomUUID(), key_version: 1, policy_version: 7, nonce: context.nonce, issued_at: new Date(now).toISOString(), expires_at: context.expires_at }
      const decisionBytes = canonicalObject(decision)
      let phoneProof = await new CompactSign(decisionBytes).setProtectedHeader({ alg: 'ES256', kid: approvalKeyID(decision.device_id, 1), typ: APPROVAL_JWS_TYPE }).sign(approvalKeys.privateKey)
      const lease = { domain: APPROVAL_AUTHORIZATION_DOMAIN, protocol_version: 1, issuer: authority.issuer, audience: APPROVAL_AUTHORIZATION_AUDIENCE,
        host_id: hostID, installation_id: installationID, runtime_id: h.runtimeId, runtime_epoch: epoch, session_id: context.session_id, approval_id: context.approval_id,
        execution_id: context.execution_id, connection_id: connectionID, lease_id: randomUUID(), action: 'approval.decide', role: 'owner', binding_sha256: decision.binding_sha256,
        decision_payload_sha256: createHash('sha256').update(decisionBytes).digest('hex'), policy_version: 7, user_id: decision.user_id, device_id: decision.device_id, key_version: 1,
        approval_key_jkt: await calculateJwkThumbprint(publicPhone), approval_public_jwk: publicPhone, grant_version: 1, assurance_profile: 'school/step-up',
        authenticated_at: new Date(now - 1000).toISOString(), issued_at: new Date(now).toISOString(), expires_at: new Date(Math.min(Date.parse(context.expires_at), now + (mode === 'expired-around' || mode === 'long-body' ? 300 : 2000))).toISOString() }
      const proof = await new CompactSign(canonicalObject(lease)).setProtectedHeader({ alg: 'ES256', kid: authority.key_id, typ: APPROVAL_AUTHORIZATION_JWS_TYPE }).sign(authorityKeys.privateKey)
      if (mode === 'changed-file') await writeFile(file, 'after')
      if (mode === 'changed-directory') await h.ctx.workingDirectory.set(agent, subdir)
      if (mode === 'disconnect') { session.close(); return }
      if (mode === 'invalid-proof') { const parts = phoneProof.split('.'); parts[2] = (parts[2]![0] === 'A' ? 'B' : 'A') + parts[2]!.slice(1); phoneProof = parts.join('.') }
      try { await session.decide(context.approval_id, phoneProof, proof) }
      catch (error) { errors.push(error); if (mode === 'invalid-proof') { assert.equal(journal.get(context.approval_id).status.decision_sha256, undefined); session.close() } }
    })
    try {
      const result = await h.ctx.tools.execute({ agent, callId: ToolCallId(randomUUID()), name: 'protected', arguments: { value: 'exact invocation' }, signal: new AbortController().signal })
      const executed = ['allow', 'auto-with-phone', 'disconnect-running','long-body'].includes(mode)
      assert.equal(calls, executed ? 1 : 0, mode)
      assert.equal(result.isError, !executed, mode)
      if (mode === 'pre-allow') assert.equal(published, 0)
      if (mode === 'expired-around') assert.equal(around, true)
      if (captured) {
        const status = journal.get(captured.approval_id).status
        if (executed) { assert.equal(status.state, 'settled'); assert.equal(status.outcome, 'succeeded') }
        else if (mode === 'reject') assert.equal(status.state, 'denied')
        else assert.ok(['invalidated', 'cancelled', 'expired'].includes(status.state), status.state)
        const reports = journal.takeReports()
        assert.ok(reports.length > 0)
        assert.equal(JSON.stringify(reports).includes('exact invocation'), false)
        assert.throws(() => journal.consume(captured!.approval_id, captured!, () => undefined))
      }
      if (mode !== 'invalid-proof' && mode !== 'disconnect' && mode !== 'native-never') assert.equal(errors.length, 0, String(errors[0]))
      assert.equal(h.errors.length, 0)
    } finally { owner.close(); parent.close(); await h.close() }
  })
})
