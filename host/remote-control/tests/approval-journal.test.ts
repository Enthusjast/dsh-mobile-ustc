import test, { type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { CompactSign, calculateJwkThumbprint } from 'jose'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { DatabaseSync } from 'node:sqlite'
import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { canonicalObject } from '../src/canonical.js'
import { ApprovalContext, approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalDecision } from '../src/approval-contract.js'
import type { RegisteredApprovalKey } from '../src/approval-signature.js'
import type { ApprovalAuthorization } from '../src/approval-authorization.js'
import { PersistentApprovalJournal } from '../src/approval-journal.js'
import { parseCommand } from '../src/protocol.js'

async function actor() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const jwk = publicKey.export({ format: 'jwk' })
  const registered: RegisteredApprovalKey = { user_id:randomUUID(), device_id:randomUUID(), key_version:1, approval_key_jkt:await calculateJwkThumbprint(jwk), public_jwk:jwk, active:true }
  return { privateKey, registered }
}

async function fixture(t: TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-approval-journal-'))
  const path = join(root, 'state', 'commands.sqlite'), runtime = randomUUID(), epoch = randomUUID()
  let now = Date.now()
  const signer = await actor()
  let parent = await PersistentCommandJournal.open(path, runtime)
  let ledger = parent.approvals(epoch, () => now)
  t.after(async () => { try { parent.close() } finally { await rm(root, { recursive:true, force:true }) } })
  const context = (): ApprovalContext => ({
    domain:'dsh-mobile-ustc/approval-context/v1', protocol_version:1, host_id:randomUUID(), installation_id:randomUUID(), runtime_id:runtime, runtime_epoch:epoch,
    session_id:randomUUID(), dsh_session_id:'native:private/session', approval_id:randomUUID(), execution_id:randomUUID(), call_id:randomUUID(), tool:'protected',
    arguments:{ text:`PRIVATE_APPROVAL_${randomUUID()}`, nested:{ value:'中文🙂' } }, workspace:{workspace_id:randomUUID(),root_sha256:'a'.repeat(64)}, resources:[],
    nonce:randomBytes(32).toString('base64url'), policy_version:1, required_assurance:{profile:'owner-user-verification/v1',max_auth_age_seconds:300},
    created_at:new Date(now).toISOString(), expires_at:new Date(now+120_000).toISOString(),
  })
  const sign = async (request: ApprovalContext, decision: 'allow_once' | 'reject' = 'allow_once', who = signer) => {
    const claims: ApprovalDecision = { domain:'dsh-mobile-ustc/approval-decision/v1', protocol_version:1,
      host_id:request.host_id, installation_id:request.installation_id, runtime_id:request.runtime_id, runtime_epoch:request.runtime_epoch,
      session_id:request.session_id, approval_id:request.approval_id, execution_id:request.execution_id, binding_sha256:approvalBinding(request).sha256,
      decision, user_id:who.registered.user_id, device_id:who.registered.device_id, key_version:who.registered.key_version,
      policy_version:request.policy_version, nonce:request.nonce, issued_at:new Date(now).toISOString(), expires_at:new Date(now+25_000).toISOString() }
    return new CompactSign(canonicalObject(claims)).setProtectedHeader({alg:'ES256',kid:approvalKeyID(who.registered.device_id,who.registered.key_version),typ:APPROVAL_JWS_TYPE}).sign(who.privateKey)
  }
  const authority = (request: ApprovalContext, decision: ApprovalDecision, who = signer): ApprovalAuthorization => ({
    lease_id:randomUUID(), action:'approval.decide', role:'owner', runtime_id:runtime, runtime_epoch:request.runtime_epoch, session_id:request.session_id,
    approval_id:request.approval_id, execution_id:request.execution_id, binding_sha256:decision.binding_sha256, policy_version:request.policy_version,
    user_id:decision.user_id, device_id:decision.device_id, key_version:decision.key_version, approval_key_jkt:who.registered.approval_key_jkt,
    grant_version:1, assurance_profile:request.required_assurance.profile, authenticated_at:new Date(now-1000).toISOString(),
    issued_at:new Date(now).toISOString(), expires_at:new Date(Math.min(now+2000,Date.parse(request.expires_at))).toISOString(),
  })
  return { root,path,runtime,epoch,signer,context,sign,authority, clock:()=>now, advance(ms:number){now+=ms},
    get parent(){return parent}, get ledger(){return ledger},
    async reopen(nextEpoch = randomUUID()) { parent.close(); parent = await PersistentCommandJournal.open(path,runtime); ledger=parent.approvals(nextEpoch,()=>now); return ledger },
  }
}

test('approval decisions persist once; altered proofs do not spend pending state; final consumption is one-use', async t => {
  const h = await fixture(t), context = h.context()
  assert.equal(h.ledger.register(context).state, 'pending')
  const signed = await h.sign(context)
  const bad = signed.split('.'); bad[2] = (bad[2]![0] === 'A' ? 'B' : 'A') + bad[2]!.slice(1)
  let calls = 0
  const authority = (request:ApprovalContext, decision:ApprovalDecision) => { calls++; return h.authority(request,decision) }
  await assert.rejects(h.ledger.decide(context.approval_id,bad.join('.'),h.signer.registered,authority), /invalid signed decision/)
  assert.equal(calls,0)
  assert.equal(h.ledger.get(context.approval_id).status.decision_sha256, undefined)
  const approved = await h.ledger.decide(context.approval_id,signed,h.signer.registered,authority)
  assert.equal(approved.state,'approved')
  assert.deepEqual(await h.ledger.decide(context.approval_id,signed,h.signer.registered,authority),approved)
  // ECDSA's alternate valid scalar must remain the same stored decision.
  const parts=signed.split('.'), signature=Buffer.from(parts[2]!,'base64url')
  const order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')
  const scalar=BigInt('0x'+signature.subarray(32).toString('hex'))
  parts[2]=Buffer.concat([signature.subarray(0,32),Buffer.from((order-scalar).toString(16).padStart(64,'0'),'hex')]).toString('base64url')
  assert.deepEqual(await h.ledger.decide(context.approval_id,parts.join('.'),h.signer.registered,authority),approved)
  await assert.rejects(h.ledger.decide(context.approval_id,await h.sign(context,'reject'),h.signer.registered,authority), /approval.conflict/)
  assert.equal(h.ledger.consume(context.approval_id,context,authority).state,'consumed')
  assert.throws(()=>h.ledger.consume(context.approval_id,context,authority),/approval.stale/)
  assert.equal(h.ledger.settle(context.approval_id,'succeeded').state,'settled')
  assert.equal(h.ledger.settle(context.approval_id,'succeeded').outcome,'succeeded')
  assert.throws(()=>h.ledger.settle(context.approval_id,'failed'),/approval.conflict/)
})

test('durable reports use stable fingerprints and old acknowledgements cannot clear newer native facts', async t => {
  const h=await fixture(t),context=h.context()
  h.ledger.register(context)
  await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
  const [approved]=h.ledger.takeReports()
  assert.equal(approved?.payload.state,'approved')
  assert.deepEqual(h.ledger.takeReports(),[])
  h.ledger.retryReports()
  assert.deepEqual(h.ledger.takeReports(),[approved])
  h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d))
  assert.equal(h.ledger.acknowledgeReport(context.approval_id,approved!.payload_sha256),false)
  const [consumed]=h.ledger.takeReports()
  assert.equal(consumed?.payload.state,'consumed')
  assert.notEqual(consumed!.request_id,approved!.request_id)
  h.ledger.settle(context.approval_id,'failed')
  assert.equal(h.ledger.acknowledgeReport(context.approval_id,consumed!.payload_sha256),false)
  const [settled]=h.ledger.takeReports()
  assert.equal(settled?.payload.execution_outcome,'failed')
  assert.equal(h.ledger.acknowledgeReport(context.approval_id,settled!.payload_sha256),true)
  assert.equal(h.ledger.acknowledgeReport(context.approval_id,settled!.payload_sha256),true)
  assert.deepEqual(h.ledger.takeReports(),[])
  await h.reopen()
  assert.deepEqual(h.ledger.takeReports(),[])
  assert.throws(()=>h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.stale/)
})

test('registration acknowledgements only enable factual reporting, including cancellation racing the ack', async t => {
  const h=await fixture(t),context=h.context()
  h.ledger.register(context)
  h.ledger.invalidate(context.approval_id,'cancelled')
  assert.deepEqual(h.ledger.takeReports(),[])
  const remote={approval_id:context.approval_id,runtime_id:h.runtime,runtime_epoch:context.runtime_epoch,session_id:context.session_id,execution_id:context.execution_id,
    binding_sha256:approvalBinding(context).sha256,state:'pending',expires_at:context.expires_at}
  assert.throws(()=>h.ledger.confirmRegistration({...remote,binding_sha256:'b'.repeat(64)}),/approval.conflict/)
  h.ledger.confirmRegistration(remote)
  h.ledger.confirmRegistration(remote)
  const [report]=h.ledger.takeReports()
  assert.equal(report?.payload.state,'cancelled')
  assert.equal(report?.payload.decision_payload_sha256,undefined)
  assert.equal(JSON.stringify(report).includes((context.arguments as {text:string}).text),false)
  assert.equal(JSON.stringify(report).includes(context.nonce),false)
  assert.throws(()=>h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.stale/)
})

test('unacknowledged final results survive restart while consumed work recovers only as unknown', async t => {
  const h=await fixture(t),one=h.context(),two=h.context()
  for(const context of [one,two]) {
    h.ledger.register(context)
    await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
    h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d))
  }
  h.ledger.settle(one.approval_id,'succeeded')
  const before=h.ledger.takeReports()
  const final=before.find(report=>report.payload.approval_id===one.approval_id)!
  await h.reopen()
  h.ledger.retryReports()
  const recovered=h.ledger.takeReports()
  assert.deepEqual(recovered.find(report=>report.payload.approval_id===one.approval_id),final)
  assert.equal(recovered.find(report=>report.payload.approval_id===two.approval_id)?.payload.state,'outcome_unknown')
  for(const report of recovered)assert.equal(report.runtime_epoch,one.runtime_epoch)
  for(const context of [one,two])assert.throws(()=>h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.stale/)
})

test('bounded report reservations back off per approval without starving other results', async t => {
  const h=await fixture(t),contexts=[h.context(),h.context()]
  for(const context of contexts) {
    h.ledger.register(context)
    h.ledger.confirmRegistration({approval_id:context.approval_id,runtime_id:h.runtime,runtime_epoch:context.runtime_epoch,session_id:context.session_id,execution_id:context.execution_id,binding_sha256:approvalBinding(context).sha256,state:'pending',expires_at:context.expires_at})
    h.ledger.invalidate(context.approval_id)
  }
  const [one]=h.ledger.takeReports(1,1000),[two]=h.ledger.takeReports(1,1000)
  assert.notEqual(one!.payload.approval_id,two!.payload.approval_id)
  assert.deepEqual(h.ledger.takeReports(1,1000),[])
  h.advance(1000)
  assert.equal(h.ledger.takeReports(2,1000).length,2)
  assert.throws(()=>h.ledger.takeReports(65),/approval.invalid_report/)
  assert.throws(()=>h.ledger.takeReports(1,60_001),/approval.invalid_report/)
})

test('schema-two journals migrate encrypted native results into the durable report queue', async t => {
  const h=await fixture(t),context=h.context()
  h.ledger.register(context)
  await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
  h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d))
  h.ledger.settle(context.approval_id,'succeeded')
  h.parent.close()
  const previous=new DatabaseSync(h.path)
  previous.exec(`DROP INDEX approval_records_reports; ALTER TABLE approval_records DROP COLUMN report_due_at;
    ALTER TABLE approval_records DROP COLUMN report_pending; ALTER TABLE approval_records DROP COLUMN remote_registered; PRAGMA user_version=2;`)
  previous.close()
  await h.reopen()
  const [report]=h.ledger.takeReports()
  assert.equal(report?.payload.state,'settled')
  assert.equal(report?.payload.execution_outcome,'succeeded')
  assert.deepEqual(h.ledger.get(context.approval_id).context,context)
})

test('failed report reservations retain the native fact and an ignored ack never clears it', async t => {
  const h=await fixture(t),context=h.context()
  h.ledger.register(context)
  await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
  h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d))
  h.ledger.settle(context.approval_id,'succeeded')
  const [report]=h.ledger.takeReports()
  const sql=new DatabaseSync(h.path)
  sql.exec(`CREATE TRIGGER ignore_ack BEFORE UPDATE ON approval_records WHEN NEW.report_pending=0 BEGIN SELECT RAISE(IGNORE); END;`)
  assert.equal(h.ledger.acknowledgeReport(context.approval_id,report!.payload_sha256),false)
  sql.exec('DROP TRIGGER ignore_ack;')
  h.ledger.retryReports()
  sql.exec(`CREATE TRIGGER fail_report BEFORE UPDATE ON approval_records WHEN NEW.report_due_at>OLD.report_due_at BEGIN SELECT RAISE(ABORT,'fixture unavailable'); END;`)
  assert.throws(()=>h.ledger.takeReports(),/approval.storage_unavailable/)
  assert.equal(sql.prepare('SELECT state,report_pending FROM approval_records').get()?.state,'settled')
  assert.equal(sql.prepare('SELECT report_pending FROM approval_records').get()?.report_pending,1)
  sql.exec('DROP TRIGGER fail_report;');sql.close()
  await h.reopen()
  const [recovered]=h.ledger.takeReports()
  assert.deepEqual(recovered,report)
})

test('competing owners can commit only one decision and cannot overwrite it with a different actor or choice', async t => {
  const h=await fixture(t), context=h.context(), other=await actor()
  h.ledger.register(context)
  const one=await h.sign(context), two=await h.sign(context,'allow_once',other)
  const results=await Promise.allSettled([
    h.ledger.decide(context.approval_id,one,h.signer.registered,(c,d)=>h.authority(c,d)),
    h.ledger.decide(context.approval_id,two,other.registered,(c,d)=>h.authority(c,d,other)),
  ])
  assert.equal(results.filter(result=>result.status==='fulfilled').length,1)
  const rejected=results.find(result=>result.status==='rejected')!
  assert.match(String((rejected as PromiseRejectedResult).reason),/approval.conflict/)
  const winner=results[0]!.status==='fulfilled'?h.signer:other
  assert.equal(h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d,winner)).state,'consumed')
})

test('execution IDs and nonce hashes cannot be reused and request bodies never enter SQLite as plaintext', async t => {
  const h=await fixture(t), context=h.context()
  h.ledger.register(context)
  assert.throws(()=>h.ledger.register({...h.context(),nonce:context.nonce}),/approval.conflict/)
  assert.throws(()=>h.ledger.register({...h.context(),execution_id:context.execution_id}),/approval.conflict/)
  assert.throws(()=>h.ledger.register({...context,tool:'another-tool'}),/approval.conflict/)
  const signed=await h.sign(context)
  await h.ledger.decide(context.approval_id,signed,h.signer.registered,(c,d)=>h.authority(c,d))
  const files=await Promise.all([h.path,`${h.path}-wal`,`${h.path}-shm`].map(path=>readFile(path).catch(()=>Buffer.alloc(0))))
  const stored=Buffer.concat(files)
  for(const secret of [(context.arguments as {text:string}).text,context.nonce,context.dsh_session_id,context.call_id,signed]) assert.equal(stored.includes(Buffer.from(secret)),false)
  assert.deepEqual(h.ledger.get(context.approval_id).context,context)
})

test('guard consumption rechecks context, owner action, key, grant version, assurance and authorization freshness', async t => {
  for(const variant of ['body','missing','grant','key','role','action','profile','assurance-age','expired-lease','future-lease','oversized-lease','promise','throw','elapsed-decision'] as const) await t.test(variant,async t=>{
    const h=await fixture(t), context=h.context()
    h.ledger.register(context)
    await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
    const actual=structuredClone(context)
    if(variant==='body') (actual.arguments as {text:string}).text+=' changed'
    const authority=(c:ApprovalContext,d:ApprovalDecision):unknown=>{
      if(variant==='elapsed-decision')h.advance(26000)
      const lease=h.authority(c,d)
      switch(variant){
        case 'missing':return undefined
        case 'grant':return {...lease,grant_version:2}
        case 'key':return {...lease,approval_key_jkt:'A'.repeat(43)}
        case 'role':return {...lease,role:'operator'}
        case 'action':return {...lease,action:'question.answer'}
        case 'profile':return {...lease,assurance_profile:'unmapped-profile'}
        case 'assurance-age':return {...lease,authenticated_at:new Date(h.clock()-301000).toISOString()}
        case 'expired-lease':return {...lease,expires_at:new Date(h.clock()).toISOString()}
        case 'future-lease':return {...lease,issued_at:new Date(h.clock()+1).toISOString()}
        case 'oversized-lease':return {...lease,expires_at:new Date(h.clock()+3001).toISOString()}
        case 'promise':return Promise.resolve(lease)
        case 'throw':throw new Error('authority unavailable')
        default:return lease
      }
    }
    assert.throws(()=>h.ledger.consume(context.approval_id,actual,authority),variant==='elapsed-decision'?/approval.stale/:/approval.authorization_unavailable/)
    assert.equal(h.ledger.get(context.approval_id).status.state,variant==='elapsed-decision'?'expired':'invalidated')
    assert.throws(()=>h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.stale/)
  })
})

test('denials, elapsed decisions, async authorization races and clock rollback cannot produce a permit', async t => {
  const h=await fixture(t), denied=h.context()
  h.ledger.register(denied)
  assert.equal((await h.ledger.decide(denied.approval_id,await h.sign(denied,'reject'),h.signer.registered,(c,d)=>h.authority(c,d))).state,'denied')
  assert.throws(()=>h.ledger.consume(denied.approval_id,denied,(c,d)=>h.authority(c,d)),/approval.stale/)
  const pending=h.context();h.ledger.register(pending)
  const proof=await h.sign(pending)
  await assert.rejects(h.ledger.decide(pending.approval_id,proof,h.signer.registered,(c,d)=>{h.advance(26000);return h.authority(c,d)}),/approval.stale/)
  assert.equal(h.ledger.get(pending.approval_id).status.state,'pending')
  await h.ledger.decide(pending.approval_id,await h.sign(pending),h.signer.registered,(c,d)=>h.authority(c,d))
  h.advance(26000)
  assert.throws(()=>h.ledger.consume(pending.approval_id,pending,(c,d)=>h.authority(c,d)),/approval.stale/)
  assert.equal(h.ledger.get(pending.approval_id).status.state,'expired')
  const expires=h.context();h.ledger.register(expires);h.advance(120000)
  assert.equal(h.ledger.get(expires.approval_id).status.state,'expired')
  h.advance(-1)
  assert.throws(()=>h.ledger.get(expires.approval_id),/approval.clock_unavailable/)
  h.advance(1)
})

test('a new journal owner fences an old handle and recovery never reactivates approved or consumed work', async t => {
  const h=await fixture(t), pending=h.context(), approved=h.context(), consumed=h.context()
  for(const request of [pending,approved,consumed]) h.ledger.register(request)
  for(const request of [approved,consumed]) await h.ledger.decide(request.approval_id,await h.sign(request),h.signer.registered,(c,d)=>h.authority(c,d))
  h.ledger.consume(consumed.approval_id,consumed,(c,d)=>h.authority(c,d))
  const old=h.ledger, second=await PersistentCommandJournal.open(h.path,h.runtime)
  t.after(()=>second.close())
  const current=second.approvals(h.epoch,h.clock)
  assert.throws(()=>old.consume(approved.approval_id,approved,(c,d)=>h.authority(c,d)),/approval.stale/)
  assert.equal(current.get(pending.approval_id).status.state,'invalidated')
  assert.equal(current.get(approved.approval_id).status.state,'invalidated')
  assert.equal(current.get(consumed.approval_id).status.state,'outcome_unknown')
  h.parent.close()
  assert.equal(current.get(approved.approval_id).status.state,'invalidated','closing a stale handle changed the new owner')
})

test('actual process exit after committed guard consumption recovers as unknown without restoring callbacks', async t => {
  const h=await fixture(t), requests=[h.context(),h.context(),h.context()]
  h.parent.close()
  const journalModule=pathToFileURL(resolve('host/remote-control/src/command-journal.ts')).href
  const canonicalModule=pathToFileURL(resolve('host/remote-control/src/canonical.ts')).href
  const contractModule=pathToFileURL(resolve('host/remote-control/src/approval-contract.ts')).href
  const script=`
    import {readFileSync} from 'node:fs'; import {createPrivateKey} from 'node:crypto'; import {CompactSign} from 'jose';
    import {PersistentCommandJournal} from ${JSON.stringify(journalModule)};
    import {canonicalObject} from ${JSON.stringify(canonicalModule)}; import {approvalBinding,approvalKeyID,APPROVAL_JWS_TYPE} from ${JSON.stringify(contractModule)};
    const input=JSON.parse(readFileSync(0,'utf8')),parent=await PersistentCommandJournal.open(input.path,input.runtime),ledger=parent.approvals(input.epoch,()=>input.now);
    const key=createPrivateKey({format:'jwk',key:input.privateJWK});
    const authority=(c,d)=>({lease_id:input.leaseID,action:'approval.decide',role:'owner',runtime_id:c.runtime_id,runtime_epoch:c.runtime_epoch,session_id:c.session_id,
      approval_id:c.approval_id,execution_id:c.execution_id,binding_sha256:d.binding_sha256,policy_version:c.policy_version,user_id:d.user_id,device_id:d.device_id,key_version:d.key_version,
      approval_key_jkt:input.registered.approval_key_jkt,grant_version:1,assurance_profile:c.required_assurance.profile,authenticated_at:new Date(input.now).toISOString(),issued_at:new Date(input.now).toISOString(),expires_at:new Date(input.now+2000).toISOString()});
    for(let index=0;index<input.contexts.length;index++){
      const c=input.contexts[index];ledger.register(c);if(index===0)continue;
      const identity=Object.fromEntries(['host_id','installation_id','runtime_id','runtime_epoch','session_id','approval_id','execution_id'].map(k=>[k,c[k]]));
      const d={domain:'dsh-mobile-ustc/approval-decision/v1',protocol_version:1,...identity,binding_sha256:approvalBinding(c).sha256,decision:'allow_once',user_id:input.registered.user_id,device_id:input.registered.device_id,key_version:1,policy_version:1,nonce:c.nonce,issued_at:new Date(input.now).toISOString(),expires_at:new Date(input.now+25000).toISOString()};
      const compact=await new CompactSign(canonicalObject(d)).setProtectedHeader({alg:'ES256',kid:approvalKeyID(d.device_id,1),typ:APPROVAL_JWS_TYPE}).sign(key);
      await ledger.decide(c.approval_id,compact,input.registered,authority);if(index===2)ledger.consume(c.approval_id,c,authority);
    }
    process.exit(0);
  `
  execFileSync(process.execPath,['--import','tsx','--input-type=module','--eval',script],{input:JSON.stringify({path:h.path,runtime:h.runtime,epoch:h.epoch,now:h.clock(),contexts:requests,registered:h.signer.registered,privateJWK:h.signer.privateKey.export({format:'jwk'}),leaseID:randomUUID()}),stdio:['pipe','pipe','pipe'],timeout:10000})
  const recovered=await h.reopen()
  assert.deepEqual(requests.map(request=>recovered.get(request.approval_id).status.state),['invalidated','invalidated','outcome_unknown'])
  for(const request of requests) assert.throws(()=>recovered.consume(request.approval_id,request,(c,d)=>h.authority(c,d)),/approval.stale/)
})

test('SQLite write failure or ignored CAS cannot grant execution and a storage error poisons further consumption', async t => {
  for(const mode of ['abort','ignore'] as const) await t.test(mode,async t=>{
    const h=await fixture(t), context=h.context();h.ledger.register(context)
    await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
    const database=new DatabaseSync(h.path);t.after(()=>database.close())
    database.exec(`CREATE TRIGGER reject_consume BEFORE UPDATE ON approval_records WHEN NEW.state='consumed'
      BEGIN SELECT RAISE(${mode==='abort'?"ABORT,'injected failure'":"IGNORE"}); END;`)
    assert.throws(()=>h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),mode==='abort'?/approval.storage_unavailable/:/approval.stale/)
    assert.equal(database.prepare('SELECT state FROM approval_records WHERE approval_id=?').get(context.approval_id)?.state,'approved')
    database.exec('DROP TRIGGER reject_consume')
    if(mode==='abort') assert.throws(()=>h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.storage_unavailable/)
    else assert.equal(h.ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)).state,'consumed')
  })
})

test('version-one command journals migrate without losing their encrypted receipts', async t => {
  const h=await fixture(t), request=parseCommand({v:0,type:'session.create',request_id:randomUUID(),runtime_epoch:h.epoch,payload:{workspace:'fixture',preset:'fixture'}})
  const owner={userId:'local',deviceId:'local'}
  h.parent.admit(request,owner);h.parent.start(request.request_id,owner);h.parent.complete(request.request_id,owner,'settled',{session_id:randomUUID()});h.parent.close()
  const previous=new DatabaseSync(h.path)
  previous.exec('DROP TABLE approval_records; DROP TABLE approval_runs; PRAGMA user_version=1;');previous.close()
  const parent=await PersistentCommandJournal.open(h.path,h.runtime);t.after(()=>parent.close())
  assert.equal(parent.admit(request,owner).state,'settled')
  const database=new DatabaseSync(h.path);assert.equal(database.prepare('PRAGMA user_version').get()?.user_version,3);database.close()
})

test('missing key-check metadata cannot reseed a journal containing approvals', async t => {
  const h=await fixture(t), context=h.context();h.ledger.register(context);h.parent.close()
  const database=new DatabaseSync(h.path);database.exec('DELETE FROM journal_meta');database.close()
  await writeFile(`${h.path}.key`,randomBytes(32),{mode:0o600})
  await assert.rejects(PersistentCommandJournal.open(h.path,h.runtime),/journal.integrity_failed/)
})

test('ciphertexts cannot move between approvals or between command and approval purposes', async t => {
  for(const purpose of ['context','decision','command'] as const) await t.test(purpose,async t=>{
    const h=await fixture(t), one=h.context(), two=h.context()
    for(const context of [one,two]){h.ledger.register(context);await h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))}
    const database=new DatabaseSync(h.path)
    try{
      let blob:Record<string,unknown>
      if(purpose==='command'){
        const command=parseCommand({v:0,type:'session.create',request_id:randomUUID(),runtime_epoch:h.epoch,payload:{workspace:'fixture',preset:'fixture'}})
        h.parent.admit(command,{userId:'local',deviceId:'local'})
        blob=database.prepare('SELECT payload_nonce nonce,payload_ciphertext ciphertext,payload_tag tag FROM commands WHERE request_id=?').get(command.request_id)!
      }else blob=database.prepare(`SELECT ${purpose}_nonce nonce,${purpose}_ciphertext ciphertext,${purpose}_tag tag FROM approval_records WHERE approval_id=?`).get(one.approval_id)!
      const target=purpose==='decision'?'decision':'context'
      database.prepare(`UPDATE approval_records SET ${target}_nonce=?,${target}_ciphertext=?,${target}_tag=? WHERE approval_id=?`).run(blob.nonce as Uint8Array,blob.ciphertext as Uint8Array,blob.tag as Uint8Array,two.approval_id)
      assert.throws(()=>h.ledger.consume(two.approval_id,two,(c,d)=>h.authority(c,d)),/approval.storage_unavailable/)
      assert.equal(database.prepare('SELECT state FROM approval_records WHERE approval_id=?').get(two.approval_id)?.state,'approved')
    }finally{database.close()}
  })
})

test('closing or superseding an owner during asynchronous verification cannot commit a late approval', async t => {
  for(const mode of ['close','supersede'] as const) await t.test(mode,async t=>{
    const h=await fixture(t), context=h.context();h.ledger.register(context)
    const compact=await h.sign(context)
    let started!:()=>void, release!:(value:unknown)=>void
    const entered=new Promise<void>(resolve=>{started=resolve}), held=new Promise<unknown>(resolve=>{release=resolve})
    let claims:ApprovalDecision|undefined
    const pending=h.ledger.decide(context.approval_id,compact,h.signer.registered,(_context,decision)=>{claims=decision;started();return held})
    void pending.catch(()=>{})
    await entered
    let current:PersistentCommandJournal|undefined
    try{
      if(mode==='close')h.parent.close()
      else {current=await PersistentCommandJournal.open(h.path,h.runtime);current.approvals(h.epoch,h.clock)}
      release(h.authority(context,claims!))
      await assert.rejects(pending,mode==='close'?/approval.storage_unavailable/:/approval.stale/)
      const reader=current?.approvals(h.epoch,h.clock)??await h.reopen()
      assert.equal(reader.get(context.approval_id).status.state,'invalidated')
      assert.equal(reader.get(context.approval_id).status.decision_sha256,undefined)
    }finally{current?.close()}
  })
})

test('unavailable admission authority does not spend the nonce and provider error bodies stay private', async t => {
  const h=await fixture(t), context=h.context();h.ledger.register(context)
  const compact=await h.sign(context)
  await assert.rejects(h.ledger.decide(context.approval_id,compact,h.signer.registered,()=>undefined),/approval.authorization_unavailable/)
  await assert.rejects(h.ledger.decide(context.approval_id,compact,h.signer.registered,()=>{throw new Error('private authority failure body')}),error=>String(error)==='Error: approval.authorization_unavailable')
  assert.equal(h.ledger.get(context.approval_id).status.state,'pending')
  assert.equal(h.ledger.get(context.approval_id).status.decision_sha256,undefined)
  assert.equal((await h.ledger.decide(context.approval_id,compact,h.signer.registered,(c,d)=>h.authority(c,d))).state,'approved')
})

test('close and bounded admission timeouts do not wait for an authority that ignores cancellation', async t => {
  for(const mode of ['close','timeout'] as const) await t.test(mode,async t=>{
    const h=await fixture(t), context=h.context();h.ledger.register(context)
    let started!:()=>void, release!:(value:unknown)=>void, claims:ApprovalDecision|undefined, signal:AbortSignal|undefined
    const entered=new Promise<void>(resolve=>{started=resolve}), held=new Promise<unknown>(resolve=>{release=resolve})
    const pending=h.ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(_c,d,s)=>{claims=d;signal=s;started();return held})
    void pending.catch(()=>{})
    await entered
    if(mode==='close')h.parent.close()
    await assert.rejects(pending,mode==='close'?/approval.storage_unavailable/:/approval.authorization_unavailable/)
    assert.equal(signal?.aborted,true)
    release(h.authority(context,claims!))
    await new Promise(resolve=>setTimeout(resolve,0))
    if(mode==='close')await h.reopen()
    const status=h.ledger.get(context.approval_id).status
    assert.equal(status.state,mode==='close'?'invalidated':'pending')
    assert.equal(status.decision_sha256,undefined,'late provider resolution accepted an expired operation')
  })
})

test('in-flight decision verification is bounded even for repeated proofs of one pending request', async t => {
  const h=await fixture(t), context=h.context();h.ledger.register(context)
  const compact=await h.sign(context)
  const waiting=Array.from({length:64},()=>h.ledger.decide(context.approval_id,compact,h.signer.registered,()=>new Promise(()=>{})))
  const settled=Promise.allSettled(waiting)
  await assert.rejects(h.ledger.decide(context.approval_id,compact,h.signer.registered,(c,d)=>h.authority(c,d)),/rate.limited/)
  h.parent.close()
  assert.ok((await settled).every(result=>result.status==='rejected'))
})

test('a lease that expires while SQLite writes the consumption marker cannot grant late execution', async t => {
  const h=await fixture(t), key=await readFile(`${h.path}.key`), database=new DatabaseSync(h.path)
  database.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL')
  const ledger=PersistentApprovalJournal.attach(database,key,h.runtime,h.epoch,h.clock)
  try{
    const context=h.context();ledger.register(context)
    await ledger.decide(context.approval_id,await h.sign(context),h.signer.registered,(c,d)=>h.authority(c,d))
    database.function('approval_write_delay',()=>{h.advance(5000);return 1})
    database.exec("CREATE TRIGGER elapsed_commit AFTER UPDATE ON approval_records WHEN NEW.state='consumed' BEGIN SELECT approval_write_delay(); END;")
    assert.throws(()=>ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.authorization_unavailable/)
    assert.equal(ledger.get(context.approval_id).status.state,'outcome_unknown')
    assert.throws(()=>ledger.consume(context.approval_id,context,(c,d)=>h.authority(c,d)),/approval.stale/)
  }finally{database.exec('DROP TRIGGER IF EXISTS elapsed_commit');ledger.close();database.close();key.fill(0)}
})
