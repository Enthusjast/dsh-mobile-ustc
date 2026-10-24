import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { access, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { CompactSign, calculateJwkThumbprint } from 'jose'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import { host } from './harness.js'
import { DshClient, mobileSessionId } from '../src/dsh-client.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalContext, type ApprovalDecision } from '../src/approval-contract.js'
import { canonicalObject } from '../src/canonical.js'

test('real DSH final guards require committed one-use approval and preserve every native denial', async t => {
  for(const mode of ['allow','reject','invalid-signature','revoked','changed-resource','write-failure','automatic-answer','pre-allow','guard-before','guard-after','cancel'] as const) await t.test(mode,async()=>{
    const h=await host({probe:false})
    const path=join(h.directory,'approval-state','commands.sqlite'), epoch=randomUUID()
    const parent=await PersistentCommandJournal.open(path,h.runtimeId), ledger=parent.approvals(epoch)
    const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'})
    const publicJWK=publicKey.export({format:'jwk'}), jkt=await calculateJwkThumbprint(publicJWK)
    const registered={user_id:randomUUID(),device_id:randomUUID(),key_version:1,approval_key_jkt:jkt,public_jwk:publicJWK,active:true}
    const client=new DshClient(h.ctx,h.runtimeId,[{id:'fixture',cwd:h.cwd}],['fixture'])
    const created=await client.create('fixture','fixture')
    const agent=h.ctx.agents.get(await client.resolve(created.session_id,new AbortController().signal))!
    agent.session.append('turn/start',{turn:1})
    const source=join(h.cwd,'reviewed.txt'), sentinel=join(h.cwd,'executed.txt')
    await writeFile(source,'before')
    const contexts=new Map<symbol,ApprovalContext>(), byCall=new Map<string,ApprovalContext>()
    const lifetime=new AbortController()
    let calls=0, signedResponses=0, active=true
    let external:DatabaseSync|undefined
    const resourceHash=()=>createHash('sha256').update(readFileSync(source)).digest('hex')
    const authorize=(context:ApprovalContext,decision:ApprovalDecision)=>{
      const now=Date.now()
      return active?{lease_id:randomUUID(),action:'approval.decide',role:'owner',runtime_id:h.runtimeId,runtime_epoch:epoch,session_id:context.session_id,
        approval_id:context.approval_id,execution_id:context.execution_id,binding_sha256:decision.binding_sha256,policy_version:context.policy_version,
        user_id:decision.user_id,device_id:decision.device_id,key_version:decision.key_version,approval_key_jkt:jkt,grant_version:1,
        assurance_profile:context.required_assurance.profile,authenticated_at:new Date(now-1000).toISOString(),issued_at:new Date(now).toISOString(),expires_at:new Date(now+2000).toISOString()}:undefined
    }
    try {
      h.ctx.tools.register(defineContentToolFixture({name:'protected',description:'Observable signed-approval fixture',parameters:{value:{type:'string',description:'Fixture value'}},
        async execute(){calls++;await writeFile(sentinel,'executed');return [{type:'text',text:'executed'}]}}))
      h.ctx.on('tools/pre-execute',async(exec,next)=>{
        if(exec.name!=='protected')return next()
        const previous=await next()
        if(previous.kind==='deny'||previous.kind==='cancel')return previous
        const now=Date.now()
        const context:ApprovalContext={domain:'dsh-mobile-ustc/approval-context/v1',protocol_version:1,host_id:randomUUID(),installation_id:randomUUID(),runtime_id:h.runtimeId,runtime_epoch:epoch,
          session_id:mobileSessionId(h.runtimeId,agent.id),dsh_session_id:String(agent.id),approval_id:randomUUID(),execution_id:randomUUID(),call_id:String(exec.callId),tool:exec.name,
          arguments:exec.arguments as ApprovalContext['arguments'],workspace:{workspace_id:randomUUID(),root_sha256:createHash('sha256').update(h.cwd).digest('hex')},
          resources:[{kind:'file',resource_id:'reviewed.txt',version_sha256:resourceHash()}],nonce:randomBytes(32).toString('base64url'),policy_version:1,
          required_assurance:{profile:'owner-user-verification/v1',max_auth_age_seconds:300},created_at:new Date(now).toISOString(),expires_at:new Date(now+120000).toISOString()}
        ledger.register(context);contexts.set(exec.token,context);byCall.set(String(exec.callId),context)
        const outcome=await h.ctx.approval.request({agent,toolName:exec.name,callId:exec.callId,signal:exec.signal})
        return outcome==='allowed-once'?{kind:'allow'}:{kind:'deny',reason:'signed fixture approval unavailable'}
      },{prepend:true})
      h.ctx.on('approval/request',async request=>{
        const context=request.callId?byCall.get(String(request.callId)):undefined
        if(!context||request.agent!==agent||request.toolName!==context.tool)return 'unavailable'
        signedResponses++
        const now=Date.now()
        const claims:ApprovalDecision={domain:'dsh-mobile-ustc/approval-decision/v1',protocol_version:1,host_id:context.host_id,installation_id:context.installation_id,runtime_id:h.runtimeId,runtime_epoch:epoch,
          session_id:context.session_id,approval_id:context.approval_id,execution_id:context.execution_id,binding_sha256:approvalBinding(context).sha256,decision:mode==='reject'?'reject':'allow_once',
          user_id:registered.user_id,device_id:registered.device_id,key_version:1,policy_version:1,nonce:context.nonce,issued_at:new Date(now).toISOString(),expires_at:new Date(now+25000).toISOString()}
        let compact=await new CompactSign(canonicalObject(claims)).setProtectedHeader({alg:'ES256',kid:approvalKeyID(registered.device_id,1),typ:APPROVAL_JWS_TYPE}).sign(privateKey)
        if(mode==='invalid-signature'){const parts=compact.split('.');parts[2]=(parts[2]![0]==='A'?'B':'A')+parts[2]!.slice(1);compact=parts.join('.')}
        let status
        try{status=await ledger.decide(context.approval_id,compact,registered,authorize)}catch{return 'rejected'}
        if(mode==='revoked')active=false
        if(mode==='changed-resource')await writeFile(source,'after')
        if(mode==='cancel')lifetime.abort()
        return status.state==='approved'?'allowed-once':'rejected'
      },{prepend:true})
      if(mode==='guard-before')h.ctx.tools.guard(exec=>exec.name==='protected'?'existing policy denied':undefined)
      h.ctx.tools.guard(exec=>{
        if(exec.name!=='protected')return
        const context=contexts.get(exec.token)
        if(!context)return 'no signed pending invocation'
        try {
          ledger.consume(context.approval_id,{...context,arguments:exec.arguments,resources:[{...context.resources[0]!,version_sha256:resourceHash()}]},authorize)
        } catch {return 'signed approval is unavailable'}
      })
      if(mode==='guard-after')h.ctx.tools.guard(exec=>exec.name==='protected'?'later policy denied':undefined)
      if(mode==='automatic-answer')h.ctx.on('approval/request',async()=> 'allowed-once',{prepend:true})
      if(mode==='pre-allow')h.ctx.on('tools/pre-execute',async()=>({kind:'allow'}),{prepend:true})
      h.ctx.on('tools/result',(exec,result)=>{
        const context=contexts.get(exec.token)
        if(!context)return
        try {
          const status=ledger.get(context.approval_id).status
          if(status.state==='consumed')ledger.settle(context.approval_id,result.isError?'failed':'succeeded')
          else if(status.state==='pending'||status.state==='approved')ledger.invalidate(context.approval_id)
        } catch { /* A poisoned journal is closed to all further approval use. */ }
      })
      if(mode==='write-failure'){
        external=new DatabaseSync(path)
        external.exec("CREATE TRIGGER fail_guard BEFORE UPDATE ON approval_records WHEN NEW.state='consumed' BEGIN SELECT RAISE(ABORT,'injected guard failure'); END;")
      }
      const result=await h.ctx.tools.execute({agent,callId:ToolCallId(randomUUID()),name:'protected',arguments:{value:'exact signed invocation'},signal:lifetime.signal})
      assert.equal(calls,mode==='allow'?1:0)
      assert.equal(result.isError,mode!=='allow')
      if(mode==='allow')await access(sentinel)
      else await assert.rejects(access(sentinel),{code:'ENOENT'})
      if(mode==='pre-allow')assert.equal(contexts.size,0)
      else {
        const context=[...contexts.values()][0]!
        if(mode==='write-failure'){
          assert.equal(external!.prepare('SELECT state FROM approval_records').get()?.state,'approved')
          assert.throws(()=>ledger.consume(context.approval_id,context,authorize),/approval.storage_unavailable/)
        }else{
          const status=ledger.get(context.approval_id).status
          assert.equal(status.state,mode==='allow'||mode==='guard-after'?'settled':mode==='reject'?'denied':'invalidated')
          if(mode==='allow'||mode==='guard-after')assert.equal(status.outcome,mode==='allow'?'succeeded':'failed')
          assert.throws(()=>ledger.consume(context.approval_id,context,authorize))
        }
      }
      if(mode==='automatic-answer'||mode==='pre-allow')assert.equal(signedResponses,0)
      assert.equal(h.errors.length,0)
    }finally{lifetime.abort();external?.close();parent.close();await h.close()}
  })
})
