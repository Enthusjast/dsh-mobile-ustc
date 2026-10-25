// Test-only normal DSH host. The phone receives no host credential/private key.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { access, mkdir, readFile, writeFile } from 'node:fs/promises'
import { request } from 'node:http'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const require = createRequire(import.meta.url)
const path = resolve(process.argv[2]), cluster = process.env.REMOTE_TEST_CLUSTER_ROOT
assert.ok(cluster && path.startsWith(resolve(cluster)+'/'), 'private cluster required')
const fixture = JSON.parse(await readFile(path,'utf8'))
const root = dirname(path), workspace = join(root,'workspace'), socketPath = join(root,'ipc','host.sock'), ca = join(root,'ca.pem')
await mkdir(workspace)
await writeFile(ca,fixture.ca_pem,{mode:0o600})
const wrapper = join(root,'plugin.mjs')
await writeFile(wrapper,[
  "import {createPrivateKey,sign} from 'node:crypto'",
  `import {createRemoteControlPlugin} from ${JSON.stringify(pathToFileURL(resolve('host/remote-control/lib/index.js')).href)}`,
  `const key=createPrivateKey({format:'jwk',key:${JSON.stringify(fixture.host_private_jwk)}})`,
  `const plugin=createRemoteControlPlugin({async acquire(){return {installationId:${JSON.stringify(fixture.host_installation_id)},credential:${JSON.stringify(fixture.host_credential)},signer:{sign(input){return sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'})}}}}},{hostId:${JSON.stringify(fixture.approval_host_id)},installationId:${JSON.stringify(fixture.host_installation_id)},policyVersion:7,requiredAssurance:${JSON.stringify(fixture.approval_policy)},authorities:[${JSON.stringify(fixture.approval_authority)}],requiresApproval:execution=>['bash','pwsh','run_code'].includes(execution.name)})`,
  'export const {name,inject,apply}=plugin','',
].join('\n'),{mode:0o600})
const patch = join(root,'host.patch.yml')
await writeFile(patch,[
  '- insert:', '    - id: local-model', `      name: ${JSON.stringify(resolve('host/remote-control/tests/fixtures/dsh-local-model.mjs'))}`,
  '    - id: remote-control', `      name: ${JSON.stringify(wrapper)}`, '      config:', '        enabled: true',
  `        runtimeId: ${fixture.runtime_id}`, `        socketPath: ${JSON.stringify(socketPath)}`, `        relayUrl: ${JSON.stringify(fixture.deployment.remote_origin)}`,
  '        applicationVersion: android-device-fixture', `        commandJournalPath: ${JSON.stringify(join(root,'commands.sqlite'))}`,
  '        workspaces:', '          - id: probe', `            remoteId: ${fixture.workspace_id}`, `            cwd: ${JSON.stringify(workspace)}`,
  '        presets: [standard]', '- id: agent-default-model', '  config:', '    provider: dsh-m0-test', '    model: offline','',
].join('\n'),{mode:0o600})
const dsh = spawn(process.execPath,[join(dirname(require.resolve('@deepseek-ai/dsh/package.json')),'lib/bin.js'),'--profile','android-device','--from-default-profile','web','--patch',patch,'--host','127.0.0.1','--port','0','--no-open'],{
  env:{PATH:process.env.PATH,NODE_EXTRA_CA_CERTS:ca,DSH_HOME:join(root,'dsh-home'),DSH_TELEMETRY_DISABLED:'1',NO_COLOR:'1',TMPDIR:root},stdio:['ignore','pipe','pipe'],
})
for (const stream of [dsh.stdout,dsh.stderr]) stream.resume()
const dshExit=once(dsh,'exit');void dshExit.catch(()=>{})
let device, phase='host-startup', stopping=false
const stop=()=>{stopping=true;device?.kill('SIGTERM');dsh.kill('SIGINT')}
process.on('SIGTERM',stop);process.on('SIGINT',stop)
async function local(method,url,body) {
  return new Promise((accept,reject)=>{
    const req=request({socketPath,method,path:url,headers:{'content-type':'application/json'}},response=>{
      const buffers=[];response.on('data',chunk=>buffers.push(Buffer.from(chunk)));response.on('error',reject)
      response.on('end',()=>{try{assert.equal(response.statusCode,200);const value=JSON.parse(Buffer.concat(buffers).toString('utf8').trim());assert.notEqual(value.type,'error');accept(value)}catch{reject(new Error('fixture IPC failed'))}})
    });req.on('error',reject);req.setTimeout(5000,()=>req.destroy(new Error('fixture IPC timeout')));req.end(body===undefined?undefined:JSON.stringify(body))
  })
}
try {
  let probe;const deadline=Date.now()+30_000
  while(Date.now()<deadline){if(stopping||dsh.exitCode!==null||dsh.signalCode!==null)throw new Error('owned host stopped');try{probe=await local('GET','/m0/probe');break}catch{}await new Promise(resolve=>setTimeout(resolve,50))}
  assert.equal(probe?.payload.dsh_version,'0.2.1-rc.2')
  phase='session-create'
  const created=await local('POST','/m0/command',{v:0,type:'session.create',request_id:randomUUID(),runtime_epoch:probe.runtime_epoch,payload:{workspace:'probe',preset:'standard'}})
  const input=join(root,'android-input.json'), result=join(root,'android-result.json')
  await writeFile(input,JSON.stringify({run_id:randomUUID(),secret:fixture.android_secret,deployment:fixture.deployment,ca_pem:fixture.ca_pem,runtime_id:fixture.runtime_id,session_id:created.payload.session_id}),{mode:0o600})
  phase='android-instrumentation'
  device=spawn('python3',[resolve('tools/integration/run_android_device.py'),input,fixture.android_serial,result],{env:process.env,stdio:['ignore','pipe','pipe']})
  let output='';for(const stream of [device.stdout,device.stderr])stream.setEncoding('utf8').on('data',value=>{output=(output+value).slice(-4096)})
  const [code]=await once(device,'exit')
  assert.equal(code,0,'native device fixture failed: '+output)
  phase='native-effects'
  assert.equal(await readFile(join(workspace,'approval-allow.txt'),'utf8'),'authorized')
  await assert.rejects(access(join(workspace,'approval-reject.txt')))
  process.stdout.write(output)
  console.log('Android APK / real Go TLS / npm DSH: one allowed Bash append and no rejected invocation file passed')
} catch(error){throw new Error('Android/Go/DSH composition failed at '+phase,{cause:error})}
finally {
  stopping=true;if(device&&device.exitCode===null&&device.signalCode===null)device.kill('SIGTERM')
  if(dsh.exitCode===null&&dsh.signalCode===null)dsh.kill('SIGINT')
  let timer;try{await Promise.race([dshExit,new Promise((_,reject)=>{timer=setTimeout(()=>{dsh.kill('SIGKILL');reject(new Error('owned host cleanup timeout'))},6000)})])}finally{clearTimeout(timer)}
}
