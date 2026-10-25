// Test-only composition: actual npm DSH -> TLS Go Relay -> production Kotlin reader.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, readFile, writeFile, access } from 'node:fs/promises'
import { request } from 'node:http'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'

const require = createRequire(import.meta.url)
const path = resolve(process.argv[2])
const cluster = process.env.REMOTE_TEST_CLUSTER_ROOT
assert.ok(cluster && path.startsWith(resolve(cluster) + '/'), 'private cluster fixture required')
const fixture = JSON.parse(await readFile(path, 'utf8'))
const root = dirname(path), socketPath = join(root, 'ipc', 'host.sock'), workspace = join(root, 'workspace')
const ca = join(root, 'ca.pem'), ready = join(root, 'reader-ready')
await mkdir(workspace)
await writeFile(ca, fixture.ca_pem, { mode: 0o600 })
const wrapper = join(root, 'plugin.mjs')
await writeFile(wrapper, [
  "import {createPrivateKey,sign} from 'node:crypto'",
  `import {createRemoteControlPlugin} from ${JSON.stringify(pathToFileURL(resolve('host/remote-control/lib/index.js')).href)}`,
  `const key=createPrivateKey({format:'jwk',key:${JSON.stringify(fixture.host_private_jwk)}})`,
  `const plugin=createRemoteControlPlugin({async acquire(){return {installationId:${JSON.stringify(fixture.host_installation_id)},credential:${JSON.stringify(fixture.host_credential)},signer:{sign(input){return sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'})}}}}})`,
  'export const {name,inject,apply}=plugin', '',
].join('\n'), { mode: 0o600 })
const patch = join(root, 'host.patch.yml')
const standardPreset = await readFile(join(dirname(require.resolve('@deepseek-ai/dsh-web-app/package.json')), 'presets/standard.patch.yml'), 'utf8')
const questionPlugin = "          - id: tool-ask-user\n            name: '@deepseek-ai/dsh-tool-ask-user'"
assert.ok(standardPreset.includes(questionPlugin), 'Pinned DSH preset question tool changed')
const timedPreset = standardPreset.replace('- id: preset-standard', '- id: preset-remote-timed').replace('        id: standard', '        id: remote-timed').replace(questionPlugin, questionPlugin+'\n            config:\n              mode: timed\n              timeout: 1')
await writeFile(patch, [
  '- insert:', '    - id: local-model', `      name: ${JSON.stringify(resolve('host/remote-control/tests/fixtures/dsh-local-model.mjs'))}`,
  '    - id: remote-control', `      name: ${JSON.stringify(wrapper)}`, '      config:', '        enabled: true',
  `        runtimeId: ${fixture.runtime_id}`, `        socketPath: ${JSON.stringify(socketPath)}`, `        relayUrl: ${JSON.stringify(fixture.deployment.remote_origin)}`,
  '        applicationVersion: kotlin-content-fixture', `        commandJournalPath: ${JSON.stringify(join(root, 'commands.sqlite'))}`,
  '        workspaces:', '          - id: probe', `            remoteId: ${fixture.workspace_id}`, `            cwd: ${JSON.stringify(workspace)}`,
  '        presets: [standard, remote-timed]', '- id: agent-default-model', '  config:', '    provider: dsh-m0-test', '    model: offline', '',
].join('\n')+'\n'+timedPreset, { mode: 0o600 })

let stopping = false, subscription, java
const dsh = spawn(process.execPath, [join(dirname(require.resolve('@deepseek-ai/dsh/package.json')), 'lib/bin.js'), '--profile', 'kotlin-content', '--from-default-profile', 'web', '--patch', patch, '--host', '127.0.0.1', '--port', '0', '--no-open'], {
  env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: ca, DSH_HOME: join(root, 'dsh-home'), DSH_TELEMETRY_DISABLED: '1', NO_COLOR: '1', TMPDIR: root },
  stdio: ['ignore', 'pipe', 'pipe'],
})
// Retain no model/body/credential output. Failure reports only the composition phase.
for (const stream of [dsh.stdout, dsh.stderr]) stream.resume()
const dshExit = once(dsh, 'exit')
void dshExit.catch(() => {})
const stop = () => { stopping = true; java?.kill('SIGTERM'); dsh.kill('SIGINT') }
process.on('SIGTERM', stop)
process.on('SIGINT', stop)
async function until(test, label, timeout = 20_000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (stopping || dsh.exitCode !== null || dsh.signalCode !== null) throw new Error('DSH fixture stopped at ' + label)
    const value = await test()
    if (value !== undefined) return value
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error('DSH fixture timed out at ' + label)
}
function local(method, url, body) {
  return new Promise((accept, reject) => {
    const req = request({ socketPath, method, path: url, headers: { 'content-type': 'application/json' } }, response => {
      const buffers = []
      response.on('data', chunk => buffers.push(Buffer.from(chunk)))
      response.on('error', reject)
      response.on('end', () => {
        try {
          const frame = JSON.parse(Buffer.concat(buffers).toString('utf8').trim())
          assert.equal(response.statusCode, 200); assert.notEqual(frame.type, 'error')
          accept(frame)
        } catch { reject(new Error('DSH IPC fixture command failed')) }
      })
    })
    req.on('error', reject); req.setTimeout(5000, () => req.destroy(new Error('DSH IPC timeout')))
    req.end(body === undefined ? undefined : JSON.stringify(body))
  })
}
let phase = 'startup'
try {
  const probe = await until(async () => { try { return await local('GET', '/m0/probe') } catch { return undefined } }, phase)
  assert.equal(probe.payload.dsh_version, '0.2.1-rc.2')
  const command = (type, payload, session_id) => local('POST', '/m0/command', { v: 0, type, request_id: randomUUID(), runtime_epoch: probe.runtime_epoch, payload, ...(session_id === undefined ? {} : { session_id }) })
  phase = 'session-create'
  const sessionId = (await command('session.create', { workspace: 'probe', preset: 'standard' })).payload.session_id
  let turns = 0, streamError = false
  subscription = request({ socketPath, method: 'POST', path: '/m0/command', headers: { 'content-type': 'application/json' } }, response => {
    createInterface({ input: response }).on('error', () => { if (!stopping) streamError = true }).on('line', line => {
      try {
        const frame = JSON.parse(line)
        if (frame.type === 'session.event' && frame.payload.type === 'turn/end') turns++
        if (frame.type === 'error') streamError = true
      } catch { streamError = true }
    })
  })
  subscription.on('error', () => { if (!stopping) streamError = true })
  subscription.end(JSON.stringify({ v: 0, type: 'session.subscribe', request_id: randomUUID(), runtime_epoch: probe.runtime_epoch, session_id: sessionId, payload: { max_messages: 1 } }))
  phase = 'native-history'
  for (let index = 0; index < 16; index++) {
    await command('message.submit', { mode: 'queue', text: `KOTLIN_HISTORY_${index} ` + '中🙂'.repeat(4000) }, sessionId)
    await until(async () => { assert.equal(streamError, false); return turns > index ? true : undefined }, phase)
  }
  phase = 'kotlin-reader'
  const readerPath = join(root, 'reader.json')
  const readerFixture = { ...fixture, session_id: sessionId, mode: 'content', ready_file: ready }
  for (const field of Object.keys(readerFixture)) if (field.startsWith('host_')) delete readerFixture[field]
  await writeFile(readerPath, JSON.stringify(readerFixture), { mode: 0o600 })
  java = spawn(process.env.REMOTE_TEST_JAVA || 'java', ['-cp', process.env.REMOTE_TEST_KOTLIN_CLASSPATH, 'cn.edu.ustc.dsh.network.RunRelayProbe', readerPath], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] })
  const javaExit = once(java, 'exit')
  void javaExit.catch(() => {})
  let output = ''
  for (const stream of [java.stdout, java.stderr]) stream.setEncoding('utf8').on('data', text => { output = (output + text).slice(-4096) })
  await until(async () => {
    if (java.exitCode !== null || java.signalCode !== null) throw new Error('Kotlin reader exited before history validation: ' + output)
    try { await access(ready); return true } catch { return undefined }
  }, phase)
  phase = 'native-live'
  await command('message.submit', { mode: 'queue', text: 'KOTLIN_LIVE_MARKER' }, sessionId)
  const [code] = await javaExit
  assert.equal(code, 0, 'Kotlin content probe failed: ' + output)
  process.stdout.write(output)
} catch (error) {
  throw new Error(`Kotlin/Go/DSH composition failed at ${phase}`, { cause: error })
} finally {
  stopping = true; subscription?.destroy()
  if (java && java.exitCode === null && java.signalCode === null) java.kill('SIGTERM')
  if (dsh.exitCode === null && dsh.signalCode === null) dsh.kill('SIGINT')
  let timer
  try { await Promise.race([dshExit, new Promise((_, reject) => { timer = setTimeout(() => { dsh.kill('SIGKILL'); reject(new Error('DSH cleanup timeout')) }, 5000) })]) }
  finally { clearTimeout(timer) }
}
