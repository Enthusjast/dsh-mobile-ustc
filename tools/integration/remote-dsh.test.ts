import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { createServer, request } from 'node:http'
import { createServer as createTCPServer } from 'node:net'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { hostHelloDigest, relayPayloadDigest, relayCancelDigest, relayArchiveDigest, relayCreateDigest, relayQuestionDigest, relayTimedQuestionDigest } from '../../host/remote-control/src/relay-client.js'
import { CompactSign } from 'jose'
import { approvalBinding, approvalKeyID, APPROVAL_JWS_TYPE, type ApprovalContext, type ApprovalDecision } from '../../host/remote-control/src/approval-contract.js'
import { canonicalObject } from '../../host/remote-control/src/canonical.js'

const require = createRequire(import.meta.url)
const WebSocket = require('ws') as new (url: string, protocol: string, options: object) => any
const now = () => Math.floor(Date.now() / 1000)
const hash = (input: string) => createHash('sha256').update(input).digest('base64url')
const key = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const jwk = pair.publicKey.export({ format: 'jwk' })
  const jkt = hash(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
  return { ...pair, jwk, jkt }
}
function jws(privateKey: KeyObject, header: object, claims: object): string {
  const input = [header, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.')
  return `${input}.${sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`
}

async function until<Value>(read: () => Promise<Value | undefined>, label: string, timeout = 10_000): Promise<Value> {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    const value = await read()
    if (value !== undefined) return value
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error(`Timed out: ${label}`)
}

async function startProcess(binary: string, args: string[], env: NodeJS.ProcessEnv) {
  const child = spawn(binary, args, { cwd: process.cwd(), env, stdio: ['ignore', 'pipe', 'pipe'] })
  let tail = ''
  for (const stream of [child.stdout, child.stderr]) stream.setEncoding('utf8').on('data', text => { tail = (tail + text).slice(-4096) })
  const exited = once(child, 'exit') as Promise<[number | null, NodeJS.Signals | null]>
  void exited.catch(() => {})
  await once(child, 'spawn')
  return {
    child, exited,
    check() { if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Child process exited: ${tail}`) },
    async stop(signal: NodeJS.Signals) {
      if (child.exitCode === null && child.signalCode === null) child.kill(signal)
      let timer: NodeJS.Timeout | undefined
      try {
        return await Promise.race([exited, new Promise<never>((_, reject) => {
          timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Child process failed graceful shutdown')) }, 5000)
        })])
      } finally { if (timer) clearTimeout(timer) }
    },
  }
}

class FrameCollector {
  readonly frames: any[] = []
  failure: Error | undefined
  closed = false
  private readonly pending: object[] = []
  private writing = false
  private lastSent = 0
  constructor(readonly socket: any, validate: (value: unknown) => boolean) {
    socket.on('message', (raw: Buffer) => {
      try {
        assert.ok(raw.length <= 65_536)
        const frame = JSON.parse(raw.toString('utf8'))
        assert.equal(validate(frame), true, `Relay emitted invalid ${String(frame.type)} frame`)
        this.frames.push(frame)
        if (this.frames.length > 4096) throw new Error('Integration frame queue exceeded budget')
      } catch (error) { this.failure = error instanceof Error ? error : new Error('Invalid frame') }
    })
    socket.on('error', (error: Error) => { this.failure = error })
    socket.on('close', () => { this.closed = true })
  }
  send(value: object) {
    assert.ok(this.pending.length < 64, 'Integration send queue exceeded budget')
    this.pending.push(value)
    if (!this.writing) void this.write()
  }
  private async write() {
    this.writing = true
    try {
      while (this.pending.length) {
        // Keep this phone fixture inside the production 20-operation/second
        // quota, including when the offline model completes immediately.
        const pause = Math.max(0, 60 - (Date.now() - this.lastSent))
        if (pause) await new Promise(resolve => setTimeout(resolve, pause))
        if (this.closed) throw new Error('Relay socket closed with queued fixture input')
        this.socket.send(JSON.stringify(this.pending.shift()))
        this.lastSent = Date.now()
      }
    } catch (error) { this.failure = error instanceof Error ? error : new Error('Fixture socket write failed') }
    finally { this.writing = false }
  }
  wait(predicate: (frame: any) => boolean, from = 0) {
    return until(async () => {
      if (this.failure) throw this.failure
      const frame = this.frames.slice(from).find(predicate)
      if (frame) return frame
      if (this.closed) throw new Error('Relay socket closed before expected frame')
      return undefined
    }, 'Relay frame').catch(error => {
      const metadata = this.frames.slice(from).slice(-12).map(frame => ({ type: frame.type, request_id: frame.request_id, state: frame.payload?.state, code: frame.payload?.code }))
      throw new Error(`${String(error)}; recent routing metadata=${JSON.stringify(metadata)}`)
    })
  }
}

test('real Go service and npm DSH share authorized sessions through PostgreSQL and signed peers', { timeout: 90_000 }, async t => {
  const cluster = process.env.REMOTE_TEST_CLUSTER_ROOT
  const database = process.env.REMOTE_TEST_DATABASE_URL
  const psql = process.env.REMOTE_TEST_PSQL
  const pgDump = process.env.REMOTE_TEST_PG_DUMP
  const serviceBin = process.env.REMOTE_TEST_SERVICE_BIN
  assert.ok(cluster && database && psql && pgDump && serviceBin, 'Use npm run test:remote-dsh to create an isolated cluster')
  assert.ok(database.startsWith(`host=${cluster} `), 'Only the disposable Unix-socket cluster is allowed')
  const root = await mkdtemp(join(cluster, 'clients-'))
  const query = (sql: string) => execFileSync(psql, ['-X', '--dbname', database, '-v', 'ON_ERROR_STOP=1', '-At'], { input: sql, encoding: 'utf8' }).trim()
  const signingKey = key(), installationKey = key(), phoneKey = key(), approvalKey = key(), outsiderKey = key(), outsiderApprovalKey = key()
  const approvalAuthority = key()
  const siblingKey = key(), siblingApprovalKey = key()
  const orgId = randomUUID(), ownerId = randomUUID(), phoneUserId = randomUUID(), outsiderId = randomUUID()
  const jwks = createServer((req, res) => {
    if (req.url !== '/jwks') { res.writeHead(404).end(); return }
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({ keys: [{ ...signingKey.jwk, kid: 'integration-key', alg: 'ES256', use: 'sig' }] }))
  })
  await new Promise<void>(accept => jwks.listen(0, '127.0.0.1', accept))
  t.after(() => new Promise<void>(accept => jwks.close(() => accept())))
  const jwksAddress = jwks.address()
  assert.ok(jwksAddress && typeof jwksAddress === 'object')
  const issuer = `http://127.0.0.1:${jwksAddress.port}`
  query(`insert into orgs(id,slug,name) values ('${orgId}','integration','Integration');
    insert into users(id,issuer,subject) values ('${ownerId}','${issuer}','owner'),('${phoneUserId}','${issuer}','phone'),('${outsiderId}','${issuer}','outsider');
    insert into org_memberships(org_id,user_id,role) values ('${orgId}','${ownerId}','member'),('${orgId}','${phoneUserId}','member'),('${orgId}','${outsiderId}','member');`)
  const reserved = createTCPServer()
  await new Promise<void>(accept => reserved.listen(0, '127.0.0.1', accept))
  const address = reserved.address()
  assert.ok(address && typeof address === 'object')
  await new Promise<void>(accept => reserved.close(() => accept()))
  const origin = `http://127.0.0.1:${address.port}`
  const metricsReserved = createTCPServer()
  await new Promise<void>(accept => metricsReserved.listen(0, '127.0.0.1', accept))
  const metricsAddress = metricsReserved.address()
  assert.ok(metricsAddress && typeof metricsAddress === 'object')
  await new Promise<void>(accept => metricsReserved.close(() => accept()))
  const metricsOrigin = `http://127.0.0.1:${metricsAddress.port}`
  const authority = { issuer: 'https://remote.example.edu', key_id: 'dsh-approval-authority/cli-integration', public_jwk: approvalAuthority.jwk, key_jkt: approvalAuthority.jkt, active: true,
    valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString() }
  const approvalSigningFile = join(root, 'approval-authority.pem'), approvalPolicyFile = join(root, 'approval-policy.json')
  await writeFile(approvalSigningFile, approvalAuthority.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
  await writeFile(approvalPolicyFile, JSON.stringify({ policy: { version: 7, assurance_profile: 'fixture/step-up', max_auth_age_seconds: 60 },
    mappings: [{ profile: 'fixture/step-up', issuer, client_id: 'fixture-phone', acr: 'urn:fixture:verified', required_amr: ['otp'] }],
    signing: { issuer: authority.issuer, key_id: authority.key_id, private_key_file: approvalSigningFile, valid_from: authority.valid_from, valid_until: authority.valid_until } }), { mode: 0o600 })
  const releasesFile = join(root, 'app-releases.json')
  const releases = JSON.parse(await readFile(resolve('deploy/android/releases.example.json'), 'utf8'))
  releases.publications[0].organization_ids = [orgId]
  await writeFile(releasesFile, JSON.stringify(releases), { mode: 0o600 })
  const service = await startProcess(serviceBin, [], {
    PATH: process.env.PATH ?? '', REMOTE_ISSUER: issuer, REMOTE_JWKS_URL: `${issuer}/jwks`, REMOTE_AUDIENCE: 'urn:dsh-e2e',
    REMOTE_CLIENT_IDS: 'fixture-host,fixture-phone', REMOTE_HOST_CLIENT_IDS: 'fixture-host', REMOTE_REQUIRED_SCOPES: 'remote.access',
    REMOTE_PUBLIC_ORIGIN: origin, REMOTE_DATABASE_URL: database, REMOTE_LISTEN_ADDR: `127.0.0.1:${address.port}`,
    REMOTE_APPROVAL_POLICY_FILE: approvalPolicyFile,
    REMOTE_APP_RELEASES_FILE: releasesFile,
    REMOTE_METRICS_LISTEN_ADDR: `127.0.0.1:${metricsAddress.port}`,
  })
  t.after(async () => { const [code] = await service.stop('SIGTERM'); assert.equal(code, 0, 'Go service did not drain cleanly') })
  await until(async () => {
    service.check()
    try { if ((await fetch(`${origin}/readyz`, { signal: AbortSignal.timeout(500) })).status === 204) return true } catch {}
    return undefined
  }, 'Go readiness')
  assert.equal((await fetch(`${origin}/metrics`)).status, 404, 'operational metrics leaked onto the public API')
  const readMetrics = async () => {
    const response = await fetch(`${metricsOrigin}/metrics`, { signal: AbortSignal.timeout(1500), headers: { accept: 'text/plain;version=0.0.4' } })
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('cache-control'), 'no-store')
    const body = await response.text()
    assert.ok(body.length < 512 * 1024, 'metric output grew with resource identities')
    return body
  }
  const metricSample = (body: string, name: string, labels: Record<string, string> = {}) => {
    for (const line of body.split('\n')) {
      const [identity, value] = line.split(' ')
      if (!identity || identity.split('{', 1)[0] !== `dsh_remote_${name}`) continue
      const found = new Map([...identity.matchAll(/([a-z_][a-z0-9_]*)="([^"]*)"/g)].map(match => [match[1]!, match[2]!]))
      if (found.size === Object.keys(labels).length && Object.entries(labels).every(([key, expected]) => found.get(key) === expected)) return Number(value)
    }
    return 0
  }

  const client = (subject: string, clientId: string, proofKey: ReturnType<typeof key>) => {
    const token = jws(signingKey.privateKey, { alg: 'ES256', typ: 'at+jwt', kid: 'integration-key' }, {
      iss: issuer, sub: subject, aud: 'urn:dsh-e2e', client_id: clientId, jti: randomUUID(), iat: now(), exp: now() + 300,
      scope: 'remote.access', cnf: { jkt: proofKey.jkt },
      auth_time: now() - 2, acr: 'urn:fixture:verified', amr: ['otp'],
    })
    let nonce = ''
    return async (method: string, path: string, body?: object | ((proofJTI: string) => object), expected = 200) => {
      for (let attempt = 0; attempt < 2; attempt++) {
        const proofJTI = randomUUID()
        const proof = jws(proofKey.privateKey, { typ: 'dpop+jwt', alg: 'ES256', jwk: proofKey.jwk }, {
          htm: method, htu: origin + path.split('?')[0], ath: hash(token), jti: proofJTI, iat: now(), nonce,
        })
        const requestBody = typeof body === 'function' ? body(proofJTI) : body
        const response = await fetch(origin + path, {
          method, headers: { authorization: `DPoP ${token}`, dpop: proof, ...(requestBody === undefined ? {} : { 'content-type': 'application/json' }) },
          ...(requestBody === undefined ? {} : { body: JSON.stringify(requestBody) }), signal: AbortSignal.timeout(5000),
        })
        nonce = response.headers.get('dpop-nonce') ?? nonce
        const result = await response.json() as any
        if (attempt === 0 && response.status === 401 && response.headers.get('www-authenticate')?.includes('use_dpop_nonce')) continue
        assert.equal(response.status, expected, `${method} ${path}: ${String(result.error?.code ?? 'unexpected status')}`)
        return result.data
      }
      throw new Error('DPoP nonce retry was rejected')
    }
  }
  const owner = client('owner', 'fixture-host', installationKey)
  const phone = client('phone', 'fixture-phone', phoneKey)
  const siblingPhone = client('phone', 'fixture-phone', siblingKey)
  const outsider = client('outsider', 'fixture-phone', outsiderKey)
  const phoneIdentity = await phone('GET', '/v1/me?user_id=untrusted&organization_id=untrusted')
  assert.equal(phoneIdentity.issuer, issuer)
  assert.equal(phoneIdentity.subject, 'phone')
  assert.equal(phoneIdentity.user_id, phoneUserId)
  assert.deepEqual(phoneIdentity.memberships, [{ organization_id: orgId, role: 'member' }])
  assert.equal((await owner('GET', '/v1/me')).user_id, ownerId)
  await client('not-provisioned', 'fixture-phone', key())('GET', '/v1/me', undefined, 403)
  query(`delete from org_memberships where user_id='${phoneUserId}';`)
  assert.deepEqual((await phone('GET', '/v1/me')).memberships, [])
  query(`insert into org_memberships(org_id,user_id,role) values ('${orgId}','${phoneUserId}','member');
    update users set status='suspended' where id='${phoneUserId}';`)
  await phone('GET', '/v1/me', undefined, 403)
  query(`update users set status='active' where id='${phoneUserId}';`)
  const register = (api: typeof phone, proofKey: ReturnType<typeof key>, approval: ReturnType<typeof key>, subject: string) => api('POST', '/v1/devices', proofJTI => ({
    name: subject, proof_public_jwk: proofKey.jwk, approval_public_jwk: approval.jwk,
    approval_proof: jws(approval.privateKey, { alg: 'ES256', typ: 'dsh-device-registration-proof+jwt' }, {
      iss: issuer, sub: subject, aud: 'urn:dsh-mobile-ustc:device-registration', iat: now(), jti: randomUUID(),
      approval_key_jkt: approval.jkt, proof_key_jkt: proofKey.jkt, device_name_sha256: hash(subject), dpop_jti: proofJTI,
    }),
  }), 201)
  assert.deepEqual(await phone('GET', '/v1/devices/current'), { state: 'unregistered' })
  const releaseQuery = `/v1/app/releases/latest?organization_id=${orgId}&version_code=1&protocol_version=1&android_api=26`
  await phone('GET', releaseQuery, undefined, 403)
  const device = await register(phone, phoneKey, approvalKey, 'phone')
  assert.deepEqual(await register(phone, phoneKey, approvalKey, 'phone'), device)
  assert.deepEqual(await phone('GET', '/v1/devices/current?device_id=untrusted'), { state: 'active', device: {
    device_id: device.device_id, key_version: 1, approval_key_jkt: approvalKey.jkt, proof_key_jkt: phoneKey.jkt,
  } })
  const siblingDevice = await register(siblingPhone, siblingKey, siblingApprovalKey, 'phone')
  await register(outsider, outsiderKey, outsiderApprovalKey, 'outsider')
  // No host has been enrolled and no runtime grant exists yet. APK metadata
  // depends on the current organization/account/phone, independently of lists.
  const publication = await phone('GET', releaseQuery)
  assert.equal(publication.current_supported, true)
  assert.deepEqual(publication.release, releases.publications[0].release)
  assert.equal((await phone('GET', releaseQuery.replace('version_code=1', 'version_code=2'))).release, null)
  const newerClient = await phone('GET', releaseQuery.replace('version_code=1', 'version_code=3'))
  assert.equal(newerClient.current_supported, false); assert.equal(newerClient.release, null)
  await owner('GET', releaseQuery, undefined, 403)
  await phone('GET', releaseQuery + `&device_id=${siblingDevice.device_id}`, undefined, 400)
  await phone('GET', releaseQuery.replace(orgId, randomUUID()), undefined, 403)
  query(`delete from org_memberships where user_id='${phoneUserId}'`)
  await phone('GET', releaseQuery, undefined, 403)
  query(`insert into org_memberships(org_id,user_id,role) values ('${orgId}','${phoneUserId}','member')`)
  assert.deepEqual((await phone('GET', releaseQuery)).release, publication.release)
  t.diagnostic('Configured APK metadata selected the supported newer fixture under the current registered phone and organization before any runtime grant; current/newer clients, foreign organization, host client and caller device selectors were fenced. No APK bytes or installation were involved.')
  const code = randomBytes(32).toString('base64url')
  const enrollment = await owner('POST', '/v1/enrollments', {
    request_id: randomUUID(), organization_id: orgId, alias: 'DSH integration', profile_ref: 'e2e', dsh_version: '0.2.1-rc.2',
    application_version: 'dsh-go-integration', plugin_version: '0.0.1', protocol_version: 1,
    installation_public_jwk: installationKey.jwk, code, workspace_refs: ['e2e-workspace', 'other-workspace'],
  }, 201)
  await phone('GET', `/v1/enrollments/${enrollment.enrollment_id}`, undefined, 403)
  await phone('POST', `/v1/enrollments/${enrollment.enrollment_id}/preview`, { code: randomBytes(32).toString('base64url') }, 403)
  assert.equal((await outsider('POST', `/v1/enrollments/${enrollment.enrollment_id}/preview`, { code })).user_confirmed_by_me, false)
  assert.deepEqual((await outsider('GET', '/v1/runtimes')).items, [])
  const preview = await phone('POST', `/v1/enrollments/${enrollment.enrollment_id}/preview`, { code })
  assert.equal(preview.organization_id, orgId)
  assert.equal(preview.installation_key_jkt, installationKey.jkt)
  assert.equal(preview.user_confirmed_by_me, false)
  assert.equal(preview.host_confirmed, false)
  assert.equal(JSON.stringify(preview).includes(code), false)
  const partial = await phone('POST', `/v1/enrollments/${enrollment.enrollment_id}/confirm`, { code })
  assert.equal(partial.state, 'user_confirmed')
  assert.equal(partial.host_confirmed, false)
  assert.equal((await phone('GET', `/v1/enrollments/${enrollment.enrollment_id}`)).user_confirmed_by_me, true)
  assert.equal((await owner('GET', `/v1/enrollments/${enrollment.enrollment_id}`)).user_confirmed_by_me, false)
  const active = await owner('POST', `/v1/enrollments/${enrollment.enrollment_id}/host-confirm`, { code })
  assert.equal(active.state, 'approved')
  assert.equal(active.host_confirmed, true)
  assert.equal(active.user_confirmed, true)
  assert.ok((await phone('GET', '/v1/hosts')).items.some((host: any) => host.id === enrollment.host_id && host.state === 'active'))
  const runtimeAccess = (await phone('GET', '/v1/runtimes')).items.find((runtime: any) => runtime.id === enrollment.runtime_id)
  assert.equal(runtimeAccess.organization_id, orgId)
  assert.equal(runtimeAccess.access.role, 'owner')
  assert.ok(runtimeAccess.access.grant_version >= 1)
  assert.ok(runtimeAccess.access.scope.actions.includes('session.read'))
  assert.ok(runtimeAccess.access.scope.workspaces.includes(enrollment.workspaces[0].workspace_id))
  const challenge = await owner('POST', '/v1/host-credentials/challenges', undefined, 201)
  const credential = await owner('POST', '/v1/host-credentials', {
    challenge_id: challenge.challenge_id,
    proof: jws(installationKey.privateKey, { alg: 'ES256', typ: 'dsh-host-credential-proof+jwt' }, {
      iss: enrollment.installation_id, aud: challenge.audience, challenge_id: challenge.challenge_id, nonce: challenge.challenge, iat: now(), jti: randomUUID(),
    }),
  }, 201)

  const workspace = join(root, 'workspace'), socketPath = join(root, 'ipc', 'host.sock')
  await mkdir(workspace)
  const plugin = pathToFileURL(resolve('host/remote-control/lib/index.js')).href
  const wrapper = join(root, 'plugin.mjs')
  await writeFile(wrapper, [
    "import { createPrivateKey, sign } from 'node:crypto'",
    "import { writeFile } from 'node:fs/promises'",
    `import { createRemoteControlPlugin } from ${JSON.stringify(plugin)}`,
    `const privateKey = createPrivateKey({format:'jwk',key:${JSON.stringify(installationKey.privateKey.export({ format: 'jwk' }))}})`,
    `const plugin = createRemoteControlPlugin({async acquire(){return {installationId:${JSON.stringify(enrollment.installation_id)},credential:${JSON.stringify(credential.credential)},signer:{sign(input){return sign('sha256',Buffer.from(input),{key:privateKey,dsaEncoding:'ieee-p1363'})}}}}}, {hostId:${JSON.stringify(enrollment.host_id)},installationId:${JSON.stringify(enrollment.installation_id)},policyVersion:7,requiredAssurance:{profile:'fixture/step-up',max_auth_age_seconds:60},authorities:[${JSON.stringify(authority)}],requiresApproval:execution=>['bash','pwsh','run_code'].includes(execution.name)})`,
    'export const {name,inject}=plugin',
    `export function apply(ctx,config){ctx.on('tools/execute',async(exec,next)=>{if(exec.name==='bash'&&exec.arguments.command.includes('approval-revoke.txt')){await writeFile(${JSON.stringify(join(workspace,'approval-revoke-held'))},'held');const signal=exec.signal;await new Promise(resolve=>{const abort=()=>{clearTimeout(timer);signal.removeEventListener('abort',abort);resolve()};const timer=setTimeout(abort,30000);signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort()})}return next()},{prepend:true});return plugin.apply(ctx,config)}`, '',
  ].join('\n'), { mode: 0o600 })
  const patch = join(root, 'host.patch.yml')
  const standardPreset = await readFile(join(dirname(require.resolve('@deepseek-ai/dsh-web-app/package.json')), 'presets/standard.patch.yml'), 'utf8')
  const questionPlugin = "          - id: tool-ask-user\n            name: '@deepseek-ai/dsh-tool-ask-user'"
  assert.ok(standardPreset.includes(questionPlugin), 'Pinned DSH preset question tool changed')
  const timedPreset = standardPreset.replace('- id: preset-standard', '- id: preset-remote-timed')
    .replace('        id: standard', '        id: remote-timed')
    .replace(questionPlugin, questionPlugin + '\n            config:\n              mode: timed\n              timeout: 1')
  await writeFile(patch, [
    '- insert:', '    - id: local-model', `      name: ${JSON.stringify(resolve('host/remote-control/tests/fixtures/dsh-local-model.mjs'))}`,
    '    - id: remote-control', `      name: ${JSON.stringify(wrapper)}`, '      config:', '        enabled: true',
    `        runtimeId: ${enrollment.runtime_id}`, `        socketPath: ${JSON.stringify(socketPath)}`,
    `        relayUrl: ${JSON.stringify(origin)}`, '        applicationVersion: dsh-go-integration',
    `        commandJournalPath: ${JSON.stringify(join(root, 'journal', 'commands.sqlite'))}`,
    '        workspaces:', '          - id: probe', `            remoteId: ${enrollment.workspaces[0].workspace_id}`, `            cwd: ${JSON.stringify(workspace)}`,
    '        presets: [standard, remote-timed]', '        highRiskTools: [bash, pwsh, run_code]', '- id: agent-default-model', '  config:', '    provider: dsh-m0-test', '    model: offline', '',
  ].join('\n') + '\n' + timedPreset, { mode: 0o600 })
  const dshPackage = dirname(require.resolve('@deepseek-ai/dsh/package.json'))
  const dsh = await startProcess(process.execPath, [join(dshPackage, 'lib/bin.js'), '--profile', 'remote-e2e', '--from-default-profile', 'web', '--patch', patch,
    '--host', '127.0.0.1', '--port', '0', '--no-open'], {
    PATH: process.env.PATH ?? '', DSH_HOME: join(root, 'dsh-home'), DSH_TELEMETRY_DISABLED: '1', NO_COLOR: '1', TMPDIR: root,
  })
  t.after(async () => { await dsh.stop('SIGINT') })
  const local = (method: string, path: string, body?: object) => new Promise<any>((accept, reject) => {
    const req = request({ socketPath, method, path, headers: { 'content-type': 'application/json' } }, response => {
      const buffers: Buffer[] = []
      response.on('data', chunk => buffers.push(Buffer.from(chunk)))
      response.on('error', reject)
      response.on('end', () => {
        try {
          const frames = Buffer.concat(buffers).toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
          assert.equal(response.statusCode, 200, `DSH local command: ${String(frames[0]?.payload?.code)}`)
          accept(frames[0])
        } catch (error) { reject(error) }
      })
    })
    req.on('error', reject)
    req.setTimeout(5000, () => req.destroy(new Error('DSH IPC timed out')))
    req.end(body === undefined ? undefined : JSON.stringify(body))
  })
  const probe = await until(async () => {
    dsh.check()
    try { return await local('GET', '/m0/probe') } catch { return undefined }
  }, 'DSH readiness', 30_000)
  assert.equal(probe.payload.dsh_version, '0.2.1-rc.2')
  await until(async () => query(`select count(*) from runtimes where id='${enrollment.runtime_id}' and epoch='${probe.runtime_epoch}' and connection_id is not null`) === '1' ? true : undefined,
    'committed host attachment')
  const command = (type: string, payload: object, sessionId?: string) => local('POST', '/m0/command', {
    v: 0, type, request_id: randomUUID(), runtime_epoch: probe.runtime_epoch, payload, ...(sessionId === undefined ? {} : { session_id: sessionId }),
  })
  const beforeCreate = (await command('session.list', {})).payload.items.length
  assert.deepEqual((await outsider('GET', '/v1/runtimes')).items, [])
  const scope = { actions: ['approval.decide', 'message.submit', 'question.answer', 'session.archive', 'session.cancel', 'session.create', 'session.read'], workspaces: [enrollment.workspaces[0].workspace_id], sessions: [] }
  await outsider('POST', '/v1/realtime/tickets', { runtime_id: enrollment.runtime_id, scope }, 403)
  const ticket = await phone('POST', '/v1/realtime/tickets', { runtime_id: enrollment.runtime_id, scope }, 201)
  const schema = JSON.parse(await readFile('contracts/ws/v1/relay.schema.json', 'utf8'))
  const ajv = new Ajv2020({ strict: true }); ajv.addFormat('date-time', value => Number.isFinite(Date.parse(value)))
  const validate = ajv.compile(schema)
  const validateApproval = ajv.compile(JSON.parse(await readFile('contracts/ws/v1/approval.schema.json', 'utf8')))
  const connectPhone = async (api: typeof phone, deviceId: string, proofKey: ReturnType<typeof key>, issued?: typeof ticket) => {
    const connectionTicket = issued ?? await api('POST', '/v1/realtime/tickets', { runtime_id: enrollment.runtime_id, scope }, 201)
    const socket = new WebSocket(origin.replace('http:', 'ws:') + '/v1/realtime', 'dsh.remote.v1', { headers: { authorization: `DSH-Ticket ${connectionTicket.ticket}` }, perMessageDeflate: false, maxPayload: 65_536 })
    const collector = new FrameCollector(socket, value => validate(value) || validateApproval(value))
    t.after(() => { socket.terminate() })
    const challenge = await collector.wait(frame => frame.type === 'challenge')
    const caps = ['approval.signed.v1', 'command.relay.v1', 'connection.heartbeat.v1', 'question.blocking.v1', 'question.timed.v1', 'session.archive.v1', 'session.cancel.v1', 'session.create.v1', 'session.read.v1']
    collector.send({ v: 1, type: 'hello.proof', payload: { device_id: deviceId, protocols: [1], capabilities: caps,
      proof: jws(proofKey.privateKey, { alg: 'ES256', typ: 'dsh-relay-handshake-proof+jwt' }, {
        iss: deviceId, aud: 'urn:dsh-mobile-ustc:realtime', challenge_id: challenge.payload.challenge_id,
        connection_id: challenge.payload.connection_id, nonce: challenge.payload.nonce, runtime_id: enrollment.runtime_id,
        hello_sha256: hostHelloDigest(['device', deviceId, '1', caps.join('\n')]), iat: now(), jti: randomUUID(),
      }),
    } })
    await collector.wait(frame => frame.type === 'hello.ok')
    return collector
  }
  const mobile = await connectPhone(phone, device.device_id, phoneKey, ticket)
  const initialMetrics = await readMetrics()
  assert.equal(metricSample(initialMetrics, 'relay_connections', { phase: 'active', role: 'installation' }), 1)
  assert.equal(metricSample(initialMetrics, 'relay_connections', { phase: 'active', role: 'device' }), 1)
  const approvalWatchId = randomUUID()
  mobile.send({ v: 1, type: 'approval.subscribe', request_id: approvalWatchId, runtime_id: enrollment.runtime_id, payload: {} })
  await mobile.wait(frame => frame.type === 'approval.snapshot' && frame.request_id === approvalWatchId)
  const creationId = randomUUID()
  const creation = { v: 1, type: 'session.create', request_id: creationId, runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch,
    payload: { workspace_id: enrollment.workspaces[0].workspace_id, preset: 'standard' } }
  mobile.send(creation)
  for (const state of ['received', 'host_accepted', 'dispatching', 'settled']) {
    const receipt = await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === creationId && frame.payload.state === state)
    assert.equal(receipt.payload.payload_sha256, relayCreateDigest(probe.runtime_epoch, creation.payload))
    assert.equal(receipt.payload.workspace_id, creation.payload.workspace_id)
    if (state !== 'settled') assert.equal(receipt.session_id, undefined)
  }
  const created = await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === creationId && frame.payload.state === 'settled')
  const sessionId = created.session_id
  assert.match(sessionId, /^[0-9a-f-]{36}$/)
  assert.equal((await command('session.list', {})).payload.items.length, beforeCreate + 1)
  const creationRetryFrom = mobile.frames.length
  mobile.send(creation)
  assert.equal((await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === creationId && frame.payload.state === 'settled', creationRetryFrom)).session_id, sessionId)
  mobile.send({ ...creation, payload: { ...creation.payload, preset: 'changed' } })
  await mobile.wait(frame => frame.type === 'error' && frame.request_id === creationId && frame.payload.code === 'command.request_conflict')
  const wrongWorkspaceId = randomUUID()
  mobile.send({ ...creation, request_id: wrongWorkspaceId, payload: { ...creation.payload, workspace_id: randomUUID() } })
  await mobile.wait(frame => frame.type === 'error' && frame.request_id === wrongWorkspaceId && frame.payload.code === 'access.denied')
  const rejectedPresetId = randomUUID()
  mobile.send({ ...creation, request_id: rejectedPresetId, payload: { ...creation.payload, preset: 'not-configured' } })
  await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === rejectedPresetId && frame.payload.state === 'rejected')
  assert.equal((await command('session.list', {})).payload.items.length, beforeCreate + 1, 'retries or rejected preset created extra sessions')
  const creationStatus = await phone('GET', `/v1/commands/${creationId}?device_id=${device.device_id}`)
  assert.equal(creationStatus.state, 'settled')
  assert.equal(creationStatus.session_id, sessionId)
  assert.equal(creationStatus.workspace_id, creation.payload.workspace_id)
  await until(async () => {
    const directory = await phone('GET', `/v1/runtimes/${enrollment.runtime_id}/sessions`)
    return directory.items.some((item: any) => item.session_id === sessionId && item.state === 'available' && item.workspace_id === enrollment.workspaces[0].workspace_id) ? true : undefined
  }, 'created session in PostgreSQL directory')
  const unrelatedTicket = await phone('POST', '/v1/realtime/tickets', {
    runtime_id: enrollment.runtime_id, scope: { actions: ['message.submit'], workspaces: [enrollment.workspaces[1].workspace_id], sessions: [] },
  }, 201)
  const unrelatedMobile = await connectPhone(phone, device.device_id, phoneKey, unrelatedTicket)
  const subscribe = () => {
    const id = randomUUID()
    mobile.send({ v: 1, type: 'session.subscribe', request_id: id, runtime_id: enrollment.runtime_id, session_id: sessionId, payload: { max_messages: 30 } })
    return id
  }
  const subscriptionRequest = subscribe()
  const opening = await mobile.wait(frame => frame.type === 'session.snapshot' && frame.request_id === subscriptionRequest)
  const requestId = randomUUID(), marker = `REMOTE_DSH_E2E_${randomUUID()}`
  const payload = { mode: 'queue' as const, content: [{ type: 'text' as const, text: marker }] }
  const submit = { v: 1, type: 'message.submit', request_id: requestId, runtime_id: enrollment.runtime_id, session_id: sessionId, payload }
  mobile.send(submit)
  for (const state of ['received', 'host_accepted', 'dispatching', 'agent_queued']) {
    const receipt = await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === requestId && frame.payload.state === state)
    assert.equal(receipt.payload.payload_sha256, relayPayloadDigest(sessionId, payload))
  }
  await mobile.wait(frame => frame.type === 'assistant.chunk' && frame.subscription_id === opening.subscription_id)
  await mobile.wait(frame => frame.type === 'session.event' && frame.payload.type === 'assistant/message')
  const settled = await mobile.wait(frame => frame.type === 'session.event' && frame.payload.type === 'turn/end')
  unrelatedMobile.send({ v: 1, type: 'ping', payload: {} })
  await unrelatedMobile.wait(frame => frame.type === 'pong')
  assert.equal(unrelatedMobile.frames.some(frame => frame.type === 'command.receipt'), false, 'command metadata leaked to a socket scoped to another workspace')
  const status = await phone('GET', `/v1/commands/${requestId}?device_id=${device.device_id}`)
  assert.equal(status.state, 'agent_queued')
  assert.equal(status.payload_sha256, relayPayloadDigest(sessionId, payload))
  const retryFrom = mobile.frames.length
  mobile.send(submit)
  await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === requestId && frame.payload.state === 'agent_queued', retryFrom)
  mobile.send({ ...submit, payload: { ...payload, content: [{ type: 'text', text: 'changed content' }] } })
  await mobile.wait(frame => frame.type === 'error' && frame.request_id === requestId && frame.payload.code === 'command.request_conflict')

  const replacementRequest = subscribe()
  const replacement = await mobile.wait(frame => frame.type === 'session.snapshot' && frame.request_id === replacementRequest)
  assert.notEqual(replacement.sync_id, opening.sync_id)
  assert.ok(replacement.payload.cursor >= settled.payload.native_seq)
  assert.equal(replacement.payload.records.filter((record: any) => record.type === 'user/message' && JSON.stringify(record.data).includes(marker)).length, 1, 'retry duplicated the native DSH message')
  const pageRequest = randomUUID()
  const page = { v: 1, type: 'session.page', request_id: pageRequest, runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch,
    session_id: sessionId, subscription_id: replacement.subscription_id, payload: { sync_id: replacement.sync_id, through_seq: replacement.payload.cursor, before_seq: replacement.payload.cursor + 1, max_messages: 30 } }
  mobile.send(page)
  const history = await mobile.wait(frame => frame.type === 'session.page.result' && frame.request_id === pageRequest)
  assert.ok(JSON.stringify(history.payload.records).includes(marker))
  assert.equal(history.payload.through_seq, replacement.payload.cursor)
  const badPageId = randomUUID()
  mobile.send({ ...page, request_id: badPageId, payload: { ...page.payload, through_seq: replacement.payload.cursor - 1, before_seq: replacement.payload.cursor } })
  await mobile.wait(frame => frame.type === 'session.error' && frame.request_id === badPageId && frame.payload.code === 'protocol.resync_required')
  mobile.send({ v: 1, type: 'session.unsubscribe', request_id: randomUUID(), runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch,
    session_id: sessionId, subscription_id: opening.subscription_id, payload: {} })
  await mobile.wait(frame => frame.type === 'session.unsubscribed' && frame.subscription_id === opening.subscription_id)

  const cancelableFrom = mobile.frames.length, cancelableRequest = randomUUID()
  const cancelMarker = `REMOTE_CANCEL_WAIT_${randomUUID()}`
  mobile.send({ ...submit, request_id: cancelableRequest, payload: { mode: 'queue', content: [{ type: 'text', text: cancelMarker }] } })
  await mobile.wait(frame => frame.type === 'assistant.chunk' && JSON.stringify(frame.payload).includes('Cancelable model call is waiting'), cancelableFrom)
  const cancelId = randomUUID(), cancelAt = Date.now()
  const cancel = { v: 1, type: 'session.cancel', request_id: cancelId, runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch, session_id: sessionId, payload: {} }
  const staleCancelId = randomUUID()
  mobile.send({ ...cancel, request_id: staleCancelId, runtime_epoch: randomUUID() })
  await mobile.wait(frame => frame.type === 'error' && frame.request_id === staleCancelId && frame.payload.code === 'runtime.changed')
  mobile.send(cancel)
  for (const state of ['received', 'host_accepted', 'dispatching', 'settled']) {
    const receipt = await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === cancelId && frame.payload.state === state)
    assert.equal(receipt.payload.payload_sha256, relayCancelDigest(sessionId, probe.runtime_epoch))
  }
  const canceledTurn = await mobile.wait(frame => frame.type === 'session.event' && frame.payload.type === 'turn/end', cancelableFrom)
  const cancelLatency = Date.now() - cancelAt
  assert.ok(cancelLatency < 5000, 'remote cancel did not interrupt the held model call')
  assert.equal(canceledTurn.payload.data.reason.kind, 'aborted')
  const partialMessages = mobile.frames.slice(cancelableFrom).filter(frame => frame.type === 'session.event' && frame.payload.type === 'assistant/message')
  assert.ok(partialMessages.every(frame => frame.payload.data.interrupted === true), 'canceled model call published a non-interrupted message')
  assert.equal(JSON.stringify(partialMessages).includes('Unexpected uncanceled completion'), false)
  const cancelRetryFrom = mobile.frames.length
  mobile.send(cancel)
  await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === cancelId && frame.payload.state === 'settled', cancelRetryFrom)
  assert.equal((await phone('GET', `/v1/commands/${cancelId}?device_id=${device.device_id}`)).state, 'settled')
  assert.equal(query(`select count(*) from commands where request_id='${cancelId}'`), '1')
  assert.equal(query(`select count(*) from commands where request_id='${staleCancelId}'`), '0')

  const archiveCommand = (archived: boolean, stopActivity = false) => ({
    v: 1, type: 'session.archive', request_id: randomUUID(), runtime_id: enrollment.runtime_id,
    runtime_epoch: probe.runtime_epoch, session_id: sessionId, payload: archived
      ? { archived: true as const, stop_activity: stopActivity } : { archived: false as const, stop_activity: false as const },
  })
  const archiveAndWait = async (frame: ReturnType<typeof archiveCommand>, state = 'settled') => {
    const from = mobile.frames.length
    mobile.send(frame)
    const receipt = await mobile.wait(item => item.type === 'command.receipt' && item.request_id === frame.request_id && item.payload.state === state, from)
    assert.equal(receipt.payload.payload_sha256, relayArchiveDigest(sessionId, probe.runtime_epoch, frame.payload))
    assert.equal((await phone('GET', `/v1/commands/${frame.request_id}?device_id=${device.device_id}`)).state, state)
  }
  const catalogState = async (state: string) => until(async () => {
    const rows = (await phone('GET', `/v1/runtimes/${enrollment.runtime_id}/sessions`)).items
    return rows.find((row: any) => row.session_id === sessionId && row.state === state)
  }, `native catalog ${state}`)
  const archive = archiveCommand(true)
  await archiveAndWait(archive)
  await catalogState('archived')
  const archivedReadId = subscribe()
  const archivedRead = await mobile.wait(frame => frame.type === 'session.snapshot' && frame.request_id === archivedReadId)
  assert.ok(JSON.stringify(archivedRead.payload.records).includes(marker), 'archive discarded native history')
  const deniedArchivedId = randomUUID()
  mobile.send({ ...submit, request_id: deniedArchivedId })
  await mobile.wait(frame => frame.type === 'error' && frame.request_id === deniedArchivedId && frame.payload.code === 'access.denied')
  await archiveAndWait(archiveCommand(false))
  await catalogState('available')
  await archiveAndWait(archive)
  assert.equal((await command('session.list', {})).payload.items.find((item: any) => item.session_id === sessionId).archived, false, 'settled retry changed current desktop state')
  const archiveActiveFrom = mobile.frames.length
  const archiveStopMarker = `REMOTE_CANCEL_WAIT_${randomUUID()}`
  mobile.send({ ...submit, request_id: randomUUID(), payload: { mode: 'queue', content: [{ type: 'text', text: archiveStopMarker }] } })
  await mobile.wait(frame => frame.type === 'assistant.chunk' && JSON.stringify(frame.payload).includes('Cancelable model call is waiting'), archiveActiveFrom)
  await archiveAndWait(archiveCommand(true), 'rejected')
  assert.equal((await command('session.list', {})).payload.items.find((item: any) => item.session_id === sessionId).archived, false)
  await archiveAndWait(archiveCommand(true, true))
  const archiveStoppedTurn = await mobile.wait(frame => frame.type === 'session.event' && frame.payload.type === 'turn/end', archiveActiveFrom)
  assert.equal(archiveStoppedTurn.payload.data.reason.kind, 'aborted')
  await catalogState('archived')
  await archiveAndWait(archiveCommand(false))
  await catalogState('available')
  mobile.send({ v: 1, type: 'session.unsubscribe', request_id: randomUUID(), runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch,
    session_id: sessionId, subscription_id: archivedRead.subscription_id, payload: {} })
  await mobile.wait(frame => frame.type === 'session.unsubscribed' && frame.subscription_id === archivedRead.subscription_id)

  const siblingMobile = await connectPhone(siblingPhone, siblingDevice.device_id, siblingKey)
  const questionFrom = mobile.frames.length, questionPromptId = randomUUID(), questionMarker = `M0_QUESTION_TEST_${randomUUID()}`
  mobile.send({ ...submit, request_id: questionPromptId, payload: { mode: 'queue', content: [{ type: 'text', text: questionMarker }] } })
  const questionState = await mobile.wait(frame => frame.type === 'question.snapshot' && frame.payload.items.length > 0, questionFrom)
  const question = questionState.payload.items[0]
  assert.match(question.question_id,/^[0-9a-f-]{36}$/)
  await until(async()=>query(`select state from question_references where id='${question.question_id}'`)==='pending'?true:undefined,'ordinary question metadata publication')
  assert.equal(question.questions[0].id, 'm0-choice')
  const answerMarker = `REMOTE_ANSWER_${randomUUID()}`
  const questionAnswer = { v: 1, type: 'question.answer', request_id: randomUUID(), runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch, session_id: sessionId,
    payload: { question_id: question.question_id, answers: [{ id: 'm0-choice', selected: ['Local answer'], custom: answerMarker }] } }
  const invalidAnswerId = randomUUID()
  mobile.send({ ...questionAnswer, request_id: invalidAnswerId, payload: { ...questionAnswer.payload, answers: [{ id: 'm0-choice', selected: ['invented'] }] } })
  await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === invalidAnswerId && frame.payload.state === 'rejected')
  assert.equal(mobile.closed, false, 'invalid question answer disconnected subscriptions')
  const competingAnswer = { ...questionAnswer, request_id: randomUUID() }
  mobile.send(questionAnswer)
  siblingMobile.send(competingAnswer)
  const terminal = (collector: FrameCollector, id: string) => collector.wait(frame => frame.type === 'command.receipt' && frame.request_id === id && ['settled', 'rejected'].includes(frame.payload.state))
  const results = await Promise.all([terminal(mobile, questionAnswer.request_id), terminal(siblingMobile, competingAnswer.request_id)])
  assert.deepEqual(results.map(frame => frame.payload.state).sort(), ['rejected', 'settled'], 'multiple devices completed the same question')
  const winner = results[0].payload.state === 'settled' ? { collector: mobile, answer: questionAnswer } : { collector: siblingMobile, answer: competingAnswer }
  const knownTarget=await phone('GET',`/v1/runtimes/${enrollment.runtime_id}/sessions/${sessionId}`)
  assert.equal(knownTarget.runtime.id,enrollment.runtime_id);assert.equal(knownTarget.session.session_id,sessionId)
  assert.ok(!JSON.stringify(knownTarget).includes('dsh_session_id'))
  const answerPhone=results[0].payload.state==='settled'?phone:siblingPhone
  const ownAnswer=await answerPhone('GET',`/v1/runtimes/${enrollment.runtime_id}/sessions/${sessionId}/question-answers/${winner.answer.request_id}`)
  assert.equal(ownAnswer.state,'settled');assert.equal(ownAnswer.payload_sha256,relayQuestionDigest(sessionId,probe.runtime_epoch,winner.answer.payload))
  const answerRetryFrom = winner.collector.frames.length
  winner.collector.send(winner.answer)
  const retriedAnswer = await winner.collector.wait(frame => frame.type === 'command.receipt' && frame.request_id === winner.answer.request_id && frame.payload.state === 'settled', answerRetryFrom)
  assert.equal(retriedAnswer.payload.payload_sha256, relayQuestionDigest(sessionId, probe.runtime_epoch, winner.answer.payload))
  await mobile.wait(frame => frame.type === 'question.snapshot' && frame.payload.revision > questionState.payload.revision && frame.payload.items.length === 0, questionFrom)
  await mobile.wait(frame => frame.type === 'session.event' && frame.payload.type === 'turn/end', questionFrom)
  assert.equal((await phone('GET', `/v1/commands/${questionAnswer.request_id}?device_id=${device.device_id}`)).state, results[0].payload.state)

  const timedSecrets: string[] = []
  const timedCreationId = randomUUID()
  mobile.send({ ...creation, request_id: timedCreationId, payload: { ...creation.payload, preset: 'remote-timed' } })
  const timedCreated = await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === timedCreationId && frame.payload.state === 'settled')
  const timedSessionId = timedCreated.session_id
  const timedSubscriptionId = randomUUID()
  mobile.send({ v: 1, type: 'session.subscribe', request_id: timedSubscriptionId, runtime_id: enrollment.runtime_id, session_id: timedSessionId, payload: {} })
  const timedOpening = await mobile.wait(frame => frame.type === 'session.snapshot' && frame.request_id === timedSubscriptionId)
  const timedEnvelope = { v: 1, runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch, session_id: timedSessionId,
    subscription_id: timedOpening.subscription_id, sync_id: timedOpening.sync_id }
  const promptTimed = async (mode: string) => {
    const marker = `REMOTE_TIMED_${mode}_${randomUUID()}`, from = mobile.frames.length
    timedSecrets.push(marker)
    mobile.send({ ...submit, request_id: randomUUID(), session_id: timedSessionId, payload: { mode: 'queue', content: [{ type: 'text', text: marker }] } })
    const state = await mobile.wait(frame => frame.type === 'question.timed.snapshot' && frame.session_id === timedSessionId && frame.payload.items.some((item: any) => item.state === 'open'), from)
    return { from, question: state.payload.items.find((item: any) => item.state === 'open') }
  }
  const claimTimed = async (questionId: string) => {
    const request = { ...timedEnvelope, type: 'question.claim', request_id: randomUUID(), payload: { question_id: questionId } }
    mobile.send(request)
    const frame = await mobile.wait(frame => frame.type === 'question.claimed' && frame.request_id === request.request_id)
    assert.equal(frame.payload.question_id, questionId)
    assert.ok(frame.payload.remaining_ms >= 0)
    return request
  }
  const answerTimed = async (questionId: string, expected: 'settled' | 'agent_queued') => {
    const marker = `REMOTE_TIMED_ANSWER_${randomUUID()}`, from = mobile.frames.length
    timedSecrets.push(marker)
    const request = { v: 1, type: 'question.timed.answer', request_id: randomUUID(), runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch, session_id: timedSessionId,
      payload: { question_id: questionId, answers: [{ id: 'timed-choice', selected: ['Reply'], custom: marker }] } }
    mobile.send(request)
    const receipt = await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === request.request_id && frame.payload.state === expected, from)
    assert.equal(receipt.payload.payload_sha256, relayTimedQuestionDigest(timedSessionId, probe.runtime_epoch, request.payload))
    const retryFrom = mobile.frames.length
    mobile.send(request)
    await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === request.request_id && frame.payload.state === expected, retryFrom)
    if (expected === 'agent_queued') await mobile.wait(frame => frame.type === 'session.event' && frame.session_id === timedSessionId && frame.payload.type === 'user/message' && JSON.stringify(frame.payload.data).includes(marker), from)
    await mobile.wait(frame => frame.type === 'session.event' && frame.session_id === timedSessionId && frame.payload.type === 'turn/end', from)
    assert.equal((await phone('GET', `/v1/commands/${request.request_id}?device_id=${device.device_id}`)).state, expected)
  }
  const foreground = await promptTimed('FOREGROUND')
  const foregroundClaim = await claimTimed(foreground.question.question_id)
  siblingMobile.send({ ...foregroundClaim, request_id: randomUUID() })
  await siblingMobile.wait(frame => frame.type === 'error' && frame.payload.code === 'protocol.resync_required')
  await answerTimed(foreground.question.question_id, 'settled')
  await mobile.wait(frame => frame.type === 'question.claim.closed' && frame.request_id === foregroundClaim.request_id)
  const released = await promptTimed('RELEASE')
  const releasedClaim = await claimTimed(released.question.question_id)
  const releaseId = randomUUID()
  mobile.send({ ...timedEnvelope, type: 'question.release', request_id: releaseId, payload: { claim_id: releasedClaim.request_id } })
  await mobile.wait(frame => frame.type === 'question.released' && frame.request_id === releaseId)
  mobile.send(releasedClaim)
  await mobile.wait(frame => frame.type === 'error' && frame.request_id === releasedClaim.request_id && frame.payload.code === 'rate.limited')
  await mobile.wait(frame => frame.type === 'question.timed.snapshot' && frame.payload.items.some((item: any) => item.question_id === released.question.question_id && item.state === 'continued'), released.from)
  await answerTimed(released.question.question_id, 'agent_queued')
  const unattended = await promptTimed('LATE')
  await mobile.wait(frame => frame.type === 'question.timed.snapshot' && frame.payload.items.some((item: any) => item.question_id === unattended.question.question_id && item.state === 'continued'), unattended.from)
  await answerTimed(unattended.question.question_id, 'agent_queued')
  await mobile.wait(frame => frame.type === 'question.timed.snapshot' && frame.session_id === timedSessionId && frame.payload.items.length === 0, unattended.from)

  // Remove the timed session's only phone subscription before producing another
  // native question. Its background reference must come from the runtime feed.
  mobile.send({v:1,type:'session.unsubscribe',request_id:randomUUID(),runtime_id:enrollment.runtime_id,runtime_epoch:probe.runtime_epoch,
    session_id:timedSessionId,subscription_id:timedOpening.subscription_id,payload:{}})
  await mobile.wait(frame=>frame.type==='session.unsubscribed' && frame.subscription_id===timedOpening.subscription_id)
  const backgroundFrom=mobile.frames.length, backgroundPrompt=randomUUID(), backgroundMarker=`REMOTE_TIMED_BACKGROUND_${randomUUID()}`
  timedSecrets.push(backgroundMarker)
  mobile.send({...submit,request_id:backgroundPrompt,session_id:timedSessionId,payload:{mode:'queue',content:[{type:'text',text:backgroundMarker}]}})
  await mobile.wait(frame=>frame.type==='command.receipt' && frame.request_id===backgroundPrompt && frame.payload.state==='agent_queued',backgroundFrom)
  const backgroundQuestion=await until(async()=>{
    const id=query(`select id::text from question_references where session_id='${timedSessionId}' and kind='timed_question' and state='continued'
      and id not in ('${foreground.question.question_id}','${released.question.question_id}','${unattended.question.question_id}') limit 1`)
    return id || undefined
  },'timed question publication without a foreground subscription')
  assert.match(backgroundQuestion,/^[0-9a-f-]{36}$/)
  assert.ok(!mobile.frames.slice(backgroundFrom).some(frame=>frame.type==='question.timed.snapshot' && frame.payload.items.some((item:any)=>item.question_id===backgroundQuestion)))
  const reopenedTimed=randomUUID()
  mobile.send({v:1,type:'session.subscribe',request_id:reopenedTimed,runtime_id:enrollment.runtime_id,session_id:timedSessionId,payload:{}})
  await mobile.wait(frame=>frame.type==='session.snapshot' && frame.request_id===reopenedTimed,backgroundFrom)
  await mobile.wait(frame=>frame.type==='question.timed.snapshot' && frame.payload.items.some((item:any)=>item.question_id===backgroundQuestion && item.state==='continued'),backgroundFrom)
  await answerTimed(backgroundQuestion,'agent_queued')
  await until(async()=>query(`select state from question_references where id='${backgroundQuestion}'`)==='ended'?true:undefined,'answered background question ended')

  const approvalSecrets: string[] = []
  for (const choice of ['ALLOW', 'REJECT', 'CANCEL'] as const) {
    const from = mobile.frames.length, promptID = randomUUID(), approvalMarker = `REMOTE_APPROVAL_${choice}_${randomUUID()}`
    approvalSecrets.push(approvalMarker)
    mobile.send({ ...submit, request_id: promptID, payload: { mode: 'queue', content: [{ type: 'text', text: approvalMarker }] } })
    const pending = await mobile.wait(frame => frame.type === 'approval.reference' && frame.session_id === sessionId && frame.payload.status.state === 'pending', from)
    const approvalID = pending.payload.status.approval_id
    const detailsID = randomUUID()
    mobile.send({ v: 1, type: 'approval.details.get', request_id: detailsID, runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch, session_id: sessionId, payload: { approval_id: approvalID } })
    const detail = await mobile.wait(frame => frame.type === 'approval.details' && frame.request_id === detailsID, from)
    const context = detail.payload.context as ApprovalContext
    const binding = approvalBinding(context)
    assert.equal(context.approval_id, approvalID)
    assert.equal(context.tool, 'bash')
    assert.equal(context.workspace.workspace_id, enrollment.workspaces[0].workspace_id)
    assert.equal(binding.sha256, pending.payload.status.binding_sha256)
    const sentinel = join(workspace, `approval-${choice.toLowerCase()}.txt`)
    const commandText = (context.arguments as { command: string }).command
    approvalSecrets.push(commandText)
    assert.ok(commandText.includes(`approval-${choice.toLowerCase()}.txt`))
    if (choice === 'CANCEL') {
      const id = randomUUID()
      mobile.send({ v: 1, type: 'session.cancel', request_id: id, runtime_id: enrollment.runtime_id, runtime_epoch: probe.runtime_epoch, session_id: sessionId, payload: {} })
      await mobile.wait(frame => frame.type === 'command.receipt' && frame.request_id === id && frame.payload.state === 'settled', from)
      await mobile.wait(frame => frame.type === 'approval.reference' && frame.payload.status.approval_id === approvalID && frame.payload.status.host_state === 'cancelled', from)
      await assert.rejects(readFile(sentinel), { code: 'ENOENT' })
    } else {
      const decision: ApprovalDecision = { domain: 'dsh-mobile-ustc/approval-decision/v1', protocol_version: 1,
        host_id: context.host_id, installation_id: context.installation_id, runtime_id: context.runtime_id, runtime_epoch: context.runtime_epoch,
        session_id: context.session_id, approval_id: context.approval_id, execution_id: context.execution_id, binding_sha256: binding.sha256,
        decision: choice === 'ALLOW' ? 'allow_once' : 'reject', user_id: phoneUserId, device_id: device.device_id, key_version: device.key_version,
        policy_version: context.policy_version, nonce: context.nonce, issued_at: new Date().toISOString(), expires_at: context.expires_at }
      const proof = await new CompactSign(canonicalObject(decision)).setProtectedHeader({ alg: 'ES256', kid: approvalKeyID(device.device_id, device.key_version), typ: APPROVAL_JWS_TYPE }).sign(approvalKey.privateKey)
      const connection = mobile.frames.find(frame => frame.type === 'hello.ok').payload.connection_id
      if (choice === 'ALLOW') {
        const parts = proof.split('.'); parts[2] = (parts[2]![0] === 'A' ? 'B' : 'A') + parts[2]!.slice(1)
        await phone('POST', `/v1/approvals/${approvalID}/decisions`, { connection_id: connection, decision_jws: parts.join('.') }, 400)
        assert.equal(query(`select state from approvals where id='${approvalID}'`), 'pending')
        await assert.rejects(readFile(sentinel), { code: 'ENOENT' })
      }
      const accepted = await phone('POST', `/v1/approvals/${approvalID}/decisions`, { connection_id: connection, decision_jws: proof })
      assert.equal(accepted.delivery, 'forwarded')
      const expected = choice === 'ALLOW' ? 'settled' : 'denied'
      const observed = await mobile.wait(frame => frame.type === 'approval.reference' && frame.payload.status.approval_id === approvalID && frame.payload.status.host_state === expected, from)
      if (choice === 'ALLOW') {
        assert.equal(observed.payload.status.execution_outcome, 'succeeded')
        assert.equal(await readFile(sentinel, 'utf8'), 'authorized', 'the protected native Bash ran more than once')
        const retry = await phone('POST', `/v1/approvals/${approvalID}/decisions`, { connection_id: connection, decision_jws: proof })
        assert.equal(retry.delivery, 'recorded')
        assert.equal(await readFile(sentinel, 'utf8'), 'authorized')
      } else await assert.rejects(readFile(sentinel), { code: 'ENOENT' })
    }
    await mobile.wait(frame => frame.type === 'session.event' && frame.session_id === sessionId && frame.payload.type === 'turn/end', from)
    await until(async () => query(`select count(*) from audit_log where action='approval.result' and metadata->>'approval_id'='${approvalID}'`) !== '0' ? true : undefined, 'native approval result audit')
  }

  const dump = execFileSync(pgDump, ['--dbname', database, '--data-only', '--no-owner'], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 })
  for (const secret of [marker, cancelMarker, archiveStopMarker, questionMarker, answerMarker, ...timedSecrets, ...approvalSecrets, 'Answer the timed DSH fixture question.', 'Choose the local DSH fixture answer.', 'DSH local integration fixture response', 'Cancelable model call is waiting', workspace, code, credential.credential, ticket.ticket]) {
    assert.equal(dump.includes(secret), false, 'Relay persisted a session body, local path or raw credential')
  }
  assert.equal(query(`select count(*) from commands where request_id='${requestId}'`), '1')
  const deviceRevokedAt = Date.now()
  await phone('DELETE', `/v1/devices/${siblingDevice.device_id}`)
  assert.equal((await siblingPhone('GET', '/v1/devices/current')).state, 'revoked')
  await siblingMobile.wait(frame => frame.type === 'access.revoked' && frame.payload.code === 'access.revoked')
  await until(async () => siblingMobile.closed ? true : undefined, 'idle revoked device socket close', 5000)
  assert.ok(Date.now() - deviceRevokedAt < 5000, 'idle device revocation exceeded five seconds')
  assert.equal(mobile.closed, false, 'revoking a sibling device closed the primary phone')
  const survivingPageId = randomUUID(), survivingPageFrom = mobile.frames.length
  mobile.send({ ...page, request_id: survivingPageId })
  await mobile.wait(frame => frame.type === 'session.page.result' && frame.request_id === survivingPageId, survivingPageFrom)
  const revokePreparationFrom = mobile.frames.length
  const revokeMarker=`REMOTE_APPROVAL_REVOKE_${randomUUID()}`,revokePromptId=randomUUID()
  mobile.send({...submit,request_id:revokePromptId,payload:{mode:'queue',content:[{type:'text',text:revokeMarker}]}})
  const revokePending=await mobile.wait(frame=>frame.type==='approval.reference'&&frame.session_id===sessionId&&frame.payload.status.state==='pending',revokePreparationFrom)
  const revokeApprovalId=revokePending.payload.status.approval_id,revokeDetailsId=randomUUID()
  mobile.send({v:1,type:'approval.details.get',request_id:revokeDetailsId,runtime_id:enrollment.runtime_id,runtime_epoch:probe.runtime_epoch,session_id:sessionId,payload:{approval_id:revokeApprovalId}})
  const revokeContext=(await mobile.wait(frame=>frame.type==='approval.details'&&frame.request_id===revokeDetailsId,revokePreparationFrom)).payload.context as ApprovalContext
  const revokeDecision:ApprovalDecision={domain:'dsh-mobile-ustc/approval-decision/v1',protocol_version:1,host_id:revokeContext.host_id,installation_id:revokeContext.installation_id,runtime_id:revokeContext.runtime_id,
    runtime_epoch:revokeContext.runtime_epoch,session_id:revokeContext.session_id,approval_id:revokeContext.approval_id,execution_id:revokeContext.execution_id,binding_sha256:approvalBinding(revokeContext).sha256,
    decision:'allow_once',user_id:phoneUserId,device_id:device.device_id,key_version:device.key_version,policy_version:revokeContext.policy_version,nonce:revokeContext.nonce,issued_at:new Date().toISOString(),expires_at:revokeContext.expires_at}
  const revokeProof=await new CompactSign(canonicalObject(revokeDecision)).setProtectedHeader({alg:'ES256',kid:approvalKeyID(device.device_id,device.key_version),typ:APPROVAL_JWS_TYPE}).sign(approvalKey.privateKey)
  const primaryConnection=mobile.frames.find(frame=>frame.type==='hello.ok').payload.connection_id
  assert.equal((await phone('POST',`/v1/approvals/${revokeApprovalId}/decisions`,{connection_id:primaryConnection,decision_jws:revokeProof})).delivery,'forwarded')
  await until(async()=>{try{await readFile(join(workspace,'approval-revoke-held'));return true}catch{return undefined}},'approved Bash held after native guard')
  const revokeLeaseExpiry=Date.parse(query(`select metadata->>'expires_at' from audit_log where action='approval.authorization.prepare' and metadata->>'approval_id'='${revokeApprovalId}' order by id desc limit 1`))
  await assert.rejects(readFile(join(workspace,'approval-revoke.txt')),{code:'ENOENT'})
  const revokedFrom = mobile.frames.length
  const grantRevokedAt = Date.now()
  await phone('DELETE', `/v1/runtimes/${enrollment.runtime_id}/grants/${phoneUserId}`)
  await mobile.wait(frame => frame.type === 'access.revoked' && frame.payload.code === 'access.revoked', revokedFrom)
  await until(async () => mobile.closed ? true : undefined, 'idle revoked grant socket close', 5000)
  assert.ok(Date.now() - grantRevokedAt < 5000, 'idle grant revocation exceeded five seconds')
  await until(async()=>query(`select host_state from approvals where id='${revokeApprovalId}'`)==='invalidated'?true:undefined,'host invalidated approved but unstarted execution',2500)
  assert.ok(Date.now()<revokeLeaseExpiry,'host waited for lease expiry instead of processing scoped revocation')
  await assert.rejects(readFile(join(workspace,'approval-revoke.txt')),{code:'ENOENT'})
  const revokedDump=execFileSync(pgDump,['--dbname',database,'--data-only','--no-owner'],{encoding:'utf8',maxBuffer:4*1024*1024})
  for(const secret of [revokeMarker,(revokeContext.arguments as {command:string}).command])assert.equal(revokedDump.includes(secret),false)
  const revocationNotice = mobile.frames.findIndex((frame,index)=>index>=revokedFrom&&frame.type==='access.revoked')
  assert.ok(revocationNotice>=revokedFrom)
  // A frame already authorized/queued before the grant transaction may arrive
  // during the DELETE round trip. Nothing may follow the ordered revoke marker.
  assert.equal(mobile.frames.slice(revocationNotice+1).some(frame => ['session.event', 'assistant.chunk'].includes(frame.type)), false, 'revoked phone received content after its revocation marker')
  await until(async () => query(`select count(*) from control_outbox where published_at is null and topic in ('device.revoked','runtime_grant.updated','runtime_grant.revoked')`) === '0' ? true : undefined, 'control outbox acknowledgement')
  await phone('POST', '/v1/realtime/tickets', { runtime_id: enrollment.runtime_id, scope }, 403)
  const finalMetrics = await until(async () => {
    const body = await readMetrics()
    return metricSample(body, 'relay_revoked_connections_total', { reason: 'access_revoked', role: 'device' }) >= 2 &&
      metricSample(body, 'control_event_age_seconds_count', { topic: 'runtime_grant.revoked' }) >= 1 ? body : undefined
  }, 'measured revocation propagation')
  assert.ok(metricSample(finalMetrics, 'relay_received_frames_total', { role: 'installation' }) > 20)
  assert.ok(metricSample(finalMetrics, 'relay_written_frames_total', { role: 'device' }) > 20)
  assert.ok(metricSample(finalMetrics, 'relay_session_route_duration_seconds_count') > 0)
  assert.ok(metricSample(finalMetrics, 'command_forward_duration_seconds_count', { result: 'forwarded' }) > 0)
  assert.ok(metricSample(finalMetrics, 'command_forward_duration_seconds_count', { result: 'duplicate' }) > 0)
  for (const secret of [orgId, ownerId, phoneUserId, device.device_id, enrollment.runtime_id, sessionId, revokeMarker, revokeProof,
    (revokeContext.arguments as { command: string }).command]) assert.equal(finalMetrics.includes(secret), false, 'metrics exposed identity, body or proof')
  t.diagnostic('Private Prometheus endpoint observed actual signed Host/phone connections, native traffic, command forwarding/retries and completed local revocation propagation without resource IDs, bodies or proofs.')
  t.diagnostic(`Device/grant revocations closed their sockets within five seconds; last grant closed after ${Date.now() - grantRevokedAt} ms. Durable control outbox acknowledged.`)
  t.diagnostic('A real Bash approved through the normal plugin was held after guard; scoped grant invalidation blocked its body before the three-second lease expired and durably reported the invalidated fact.')
  t.diagnostic(`Remote cancellation interrupted the held model call after ${cancelLatency} ms; stale epoch rejected and settled retry preserved.`)
  t.diagnostic('Native archive/restore persisted through the Go relay: archived history remained readable, writes were denied, busy archive refused, explicit archive-and-stop aborted the held turn, and a historical settled retry did not undo a later restore.')
  t.diagnostic('Blocking question snapshots, invalid-answer rejection, two-device answer competition and durable retry passed without storing question/answer bodies.')
  t.diagnostic('Native timed-question foreground claim/answer, release, retired-ID denial, unattended continuation and durable late-message admission passed through Go Relay.')
  t.diagnostic('Normal Host runtime question metadata reached PostgreSQL without a timed-session phone subscription; fresh resubscription found the same continued native question and admitted one late answer. Full database dump excluded question and answer bodies.')
  t.diagnostic('The normal plugin negotiated signed approval: current Bash context, invalid-proof nonconsumption, phone allow/reject/cancel, one actual execution, duplicate decision reconciliation and durable native result reporting passed through the real Go service.')
  t.diagnostic('Go production entrypoint + isolated PostgreSQL + npm DSH 0.2.1-rc.2: signed enrollment/credentials/ticket, session creation, catalog, snapshots, assistant stream, pagination, idempotency, scoped receipts, cancellation, questions, body-storage boundary and proactive revocation passed. Identity and model are local fixtures; Android and production IdP are not involved.')
})
