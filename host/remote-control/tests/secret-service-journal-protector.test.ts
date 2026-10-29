import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createDecipheriv, createHmac, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto'
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { inspect } from 'node:util'
import { pathToFileURL } from 'node:url'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { parseCommand } from '../src/protocol.js'
import { LinuxSecretServiceJournalProtector } from '../src/secret-service-journal-protector.js'

const service = 'cn.edu.ustc.dsh.journal'
const account = 'fixture-account'
const owner = { userId: 'fixture-user', deviceId: 'fixture-device' }
const context = Buffer.from('fixture-journal-binding')

async function fixture(t: test.TestContext, body?: string) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-secret-service-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const master = randomBytes(32), secret = join(root, 'secret'), calls = join(root, 'calls'), executable = join(root, 'secret-tool')
  t.after(() => master.fill(0))
  await writeFile(secret, master.toString('base64'), { mode: 0o600 })
  const script = body ?? `const fs=require('node:fs');fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify(process.argv.slice(2))+'\\n');if(JSON.stringify(process.argv.slice(2))!==JSON.stringify(['lookup','service',${JSON.stringify(service)},'account',${JSON.stringify(account)}]))process.exit(2);process.stdout.write(fs.readFileSync(${JSON.stringify(secret)},'utf8')+'\\n')`
  await writeFile(executable, `#!/usr/bin/env node\n${script}\n`, { mode: 0o700 })
  const protector = new LinuxSecretServiceJournalProtector({ executable, service, account })
  return { root, master, secret, calls, executable, protector }
}

function command(text: string) {
  return parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: randomUUID(),
    session_id: '55555555-5555-4555-8555-555555555555', payload: { mode: 'queue', text } })
}

test('Secret Service protector wraps with the preprovisioned key and authenticated context', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const key = randomBytes(32)
  t.after(() => key.fill(0))
  const wrapped = Buffer.from(await f.protector.wrap(key, context, AbortSignal.timeout(2_000)))
  assert.equal(wrapped.length, 100)
  assert.equal(wrapped.includes(key), false)
  const derived = createHmac('sha256', f.master).update('dsh-secret-service-journal-wrap-v1\0').update(wrapped.subarray(8, 40)).digest()
  const decipher = createDecipheriv('aes-256-gcm', derived, wrapped.subarray(40, 52))
  decipher.setAAD(Buffer.concat([context, wrapped.subarray(0, 52)]))
  decipher.setAuthTag(wrapped.subarray(84, 100))
  const clear = Buffer.concat([decipher.update(wrapped.subarray(52, 84)), decipher.final()])
  assert.deepEqual(clear, key)
  clear.fill(0); derived.fill(0)
  const reopened = Buffer.from(await f.protector.unwrap(wrapped, context, AbortSignal.timeout(2_000)))
  assert.deepEqual(reopened, key)
  reopened.fill(0)
  await assert.rejects(f.protector.unwrap(wrapped, Buffer.from('wrong-binding'), AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  const damaged = Buffer.from(wrapped)
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1
  await assert.rejects(f.protector.unwrap(damaged, context, AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  const loggedArgs = await readFile(f.calls, 'utf8')
  assert.equal(loggedArgs.includes(f.master.toString('base64')), false)
  for (const rendered of [String(f.protector), inspect(f.protector), JSON.stringify(f.protector)]) {
    assert.equal(rendered.includes(f.executable), false)
    assert.equal(rendered.includes(service), false)
    assert.equal(rendered.includes(account), false)
    assert.equal(rendered.includes(f.master.toString('base64')), false)
  }
})

test('Secret Service protector opens and reopens a protected journal without a raw key file', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const path = join(f.root, 'commands.sqlite'), runtime = randomUUID(), input = command('PRIVATE_SECRET_SERVICE_COMMAND')
  let journal = await PersistentCommandJournal.open(path, runtime, { protector: f.protector })
  journal.admit(input, owner)
  journal.close()
  await assert.rejects(lstat(`${path}.key`), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  assert.equal((await lstat(`${path}.wrapped-key`)).mode & 0o777, 0o600)
  assert.equal((await readFile(`${path}.wrapped-key`)).includes(f.master), false)
  journal = await PersistentCommandJournal.open(path, runtime, { protector: f.protector })
  assert.deepEqual(journal.get(input.request_id, owner)?.command, input)
  journal.close()
  await writeFile(f.secret, randomBytes(32).toString('base64'), { mode: 0o600 })
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: f.protector }), /key protection unavailable/)
  await assert.rejects(lstat(`${path}.key`), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  await writeFile(f.secret, f.master.toString('base64'), { mode: 0o600 })
  journal = await PersistentCommandJournal.open(path, runtime, { protector: f.protector })
  assert.deepEqual(journal.get(input.request_id, owner)?.command, input)
  journal.close()
})

test('Secret Service errors and noncanonical secrets fail without exposing subprocess output', { skip: process.platform !== 'linux' }, async t => {
  const cases = [
    `process.stderr.write('PRIVATE_SECRET_TOOL_ERROR');process.exit(1)`,
    `process.stdout.write('not-base64\\n')`,
    `process.stdout.write('A'.repeat(512))`,
    `process.stdout.write('A'.repeat(42)+'B=\\n')`,
  ]
  for (const body of cases) {
    const f = await fixture(t, body)
    await assert.rejects(f.protector.wrap(randomBytes(32), context, AbortSignal.timeout(2_000)), error => error instanceof Error && /Secret Service protection unavailable/.test(error.message) && !error.message.includes('PRIVATE_SECRET_TOOL_ERROR'))
  }
})

test('Secret Service executable must be an owned non-writable regular file in a protected parent', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  await chmod(f.executable, 0o722)
  await assert.rejects(f.protector.wrap(randomBytes(32), context, AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  await chmod(f.executable, 0o700)
  await chmod(f.executable, 0o4700)
  await assert.rejects(f.protector.wrap(randomBytes(32), context, AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  await chmod(f.executable, 0o700)
  const alias = join(f.root, 'alias')
  await symlink(f.executable, alias)
  const symlinked = new LinuxSecretServiceJournalProtector({ executable: alias, service, account })
  await assert.rejects(symlinked.wrap(randomBytes(32), context, AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  await chmod(f.root, 0o777)
  await assert.rejects(f.protector.wrap(randomBytes(32), context, AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  await chmod(f.root, 0o700)
})

test('Secret Service executable cannot be replaced through a writable ancestor', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const ancestor = join(f.root, 'writable-ancestor'), parent = join(ancestor, 'protected-parent')
  const executable = join(parent, 'secret-tool')
  await mkdir(ancestor, { mode: 0o700 })
  await mkdir(parent, { mode: 0o700 })
  await writeFile(executable, await readFile(f.executable), { mode: 0o700 })
  const protector = new LinuxSecretServiceJournalProtector({ executable, service, account })
  await chmod(ancestor, 0o777)
  await assert.rejects(protector.wrap(randomBytes(32), context, AbortSignal.timeout(2_000)), /Secret Service protection unavailable/)
  await chmod(ancestor, 0o700)
  const key = randomBytes(32)
  t.after(() => key.fill(0))
  const wrapped = await protector.wrap(key, context, AbortSignal.timeout(2_000))
  const reopened = Buffer.from(await protector.unwrap(wrapped, context, AbortSignal.timeout(2_000)))
  assert.deepEqual(reopened, key)
  reopened.fill(0)
})

test('Secret Service lookup cancellation does not wait for an uncooperative child', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t)
  const pidPath = join(f.root, 'child.pid')
  await writeFile(f.executable, `#!/usr/bin/env node\nconst fs=require('node:fs');fs.writeFileSync(${JSON.stringify(pidPath)},String(process.pid));process.on('SIGTERM',()=>{});process.stdout.write('PARTIAL');setInterval(()=>{},1000)\n`, { mode: 0o700 })
  const controller = new AbortController()
  const operation = f.protector.wrap(randomBytes(32), context, controller.signal)
  const deadline = Date.now() + 1_500
  let childPID = 0
  while (!childPID && Date.now() < deadline) {
    try { childPID = Number(await readFile(pidPath, 'utf8')) } catch { await new Promise(resolve => setTimeout(resolve, 10)) }
  }
  assert.ok(Number.isSafeInteger(childPID) && childPID > 0)
  const started = Date.now()
  controller.abort()
  await assert.rejects(operation, /Secret Service protection unavailable/)
  assert.ok(Date.now() - started < 1_000)
  const goneBy = Date.now() + 2_000
  let gone = false
  while (!gone && Date.now() < goneBy) {
    try { process.kill(childPID, 0); await new Promise(resolve => setTimeout(resolve, 20)) }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') gone = true; else throw error }
  }
  assert.equal(gone, true, 'owned lookup child did not terminate')
})

test('Secret Service protector copies input before an asynchronous lookup', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const key = randomBytes(32), original = Buffer.from(key), aad = Buffer.from(context), originalAAD = Buffer.from(aad)
  const operation = f.protector.wrap(key, aad, AbortSignal.timeout(2_000))
  key.fill(0); aad.fill(0)
  const wrapped = await operation
  const reopened = Buffer.from(await f.protector.unwrap(wrapped, originalAAD, AbortSignal.timeout(2_000)))
  assert.deepEqual(reopened, original)
  reopened.fill(0); original.fill(0)
})

test('Secret Service protector snapshots the lookup reference used for its stable identity', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  let reads = 0
  const protector = new LinuxSecretServiceJournalProtector({ executable: f.executable, service,
    get account() { return ++reads === 1 ? account : 'changed-account' } })
  assert.equal(reads, 1)
  assert.equal(protector.id, f.protector.id)
  const key = randomBytes(32)
  t.after(() => key.fill(0))
  const wrapped = await protector.wrap(key, context, AbortSignal.timeout(2_000))
  const reopened = Buffer.from(await protector.unwrap(wrapped, context, AbortSignal.timeout(2_000)))
  assert.deepEqual(reopened, key)
  reopened.fill(0)
})

test('isolated Secret Service supplies journal, installation and enrollment recovery keys', { skip: process.platform !== 'linux', timeout: 25_000 }, async t => {
  const gi = spawnSync('/usr/bin/python3', ['-c', "import gi;gi.require_version('Secret','1');from gi.repository import Secret"], { stdio: 'ignore' })
  const dbus = spawnSync('dbus-run-session', ['--version'], { stdio: 'ignore' })
  const keyring = spawnSync('gnome-keyring-daemon', ['--version'], { stdio: 'ignore' })
  if (gi.status !== 0 || dbus.status !== 0 || keyring.status !== 0) return t.skip('isolated D-Bus, libsecret GI or GNOME keyring unavailable')
  const root = await mkdtemp(join(tmpdir(), 'dsh-real-secret-service-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const data = join(root, 'data'), config = join(root, 'config'), runtimeDir = join(root, 'runtime')
  await Promise.all([data, config, runtimeDir].map(path => mkdir(path, { mode: 0o700 })))
  const shim = join(root, 'secret-tool'), coordinator = join(root, 'coordinator.py'), client = join(root, 'client.mts')
  const schema = 'org.example.DshJournalFixture'
  const installationAccount = 'fixture-installation'
  const installationKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const installationPublic = installationKeys.publicKey.export({ format: 'jwk' })
  const installationPrivate = installationKeys.privateKey.export({ format: 'der', type: 'pkcs8' })
  t.after(() => installationPrivate.fill(0))
  await writeFile(shim, [
    '#!/usr/bin/python3', 'import sys, gi', "gi.require_version('Secret','1')", 'from gi.repository import Secret',
    `schema=Secret.Schema.new(${JSON.stringify(schema)},Secret.SchemaFlags.NONE,{'service':Secret.SchemaAttributeType.STRING,'account':Secret.SchemaAttributeType.STRING})`,
    `expected=['lookup','service',${JSON.stringify(service)},'account']`,
    `if len(sys.argv[1:])!=5 or sys.argv[1:5]!=expected or sys.argv[5] not in [${JSON.stringify(account)},${JSON.stringify(installationAccount)}]: sys.exit(2)`,
    `value=Secret.password_lookup_sync(schema,{'service':${JSON.stringify(service)},'account':sys.argv[5]},None)`,
    'if value is None: sys.exit(1)', "sys.stdout.write(value+'\\n')", '',
  ].join('\n'), { mode: 0o700 })
  const protectorModule = pathToFileURL(resolve('host/remote-control/src/secret-service-journal-protector.ts')).href
  const signerModule = pathToFileURL(resolve('host/remote-control/src/secret-service-installation-signer.ts')).href
  const enrollmentModule = pathToFileURL(resolve('host/remote-control/src/host-enrollment.ts')).href
  const recoveryModule = pathToFileURL(resolve('host/remote-control/src/host-enrollment-recovery.ts')).href
  const journalModule = pathToFileURL(resolve('host/remote-control/src/command-journal.ts')).href
  const protocolModule = pathToFileURL(resolve('host/remote-control/src/protocol.ts')).href
  const journalPath = join(root, 'commands.sqlite'), runtime = randomUUID()
  await writeFile(client, [
    "import assert from 'node:assert/strict'", "import { lstat, readFile } from 'node:fs/promises'", "import { createPublicKey, randomUUID, verify } from 'node:crypto'",
    `import { LinuxSecretServiceJournalProtector } from ${JSON.stringify(protectorModule)}`,
    `import { LinuxSecretServiceInstallationSigner } from ${JSON.stringify(signerModule)}`,
    `import { HostEnrollmentClient } from ${JSON.stringify(enrollmentModule)}`,
    `import { HostEnrollmentRecoveryStore } from ${JSON.stringify(recoveryModule)}`,
    `import { PersistentCommandJournal } from ${JSON.stringify(journalModule)}`,
    `import { parseCommand } from ${JSON.stringify(protocolModule)}`,
    `const path=${JSON.stringify(journalPath)},runtime=${JSON.stringify(runtime)}`,
    `const protector=new LinuxSecretServiceJournalProtector({executable:${JSON.stringify(shim)},service:${JSON.stringify(service)},account:${JSON.stringify(account)}})`,
    "const owner={userId:'fixture-user',deviceId:'fixture-device'}",
    "const input=parseCommand({v:0,type:'message.submit',request_id:randomUUID(),runtime_epoch:randomUUID(),session_id:'55555555-5555-4555-8555-555555555555',payload:{mode:'queue',text:'PRIVATE_ISOLATED_KEYRING_COMMAND'}})",
    'let journal=await PersistentCommandJournal.open(path,runtime,{protector});journal.admit(input,owner);journal.close()',
    "await assert.rejects(lstat(path+'.key'),error=>error.code==='ENOENT')",
    "assert.equal((await lstat(path+'.wrapped-key')).mode&0o777,0o600)",
    "assert.equal((await readFile(path+'.wrapped-key')).includes(Buffer.from('PRIVATE_ISOLATED_KEYRING_COMMAND')),false)",
    'journal=await PersistentCommandJournal.open(path,runtime,{protector});assert.deepEqual(journal.get(input.request_id,owner)?.command,input);journal.close()',
    `const publicJwk=${JSON.stringify(installationPublic)}`,
    `const signer=new LinuxSecretServiceInstallationSigner({executable:${JSON.stringify(shim)},service:${JSON.stringify(service)},account:${JSON.stringify(installationAccount)},publicJwk,ownerSignal:new AbortController().signal})`,
    "const message=Buffer.from('isolated-installation-proof');assert.equal(verify('sha256',message,{key:createPublicKey({key:publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},await signer.sign(message)),true)",
    "const ownerSignal=new AbortController().signal;const options={origin:'https://fixture.example',identity:{issuer:'https://id.example',subject:'fixture',audience:'urn:fixture',clientId:'fixture-host'},publicJwk,signer,account:{signal:ownerSignal,async acquire(){throw new Error('unexpected network')}},requiredScopes:['remote.access']}",
    `const recoveryPath=${JSON.stringify(join(root, 'recovery', 'pending.bin'))}`,
    "let client=new HostEnrollmentClient(options),store=new HostEnrollmentRecoveryStore({path:recoveryPath,client,protector})",
    "const attempt=client.prepare({organizationId:randomUUID(),alias:'PRIVATE_RECOVERY_ALIAS',profileRef:'fixture',protocolVersion:1,workspaceRefs:['workspace']});const code=attempt.code,id=attempt.requestId",
    "await store.save(attempt,AbortSignal.timeout(5000));const encrypted=await readFile(recoveryPath);assert.equal(encrypted.includes(Buffer.from(code)),false);assert.equal(encrypted.includes(Buffer.from('PRIVATE_RECOVERY_ALIAS')),false);attempt.destroy();store.close();client.close()",
    "client=new HostEnrollmentClient(options);store=new HostEnrollmentRecoveryStore({path:recoveryPath,client,protector});const restored=await store.load(AbortSignal.timeout(5000));assert.ok(restored);assert.equal(restored.code,code);assert.equal(restored.requestId,id);assert.equal(await store.remove(restored,AbortSignal.timeout(5000)),true);restored.destroy();store.close();client.close();signer.close()",
    "process.stdout.write('isolated-client-ok\\n')", '',
  ].join('\n'), { mode: 0o600 })
  await writeFile(coordinator, [
    'import base64, subprocess, sys, time, gi', "gi.require_version('Secret','1')", 'from gi.repository import Secret',
    'fixture=bytearray(sys.stdin.buffer.read())', 'if len(fixture)<=32: sys.exit(2)', 'master=fixture[:32]', 'installation=fixture[32:]',
    "daemon=subprocess.Popen(['gnome-keyring-daemon','--foreground','--unlock','--components=secrets'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)",
    'try:', " daemon.stdin.write(b'isolated-fixture-password\\n');daemon.stdin.close();time.sleep(0.5)",
    ` schema=Secret.Schema.new(${JSON.stringify(schema)},Secret.SchemaFlags.NONE,{'service':Secret.SchemaAttributeType.STRING,'account':Secret.SchemaAttributeType.STRING})`,
    ` attrs={'service':${JSON.stringify(service)},'account':${JSON.stringify(account)}}`,
    " if not Secret.password_store_sync(schema,attrs,Secret.COLLECTION_DEFAULT,'fixture',base64.b64encode(master).decode('ascii'),None): sys.exit(3)",
    ` attrs={'service':${JSON.stringify(service)},'account':${JSON.stringify(installationAccount)}}`,
    " if not Secret.password_store_sync(schema,attrs,Secret.COLLECTION_DEFAULT,'installation-fixture',base64.b64encode(installation).decode('ascii'),None): sys.exit(3)",
    ' master[:]=bytes(len(master));installation[:]=bytes(len(installation));fixture[:]=bytes(len(fixture))',
    ' result=subprocess.run(sys.argv[1:],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)',
    " if result.returncode!=0 or b'isolated-client-ok' not in result.stdout: sys.exit(4)",
    " print('isolated-secret-service-ok')", 'finally:', ' master[:]=bytes(len(master));installation[:]=bytes(len(installation));fixture[:]=bytes(len(fixture))', ' daemon.terminate()',
    ' try: daemon.wait(timeout=3)', ' except subprocess.TimeoutExpired:', '  daemon.kill();daemon.wait(timeout=3)', '',
  ].join('\n'), { mode: 0o600 })
  const env: NodeJS.ProcessEnv = { ...process.env, XDG_DATA_HOME: data, XDG_CONFIG_HOME: config, XDG_RUNTIME_DIR: runtimeDir }
  delete env.DBUS_SESSION_BUS_ADDRESS
  delete env.GNOME_KEYRING_CONTROL
  delete env.GNOME_KEYRING_PID
  const child = spawn('dbus-run-session', ['--', '/usr/bin/python3', coordinator, resolve('node_modules/.bin/tsx'), client],
    { cwd: root, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.setEncoding('utf8').on('data', value => { stdout = (stdout + value).slice(-4096) })
  child.stderr.setEncoding('utf8').on('data', value => { stderr = (stderr + value).slice(-4096) })
  const master = randomBytes(32)
  t.after(() => master.fill(0))
  const keyMaterial = Buffer.concat([master, installationPrivate])
  t.after(() => keyMaterial.fill(0))
  child.stdin.on('error', () => { master.fill(0); keyMaterial.fill(0) })
  child.stdin.end(keyMaterial, () => { master.fill(0); keyMaterial.fill(0) })
  const timer = setTimeout(() => { if (child.pid) { try { process.kill(-child.pid, 'SIGKILL') } catch { /* Already exited. */ } } }, 20_000)
  let code: number | null
  try {
    code = await new Promise<number | null>((accept, reject) => { child.once('error', reject); child.once('close', accept) })
  } finally { clearTimeout(timer) }
  assert.equal(code, 0, 'isolated Secret Service fixture failed')
  assert.ok(stdout.includes('isolated-secret-service-ok'))
  assert.equal(stderr.includes('PRIVATE_ISOLATED_KEYRING_COMMAND'), false)
})
