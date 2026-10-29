import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createPublicKey, randomBytes, verify } from 'node:crypto'
import { once } from 'node:events'
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { inspect } from 'node:util'
import { pathToFileURL } from 'node:url'
import { LinuxInstallationKeyError, LinuxInstallationKeyStore } from '../src/linux-installation-key.js'

const code = (name: string) => (cause: unknown) => cause instanceof LinuxInstallationKeyError && cause.code === `host.installation_key.${name}`

async function fixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-installation-key-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const keyring = join(root, 'keyring'), executable = join(root, 'secret-tool'), calls = join(root, 'calls')
  await mkdir(keyring, { mode: 0o700 })
  await writeFile(executable, [
    '#!/usr/bin/env node', "const fs=require('node:fs'),path=require('node:path')",
    `const root=${JSON.stringify(keyring)},calls=${JSON.stringify(calls)},args=process.argv.slice(2);fs.appendFileSync(calls,JSON.stringify(args)+'\\n',{mode:0o600})`,
    "let account;if(args[0]==='store'&&args.length===6&&args[1]==='--label=DSH remote installation key'&&args[2]==='service'&&args[3]==='fixture-service'&&args[4]==='account')account=args[5];else if(args[0]==='lookup'&&args.length===5&&args[1]==='service'&&args[2]==='fixture-service'&&args[3]==='account')account=args[4];else process.exit(2)",
    "if(!/^installation-[0-9a-f]{48}$/.test(account))process.exit(2);const file=path.join(root,account)",
    "if(args[0]==='store')fs.writeFileSync(file,fs.readFileSync(0),{mode:0o600,flag:'wx'});else process.stdout.write(fs.readFileSync(file))", '',
  ].join('\n'), { mode: 0o700 })
  const owner = new AbortController(), path = join(root, 'identity', 'installation.json')
  const options = { path, executable, service: 'fixture-service', ownerSignal: owner.signal }
  const store = new LinuxInstallationKeyStore(options)
  t.after(() => { owner.abort(); store.close() })
  return { root, keyring, executable, calls, owner, path, options, store }
}

test('installation key is generated once, stored outside its public reference and reopened with the same identity', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  assert.equal(await f.store.open(AbortSignal.timeout(5_000)), undefined)
  const identity = await f.store.create(AbortSignal.timeout(5_000))
  const input = Buffer.from('installation-proof'), signature = await identity.signer.sign(input)
  assert.equal(verify('sha256', input, { key: createPublicKey({ key: identity.publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, signature), true)
  assert.equal((await lstat(f.path)).mode & 0o777, 0o600)
  const publicBytes = await readFile(f.path), reference = JSON.parse(publicBytes.toString('utf8')) as { account: string; public_jwk: object }
  const secret = await readFile(join(f.keyring, reference.account))
  assert.equal(publicBytes.includes(secret), false)
  assert.equal(publicBytes.includes(Buffer.from(secret.toString('utf8'), 'base64')), false)
  assert.deepEqual(reference.public_jwk, identity.publicJwk)
  const args = await readFile(f.calls, 'utf8')
  assert.equal(args.includes(secret.toString('utf8')), false)
  for (const value of [String(identity), inspect(identity), JSON.stringify(identity), String(f.store), inspect(f.store), JSON.stringify(f.store)]) {
    assert.equal(value.includes(f.path), false); assert.equal(value.includes(reference.account), false); assert.equal(value.includes(secret.toString('utf8')), false)
  }
  await assert.rejects(f.store.create(AbortSignal.timeout(5_000)), code('exists'))
  assert.equal((await readdir(f.keyring)).length, 1)
  identity.close(); f.store.close()
  const reopened = new LinuxInstallationKeyStore(f.options)
  t.after(() => reopened.close())
  const restored = await reopened.open(AbortSignal.timeout(5_000))
  assert.ok(restored); assert.deepEqual(restored.publicJwk, reference.public_jwk); assert.equal(restored.thumbprint, identity.thumbprint)
  assert.equal(verify('sha256', input, { key: createPublicKey({ key: restored.publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, await restored.signer.sign(input)), true)
  f.owner.abort()
  await assert.rejects(restored.signer.sign(input), /installation Secret Service signing unavailable/)
  await assert.rejects(reopened.open(AbortSignal.timeout(5_000)), code('cancelled'))
})

test('missing, replaced, corrupted or copied key references never trigger replacement', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), original = await f.store.create(AbortSignal.timeout(5_000))
  const bytes = await readFile(f.path), reference = JSON.parse(bytes.toString('utf8')) as { account: string; signature: string }
  const copied = join(f.root, 'identity', 'copied.json')
  await writeFile(copied, bytes, { mode: 0o600 })
  const wrongPath = new LinuxInstallationKeyStore({ ...f.options, path: copied })
  t.after(() => wrongPath.close())
  await assert.rejects(wrongPath.open(AbortSignal.timeout(5_000)), code('unavailable'))
  const damaged = { ...reference, signature: reference.signature.slice(0, -1) + (reference.signature.endsWith('A') ? 'B' : 'A') }
  await writeFile(f.path, JSON.stringify(damaged), { mode: 0o600 })
  await assert.rejects(f.store.open(AbortSignal.timeout(5_000)), code('unavailable'))
  await assert.rejects(f.store.create(AbortSignal.timeout(5_000)), code('exists'))
  await writeFile(f.path, bytes, { mode: 0o600 })
  const alias = join(f.root, 'extra-reference-link')
  await link(f.path, alias)
  await assert.rejects(f.store.open(AbortSignal.timeout(5_000)), code('unavailable'))
  await rm(alias)
  await writeFile(join(f.keyring, reference.account), 'not-a-private-key', { mode: 0o600 })
  await assert.rejects(f.store.open(AbortSignal.timeout(5_000)), code('unavailable'))
  await assert.rejects(f.store.create(AbortSignal.timeout(5_000)), code('exists'))
  assert.deepEqual(await readFile(f.path), bytes)
  assert.equal((await readdir(f.keyring)).length, 1)
  await rm(join(f.keyring, reference.account))
  await assert.rejects(f.store.open(AbortSignal.timeout(5_000)), code('unavailable'))
  await assert.rejects(f.store.create(AbortSignal.timeout(5_000)), code('exists'))
  original.close()
})

test('installation reference rejects unsafe directories and symlinks before writing a key', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), directory = join(f.root, 'unsafe')
  await mkdir(directory, { mode: 0o700 }); await chmod(directory, 0o777)
  const unsafe = new LinuxInstallationKeyStore({ ...f.options, path: join(directory, 'key.json') })
  t.after(() => unsafe.close())
  await assert.rejects(unsafe.create(AbortSignal.timeout(5_000)), code('unavailable'))
  assert.deepEqual(await readdir(f.keyring), [])
  await chmod(directory, 0o700)
  const linkPath = join(f.root, 'link')
  await symlink(directory, linkPath)
  const linked = new LinuxInstallationKeyStore({ ...f.options, path: join(linkPath, 'key.json') })
  t.after(() => linked.close())
  await assert.rejects(linked.create(AbortSignal.timeout(5_000)), code('unavailable'))
  assert.deepEqual(await readdir(f.keyring), [])
  const executableLink = join(f.root, 'secret-tool-link')
  await symlink(f.executable, executableLink)
  const linkedExecutable = new LinuxInstallationKeyStore({ ...f.options, executable: executableLink })
  t.after(() => linkedExecutable.close())
  await assert.rejects(linkedExecutable.create(AbortSignal.timeout(5_000)), code('outcome_unknown'))
  assert.deepEqual(await readdir(f.keyring), [])
})

test('installation reference replaced during key verification does not publish an identity', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t), identity = await f.store.create(AbortSignal.timeout(5_000))
  identity.close()
  const bytes = await readFile(f.path), reference = JSON.parse(bytes.toString('utf8')) as { account: string }
  const marker = join(f.root, 'lookup-started'), key = join(f.keyring, reference.account)
  await writeFile(f.executable, `#!/usr/bin/env node\nconst fs=require('node:fs');fs.writeFileSync(${JSON.stringify(marker)},'ready');setTimeout(()=>process.stdout.write(fs.readFileSync(${JSON.stringify(key)})),250)\n`, { mode: 0o700 })
  const opening = f.store.open(AbortSignal.timeout(3_000))
  const deadline = Date.now() + 1_500
  let started = false
  while (!started && Date.now() < deadline) {
    try { await lstat(marker); started = true } catch { await new Promise(resolve => setTimeout(resolve, 10)) }
  }
  assert.equal(started, true)
  await rename(f.path, join(f.root, 'old-reference'))
  await writeFile(f.path, bytes, { mode: 0o600 })
  await assert.rejects(opening, code('unavailable'))
})

test('cancelled keyring writes are unknown and never publish a replacement reference', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t), pidPath = join(f.root, 'child.pid'), controller = new AbortController()
  await writeFile(f.executable, `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(pidPath)},String(process.pid));process.on('SIGTERM',()=>{});process.stdin.resume();setInterval(()=>{},1000)\n`, { mode: 0o700 })
  const creating = f.store.create(controller.signal)
  const deadline = Date.now() + 1_500
  let childPID = 0
  while (!childPID && Date.now() < deadline) {
    try { childPID = Number(await readFile(pidPath, 'utf8')) } catch { await new Promise(resolve => setTimeout(resolve, 10)) }
  }
  assert.ok(Number.isSafeInteger(childPID) && childPID > 0)
  const duplicateModule = await import(`${pathToFileURL(resolve('host/remote-control/src/linux-installation-key.ts')).href}?fixture=${randomBytes(8).toString('hex')}`) as typeof import('../src/linux-installation-key.js')
  const duplicate = new duplicateModule.LinuxInstallationKeyStore(f.options)
  t.after(() => duplicate.close())
  await assert.rejects(duplicate.open(AbortSignal.timeout(1_000)), error =>
    error instanceof Error && 'code' in error && error.code === 'host.installation_key.busy')
  controller.abort(); await assert.rejects(creating, code('outcome_unknown'))
  await assert.rejects(lstat(f.path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  const goneBy = Date.now() + 2_000
  let gone = false
  while (!gone && Date.now() < goneBy) {
    try { process.kill(childPID, 0); await new Promise(resolve => setTimeout(resolve, 20)) }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') gone = true; else throw error }
  }
  assert.equal(gone, true, 'owned keyring child did not terminate')
  assert.equal(await f.store.open(AbortSignal.timeout(1_000)), undefined)
})

test('keyring errors are redacted and do not publish a reference', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  await writeFile(f.executable, "#!/usr/bin/env node\nprocess.stderr.write('PRIVATE_SECRET_TOOL_ERROR');process.exit(1)\n", { mode: 0o700 })
  await assert.rejects(f.store.create(AbortSignal.timeout(5_000)), error =>
    code('outcome_unknown')(error) && !String(error).includes('PRIVATE_SECRET_TOOL_ERROR'))
  await assert.rejects(lstat(f.path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  assert.deepEqual(await readdir(f.keyring), [])
})

test('a stored but unverifiable key remains an unclaimed item and cannot become an identity', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  await writeFile(f.executable, [
    '#!/usr/bin/env node', "const fs=require('node:fs'),path=require('node:path'),args=process.argv.slice(2)",
    `const root=${JSON.stringify(f.keyring)}`,
    "if(args[0]==='store')fs.writeFileSync(path.join(root,args[5]),fs.readFileSync(0),{mode:0o600});else process.stdout.write('not-base64')", '',
  ].join('\n'), { mode: 0o700 })
  await assert.rejects(f.store.create(AbortSignal.timeout(5_000)), code('outcome_unknown'))
  await assert.rejects(lstat(f.path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  assert.equal((await readdir(f.keyring)).length, 1)
  assert.equal(await f.store.open(AbortSignal.timeout(5_000)), undefined)
})

test('independent creators cannot overwrite an installation identity', { skip: process.platform !== 'linux', timeout: 12_000 }, async t => {
  const f = await fixture(t), script = join(f.root, 'creator.mts')
  const module = pathToFileURL(resolve('host/remote-control/src/linux-installation-key.ts')).href
  await writeFile(script, [
    "import { createInterface } from 'node:readline'",
    `import { LinuxInstallationKeyStore } from ${JSON.stringify(module)}`,
    `const store=new LinuxInstallationKeyStore({path:${JSON.stringify(f.path)},executable:${JSON.stringify(f.executable)},service:'fixture-service',ownerSignal:new AbortController().signal})`,
    "const lines=createInterface({input:process.stdin})[Symbol.asyncIterator]();process.stdout.write('READY\\n');await lines.next()",
    "let result='CREATED';try{const identity=await store.create(AbortSignal.timeout(7000));identity.close()}catch(error){result=error.code==='host.installation_key.exists'?'EXISTS':'ERROR'};await new Promise(resolve=>process.stdout.write(result+'\\n',resolve));store.close();process.exit(0)", '',
  ].join('\n'), { mode: 0o600 })
  const children = [0, 1].map(() => {
    const child = spawn(resolve('node_modules/.bin/tsx'), [script], { cwd: f.root, env: { PATH: process.env.PATH ?? '', TMPDIR: f.root }, stdio: ['pipe', 'pipe', 'pipe'] })
    t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL') })
    const output = createInterface({ input: child.stdout })[Symbol.asyncIterator]()
    return { child, output, exited: once(child, 'close') }
  })
  for (const child of children) assert.equal((await child.output.next()).value, 'READY')
  for (const child of children) child.child.stdin.end('GO\n')
  const results = await Promise.all(children.map(async child => (await child.output.next()).value))
  for (const child of children) assert.deepEqual(await child.exited, [0, null])
  assert.deepEqual(results.sort(), ['CREATED', 'EXISTS'])
  const identity = await f.store.open(AbortSignal.timeout(5_000))
  assert.ok(identity)
  const input = Buffer.from('competing-creator-proof')
  assert.equal(verify('sha256', input, { key: createPublicKey({ key: identity.publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, await identity.signer.sign(input)), true)
  assert.ok((await readdir(f.keyring)).length <= 2)
  identity.close()
})

test('real secret-tool creates and reopens an installation key in an isolated keyring', { skip: process.platform !== 'linux', timeout: 25_000 }, async t => {
  const binary = process.env.REMOTE_TEST_SECRET_TOOL ?? '/usr/bin/secret-tool'
  const available = spawnSync(binary, ['--help'], { stdio: 'ignore' })
  const dbus = spawnSync('dbus-run-session', ['--version'], { stdio: 'ignore' })
  const keyring = spawnSync('gnome-keyring-daemon', ['--version'], { stdio: 'ignore' })
  if (available.error || dbus.status !== 0 || keyring.status !== 0) return t.skip('secret-tool, isolated D-Bus or GNOME keyring unavailable')
  const root = await mkdtemp(join(tmpdir(), 'dsh-real-installation-key-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const data = join(root, 'data'), config = join(root, 'config'), runtime = join(root, 'runtime')
  await Promise.all([data, config, runtime].map(path => mkdir(path, { mode: 0o700 })))
  const executable = join(root, 'secret-tool'), coordinator = join(root, 'coordinator.py'), client = join(root, 'client.mts')
  await copyFile(binary, executable); await chmod(executable, 0o700)
  const module = pathToFileURL(resolve('host/remote-control/src/linux-installation-key.ts')).href
  await writeFile(client, [
    "import assert from 'node:assert/strict'", "import { createPublicKey, verify } from 'node:crypto'", "import { lstat, readFile } from 'node:fs/promises'",
    `import { LinuxInstallationKeyStore } from ${JSON.stringify(module)}`,
    `const options={path:${JSON.stringify(join(root, 'identity', 'installation.json'))},executable:${JSON.stringify(executable)},service:'fixture-installation',ownerSignal:new AbortController().signal}`,
    "let store=new LinuxInstallationKeyStore(options),identity=await store.create(AbortSignal.timeout(10000));const publicJwk=identity.publicJwk,input=Buffer.from('isolated-installation-proof')",
    "assert.equal(verify('sha256',input,{key:createPublicKey({key:publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},await identity.signer.sign(input)),true)",
    "assert.equal((await lstat(options.path)).mode&0o777,0o600);assert.equal((await readFile(options.path,'utf8')).includes('privateKey'),false)",
    "identity.close();store.close();store=new LinuxInstallationKeyStore(options);identity=await store.open(AbortSignal.timeout(10000));assert.ok(identity);assert.deepEqual(identity.publicJwk,publicJwk)",
    "assert.equal(verify('sha256',input,{key:createPublicKey({key:publicJwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},await identity.signer.sign(input)),true);identity.close();store.close();process.stdout.write('isolated-installation-ok\\n')", '',
  ].join('\n'), { mode: 0o600 })
  await writeFile(coordinator, [
    'import subprocess, sys, time',
    "daemon=subprocess.Popen(['gnome-keyring-daemon','--foreground','--unlock','--components=secrets'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)",
    'try:', " daemon.stdin.write(b'isolated-fixture-password\\n');daemon.stdin.close();time.sleep(0.5)",
    ' result=subprocess.run(sys.argv[1:],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=18)',
    " if result.returncode!=0 or b'isolated-installation-ok' not in result.stdout: sys.exit(4)",
    " print('isolated-secret-tool-ok')", 'finally:', ' daemon.terminate()', ' try: daemon.wait(timeout=3)', ' except subprocess.TimeoutExpired:', '  daemon.kill();daemon.wait(timeout=3)', '',
  ].join('\n'), { mode: 0o600 })
  const env: NodeJS.ProcessEnv = { ...process.env, XDG_DATA_HOME: data, XDG_CONFIG_HOME: config, XDG_RUNTIME_DIR: runtime }
  delete env.DBUS_SESSION_BUS_ADDRESS; delete env.GNOME_KEYRING_CONTROL; delete env.GNOME_KEYRING_PID
  const child = spawn('dbus-run-session', ['--', '/usr/bin/python3', coordinator, resolve('node_modules/.bin/tsx'), client], { cwd: root, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.setEncoding('utf8').on('data', value => { stdout = (stdout + value).slice(-4096) })
  child.stderr.setEncoding('utf8').on('data', value => { stderr = (stderr + value).slice(-4096) })
  const timer = setTimeout(() => { if (child.pid) { try { process.kill(-child.pid, 'SIGKILL') } catch { /* Already exited. */ } } }, 22_000)
  let exit: number | null
  try { exit = await new Promise<number | null>((accept, reject) => { child.once('error', reject); child.once('close', accept) }) }
  finally { clearTimeout(timer) }
  assert.equal(exit, 0, 'isolated secret-tool fixture failed')
  assert.ok(stdout.includes('isolated-secret-tool-ok'))
  assert.equal(stderr.includes('isolated-fixture-password'), false)
})
