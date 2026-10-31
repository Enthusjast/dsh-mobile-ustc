import assert from 'node:assert/strict'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { chmod, link, lstat, readFile, realpath, symlink, unlink, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { inspect } from 'node:util'
import { MacOSKeychainJournalProtector } from '../../src/macos-keychain-journal-protector.js'
import { PersistentCommandJournal } from '../../src/command-journal.js'
import { parseCommand } from '../../src/protocol.js'

const root = process.env.MACOS_KEYCHAIN_FIXTURE_ROOT, mode = process.argv[2]
assert.ok(root && /^dsh-keychain-[A-Za-z0-9_-]+$/.test(basename(root)))
assert.equal(await realpath(root), root)
const metadata = await lstat(root)
assert.equal(metadata.uid, process.getuid!()); assert.equal(metadata.mode & 0o777, 0o700)
assert.ok(['roundtrip', 'errors', 'permissions', 'cancel', 'slots'].includes(mode!))
const originalPlatform = process.platform
// Only this owned protocol fixture changes platform. No production bypass flag
// or system security executable is used; this is not macOS acceptance evidence.
Object.defineProperty(process, 'platform', { value: 'darwin' })
const service = 'cn.edu.ustc.dsh.journal', account = 'fixture-master'
const executable = join(root, 'security-fixture'), keychainPath = join(root, 'login.keychain-db')
const secret = join(root, 'secret'), calls = join(root, 'calls'), started = join(root, 'started')
const master = randomBytes(32), key = randomBytes(32), context = Buffer.from('fixture-keychain-context')
const expected = ['find-generic-password', '-s', service, '-a', account, '-w', keychainPath]
await writeFile(keychainPath, 'opaque-fixture-keychain', { mode: 0o600 })
await writeFile(secret, master.toString('base64'), { mode: 0o600 })
const emit = `process.stdout.write(fs.readFileSync(${JSON.stringify(secret)},'utf8')+String.fromCharCode(10))`
const setup = async (body = emit) => writeFile(executable, `#!/usr/bin/env node
const fs=require('node:fs');
if(JSON.stringify(process.argv.slice(2))!==${JSON.stringify(JSON.stringify(expected))})process.exit(2);
for(const name of ['LD_PRELOAD','DYLD_INSERT_LIBRARIES','NODE_OPTIONS','PYTHONPATH','PYTHONHOME'])if(process.env[name])process.exit(3);
fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify(process.argv.slice(2))+String.fromCharCode(10));
${body}
`, { mode: 0o700 })
const options = { executable, keychainPath, service, account }
const make = () => new MacOSKeychainJournalProtector(options)
let operations = 0
const controllers: AbortController[] = []
try {
  await setup()
  const protector = make()
  if (mode === 'roundtrip') {
    options.service = 'changed'; options.account = 'changed'; options.keychainPath = join(root, 'other.keychain-db'); options.executable = '/not-invoked/security'
    process.env.LD_PRELOAD = 'PRIVATE_INJECTION'; process.env.DYLD_INSERT_LIBRARIES = 'PRIVATE_INJECTION'
    process.env.NODE_OPTIONS = '--require PRIVATE_INJECTION'; process.env.PYTHONPATH = 'PRIVATE_INJECTION'; process.env.PYTHONHOME = 'PRIVATE_INJECTION'
    const wrapped = await protector.wrap(key, context, AbortSignal.timeout(2000))
    assert.equal(wrapped.length, 100); assert.equal(Buffer.from(wrapped).subarray(0, 8).toString(), 'DSHKCK01')
    const restored = Buffer.from(await protector.unwrap(wrapped, context, AbortSignal.timeout(2000)))
    assert.ok(restored.equals(key)); restored.fill(0)
    await assert.rejects(protector.unwrap(wrapped, Buffer.from('wrong-context'), AbortSignal.timeout(2000)), /Keychain protection unavailable/)
    const damaged = Buffer.from(wrapped); damaged[99] = damaged[99]! ^ 1
    await assert.rejects(protector.unwrap(damaged, context, AbortSignal.timeout(2000)), /Keychain protection unavailable/)
    const linux = Buffer.from(wrapped); linux.write('DSHSSK01')
    await assert.rejects(protector.unwrap(linux, context, AbortSignal.timeout(2000)), /Keychain protection unavailable/)
    const runtime = randomUUID(), path = join(root, 'journal', 'commands.sqlite')
    const command = parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: randomUUID(), session_id: randomUUID(), payload: { mode: 'queue', text: 'PRIVATE_KEYCHAIN_COMMAND' } })
    const owner = { userId: randomUUID(), deviceId: randomUUID() }
    let journal = await PersistentCommandJournal.open(path, runtime, { protector })
    journal.admit(command, owner); journal.close()
    await assert.rejects(lstat(path + '.key'), { code: 'ENOENT' })
    const protectedBefore = await readFile(path + '.wrapped-key')
    assert.equal(protectedBefore.includes(master), false)
    journal = await PersistentCommandJournal.open(path, runtime, { protector }); assert.deepEqual(journal.get(command.request_id, owner)?.command, command); journal.close()
    await writeFile(secret, randomBytes(32).toString('base64'), { mode: 0o600 })
    await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector }), /key protection unavailable/)
    assert.ok((await readFile(path + '.wrapped-key')).equals(protectedBefore))
    await assert.rejects(lstat(path + '.key'), { code: 'ENOENT' })
    const args = await readFile(calls, 'utf8')
    assert.equal(args.includes(master.toString('base64')), false)
    for (const value of [String(protector), inspect(protector), JSON.stringify(protector), JSON.stringify({ ...protector })]) {
      for (const privateValue of [master.toString('base64'), keychainPath, service, account, executable]) assert.equal(value.includes(privateValue), false)
    }
    operations = args.trim().split('\n').length
  } else if (mode === 'errors') {
    for (const body of ["process.stderr.write('PRIVATE_KEYCHAIN_ERROR');process.exit(44)", "process.stdout.write('not base64')", "process.stdout.write('A'.repeat(1024))", "process.stdout.write('A'.repeat(42)+'B=')"]) {
      await setup(body)
      await assert.rejects(make().wrap(key, context, AbortSignal.timeout(2000)), error => error instanceof Error && error.message === 'journal Keychain protection unavailable')
      operations++
    }
    for (const change of [{ service: '-w' }, { account: 'two words' }, { keychainPath: '../login.keychain-db' }]) {
      assert.throws(() => new MacOSKeychainJournalProtector({ ...options, ...change }), /Keychain protection unavailable/)
    }
  } else if (mode === 'permissions') {
    const denied = () => assert.rejects(make().wrap(key, context, AbortSignal.timeout(2000)), /Keychain protection unavailable/)
    await chmod(keychainPath, 0o644); await denied(); await chmod(keychainPath, 0o600)
    const alias = join(root, 'keychain-alias'); await symlink(keychainPath, alias)
    await assert.rejects(new MacOSKeychainJournalProtector({ ...options, keychainPath: alias }).wrap(key, context, AbortSignal.timeout(2000)), /Keychain protection unavailable/)
    const hardlink = join(root, 'keychain-hardlink'); await link(keychainPath, hardlink); await denied(); await unlink(hardlink)
    await chmod(executable, 0o722); await denied(); await chmod(executable, 0o700)
    await chmod(root, 0o777); await denied(); await chmod(root, 0o700)
    await assert.rejects(lstat(calls), { code: 'ENOENT' }); operations = 5
  } else if (mode === 'cancel') {
    await setup(`fs.writeFileSync(${JSON.stringify(started)},String(process.pid));process.on('SIGTERM',()=>{});process.stdout.write('PARTIAL');setInterval(()=>{},1000);setTimeout(()=>process.exit(12),4000)`)
    const controller = new AbortController(), pending = protector.wrap(key, context, controller.signal)
    controllers.push(controller); void pending.catch(() => {})
    let pid = 0
    const deadline = Date.now() + 2000
    while (!pid && Date.now() < deadline) { try { pid = Number(await readFile(started, 'utf8')) } catch { await new Promise(resolve => setTimeout(resolve, 10)) } }
    assert.ok(pid > 0); controller.abort()
    await assert.rejects(pending, /Keychain protection unavailable/)
    let gone = false
    const goneBy = Date.now() + 2000
    while (!gone && Date.now() < goneBy) { try { process.kill(pid, 0); await new Promise(resolve => setTimeout(resolve, 20)) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') gone = true; else throw error } }
    assert.ok(gone); operations = 1
  } else {
    await setup(`fs.appendFileSync(${JSON.stringify(started)},String(process.pid)+String.fromCharCode(10));process.on('SIGTERM',()=>{});setInterval(()=>{},1000);setTimeout(()=>process.exit(12),5000)`)
    const controls = Array.from({ length: 8 }, () => new AbortController())
    controllers.push(...controls)
    const pending: Promise<unknown>[] = []
    for (const control of controls) {
      pending.push(protector.wrap(key, context, control.signal).catch(error => error))
      const expectedCount = pending.length
      const until = Date.now() + 2000
      while (Date.now() < until) { try { if ((await readFile(started, 'utf8')).trim().split('\n').length === expectedCount) break } catch {} await new Promise(resolve => setTimeout(resolve, 10)) }
    }
    assert.equal((await readFile(started, 'utf8')).trim().split('\n').length, 8)
    await assert.rejects(protector.wrap(key, context, AbortSignal.timeout(2000)), /Keychain protection unavailable/)
    controls.forEach(control => control.abort()); await Promise.all(pending)
    const after = (await readFile(calls, 'utf8')).trim().split('\n').length
    assert.equal(after, 8); operations = after
    await new Promise(resolve => setTimeout(resolve, 350))
    await setup()
    assert.equal((await protector.wrap(key, context, AbortSignal.timeout(2000))).length, 100)
  }
  process.stdout.write(JSON.stringify({ mode, operations, platform: 'darwin-protocol-fixture', keychain_sha256: createHash('sha256').update(await readFile(keychainPath)).digest('hex') }) + '\n')
} finally {
  controllers.forEach(controller => controller.abort())
  master.fill(0); key.fill(0)
  Object.defineProperty(process, 'platform', { value: originalPlatform })
}
