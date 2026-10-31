import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, verify } from 'node:crypto'
import { chmod, lstat, readFile, realpath, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { inspect } from 'node:util'
import { MacOSKeychainInstallationSigner, type MacOSKeychainInstallationSignerOptions } from '../../src/macos-keychain-installation-signer.js'

const root = process.env.MACOS_KEYCHAIN_SIGNER_ROOT, mode = process.argv[2]
assert.ok(root && /^dsh-keychain-sign-[A-Za-z0-9_-]+$/.test(basename(root)))
assert.equal(await realpath(root), root)
const metadata = await lstat(root)
assert.equal(metadata.uid, process.getuid!()); assert.equal(metadata.mode & 0o777, 0o700)
assert.ok(['sign', 'errors', 'owner'].includes(mode!))
// Protocol emulation only; all module imports happen on the actual platform.
const originalPlatform = process.platform
Object.defineProperty(process, 'platform', { value: 'darwin' })
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const der = keys.privateKey.export({ format: 'der', type: 'pkcs8' })
const publicJwk = keys.publicKey.export({ format: 'jwk' }) as MacOSKeychainInstallationSignerOptions['publicJwk']
const keychainPath = join(root, 'login.keychain-db'), executable = join(root, 'security-fixture')
const secret = join(root, 'secret'), calls = join(root, 'calls'), started = join(root, 'started')
const service = 'cn.edu.ustc.dsh.installation', account = 'fixture-installation'
const owner = new AbortController()
const options: MacOSKeychainInstallationSignerOptions = { executable, keychainPath, service, account, publicJwk, ownerSignal: owner.signal }
await writeFile(keychainPath, 'opaque-signer-keychain', { mode: 0o600 })
await writeFile(secret, der.toString('base64'), { mode: 0o600 })
const expected = ['find-generic-password', '-s', service, '-a', account, '-w', keychainPath]
const emit = `process.stdout.write(fs.readFileSync(${JSON.stringify(secret)},'utf8')+String.fromCharCode(10))`
const setup = (body = emit) => writeFile(executable, `#!/usr/bin/env node
const fs=require('node:fs');
if(JSON.stringify(process.argv.slice(2))!==${JSON.stringify(JSON.stringify(expected))})process.exit(2);
fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify(process.argv.slice(2))+String.fromCharCode(10));
${body}
`, { mode: 0o700 })
const signers: MacOSKeychainInstallationSigner[] = []
const make = (current = options) => { const signer = new MacOSKeychainInstallationSigner(current); signers.push(signer); return signer }
let operations = 0
try {
  await setup()
  const signer = make(), input = Buffer.from('installation-handshake.header.payload')
  if (mode === 'sign') {
    const original = Buffer.from(input), pending = signer.sign(input)
    input.fill(0); options.publicJwk.x = randomBytes(32).toString('base64url')
    options.executable = '/not-invoked'; options.keychainPath = '/not-invoked'; options.service = 'changed'; options.account = 'changed'
    const signature = await pending
    assert.equal(signature.length, 64)
    assert.ok(verify('sha256', original, { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, signature))
    const logged = await readFile(calls, 'utf8')
    assert.equal(logged.includes(der.toString('base64')), false)
    for (const value of [String(signer), inspect(signer), JSON.stringify(signer), JSON.stringify({ ...signer })]) {
      for (const privateValue of [der.toString('base64'), executable, keychainPath, service, account]) assert.equal(value.includes(privateValue), false)
    }
    operations = logged.trim().split('\n').length
  } else if (mode === 'errors') {
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), wrongCurve = generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
    const cases = [other.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), wrongCurve.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      Buffer.concat([der, Buffer.from([0])]).toString('base64'), randomBytes(32).toString('base64'), 'invalid-base64', 'A'.repeat(3000)]
    for (const value of cases) {
      await writeFile(secret, value, { mode: 0o600 })
      await assert.rejects(signer.sign(input), error => error instanceof Error && error.message === 'installation Keychain signing unavailable')
      operations++
    }
    await writeFile(secret, der.toString('base64'), { mode: 0o600 })
    assert.ok(verify('sha256', input, { key: keys.publicKey, dsaEncoding: 'ieee-p1363' }, await signer.sign(input)))
    assert.throws(() => make({ ...options, publicJwk: { ...publicJwk, x: 'invalid' } }), /Keychain signing unavailable/)
    await assert.rejects(signer.sign(new Uint8Array()), /Keychain signing unavailable/)
    await assert.rejects(signer.sign(new Uint8Array(16 * 1024 + 1)), /Keychain signing unavailable/)
    await setup("process.stderr.write('PRIVATE_KEYCHAIN_FAILURE');process.exit(44)")
    await assert.rejects(signer.sign(input), error => error instanceof Error && error.message === 'installation Keychain signing unavailable')
    await setup(); await chmod(keychainPath, 0o644)
    await assert.rejects(signer.sign(input), /Keychain signing unavailable/)
    await chmod(keychainPath, 0o600)
  } else {
    await setup(`fs.writeFileSync(${JSON.stringify(started)},String(process.pid));process.on('SIGTERM',()=>{});setInterval(()=>{},1000);setTimeout(()=>process.exit(12),5000)`)
    const pending = signer.sign(input); void pending.catch(() => {})
    let pid = 0
    const deadline = Date.now() + 2000
    while (!pid && Date.now() < deadline) { try { pid = Number(await readFile(started, 'utf8')) } catch { await new Promise(resolve => setTimeout(resolve, 10)) } }
    assert.ok(pid > 0); owner.abort()
    await assert.rejects(pending, /Keychain signing unavailable/)
    await assert.rejects(signer.sign(input), /Keychain signing unavailable/)
    let gone = false
    const goneBy = Date.now() + 2000
    while (!gone && Date.now() < goneBy) { try { process.kill(pid, 0); await new Promise(resolve => setTimeout(resolve, 20)) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') gone = true; else throw error } }
    assert.ok(gone)
    const nextOwner = new AbortController(), next = make({ ...options, ownerSignal: nextOwner.signal })
    const group = Array.from({ length: 8 }, () => next.sign(input))
    const outcomes = Promise.allSettled(group)
    await assert.rejects(next.sign(input), /Keychain signing unavailable/)
    next.close()
    assert.ok((await outcomes).every(outcome => outcome.status === 'rejected'))
    await assert.rejects(next.sign(input), /Keychain signing unavailable/)
    await new Promise(resolve => setTimeout(resolve, 350)); operations = 9
  }
  process.stdout.write(JSON.stringify({ mode, operations, platform: 'darwin-protocol-fixture', keychain_sha256: createHash('sha256').update(await readFile(keychainPath)).digest('hex') }) + '\n')
} finally {
  signers.forEach(signer => signer.close()); der.fill(0)
  Object.defineProperty(process, 'platform', { value: originalPlatform })
}
