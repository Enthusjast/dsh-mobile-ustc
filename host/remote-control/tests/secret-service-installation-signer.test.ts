import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, verify } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { inspect } from 'node:util'
import { LinuxSecretServiceInstallationSigner, type LinuxSecretServiceInstallationSignerOptions } from '../src/secret-service-installation-signer.js'

async function fixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-secret-service-signer-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const der = keys.privateKey.export({ type: 'pkcs8', format: 'der' })
  t.after(() => der.fill(0))
  const publicJwk = keys.publicKey.export({ format: 'jwk' }) as LinuxSecretServiceInstallationSignerOptions['publicJwk']
  const secret = join(root, 'secret'), executable = join(root, 'secret-tool'), calls = join(root, 'calls')
  await writeFile(secret, der.toString('base64'), { mode: 0o600 })
  await writeFile(executable, [
    '#!/usr/bin/env node', "const fs=require('node:fs')",
    `fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify(process.argv.slice(2))+'\\n')`,
    "if(JSON.stringify(process.argv.slice(2))!==JSON.stringify(['lookup','service','fixture-service','account','fixture-installation']))process.exit(2)",
    `process.stdout.write(fs.readFileSync(${JSON.stringify(secret)},'utf8')+'\\n')`, '',
  ].join('\n'), { mode: 0o700 })
  const owner = new AbortController()
  const options: LinuxSecretServiceInstallationSignerOptions = { executable, service: 'fixture-service', account: 'fixture-installation', publicJwk, ownerSignal: owner.signal }
  const signer = new LinuxSecretServiceInstallationSigner(options)
  t.after(() => signer.close())
  return { root, keys, der, publicJwk, secret, executable, calls, owner, options, signer }
}

test('Secret Service installation signer binds each signature to its registered P-256 key', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const input = Buffer.from('fixture.signing-input'), original = Buffer.from(input)
  const operation = f.signer.sign(input)
  input.fill(0)
  const signature = await operation
  assert.equal(signature.length, 64)
  assert.equal(verify('sha256', original, { key: f.keys.publicKey, dsaEncoding: 'ieee-p1363' }, signature), true)
  const argumentsLog = await readFile(f.calls, 'utf8')
  assert.equal(argumentsLog.includes(f.der.toString('base64')), false)
  for (const rendered of [String(f.signer), inspect(f.signer), JSON.stringify(f.signer)]) {
    assert.equal(rendered.includes(f.executable), false)
    assert.equal(rendered.includes('fixture-installation'), false)
    assert.equal(rendered.includes(f.der.toString('base64')), false)
  }
  original.fill(0)
})

test('Secret Service installation signer rejects replaced, malformed and noncanonical keys', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const wrongCurve = generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
  const cases = [
    other.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    wrongCurve.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    Buffer.concat([f.der, Buffer.from([0])]).toString('base64'),
    `${f.der.toString('base64')} `,
    'A'.repeat(2049),
    'invalid-base64',
  ]
  for (const value of cases) {
    await writeFile(f.secret, value, { mode: 0o600 })
    await assert.rejects(f.signer.sign(Buffer.from('fixture-input')), /installation Secret Service signing unavailable/)
  }
  await writeFile(f.secret, f.der.toString('base64'), { mode: 0o600 })
  assert.equal(verify('sha256', Buffer.from('fixture-input'), { key: f.keys.publicKey, dsaEncoding: 'ieee-p1363' }, await f.signer.sign(Buffer.from('fixture-input'))), true)
})

test('Secret Service signer pins configuration and bounds concurrent operations', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t)
  const original = { ...f.publicJwk }
  f.options.publicJwk.x = randomBytes(32).toString('base64url')
  assert.equal(verify('sha256', Buffer.from('fixture-input'), { key: f.keys.publicKey, dsaEncoding: 'ieee-p1363' }, await f.signer.sign(Buffer.from('fixture-input'))), true)
  assert.throws(() => new LinuxSecretServiceInstallationSigner({ ...f.options, publicJwk: { ...original, x: 'invalid' } }), /installation Secret Service signing unavailable/)
  await assert.rejects(f.signer.sign(new Uint8Array()), /installation Secret Service signing unavailable/)
  await assert.rejects(f.signer.sign(new Uint8Array(16 * 1024 + 1)), /installation Secret Service signing unavailable/)
  await writeFile(f.executable, '#!/usr/bin/env node\nsetInterval(()=>{},1000)\n', { mode: 0o700 })
  const pending = Array.from({ length: 8 }, () => f.signer.sign(Buffer.from('fixture-input')))
  const outcomes = Promise.allSettled(pending)
  await assert.rejects(f.signer.sign(Buffer.from('fixture-input')), /installation Secret Service signing unavailable/)
  f.owner.abort()
  assert.ok((await outcomes).every(result => result.status === 'rejected'))
  await assert.rejects(f.signer.sign(Buffer.from('fixture-input')), /installation Secret Service signing unavailable/)
})

test('closing a Secret Service signer cancels a running uncooperative lookup', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t)
  const pidPath = join(f.root, 'child.pid')
  await writeFile(f.executable, `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(pidPath)},String(process.pid));process.on('SIGTERM',()=>{});setInterval(()=>{},1000)\n`, { mode: 0o700 })
  const operation = f.signer.sign(Buffer.from('fixture-input'))
  const deadline = Date.now() + 1_500
  let childPID = 0
  while (!childPID && Date.now() < deadline) {
    try { childPID = Number(await readFile(pidPath, 'utf8')) } catch { await new Promise(resolve => setTimeout(resolve, 10)) }
  }
  assert.ok(Number.isSafeInteger(childPID) && childPID > 0)
  f.signer.close()
  await assert.rejects(operation, /installation Secret Service signing unavailable/)
  const goneBy = Date.now() + 2_000
  let gone = false
  while (!gone && Date.now() < goneBy) {
    try { process.kill(childPID, 0); await new Promise(resolve => setTimeout(resolve, 20)) }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') gone = true; else throw error }
  }
  assert.equal(gone, true, 'owned lookup child did not terminate')
  await assert.rejects(f.signer.sign(Buffer.from('fixture-input')), /installation Secret Service signing unavailable/)
})
