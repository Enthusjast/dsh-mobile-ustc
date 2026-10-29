import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { once } from 'node:events'
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createInterface } from 'node:readline'
import { inspect } from 'node:util'
import { pathToFileURL } from 'node:url'
import { HostEnrollmentClient, type HostEnrollmentOptions } from '../src/host-enrollment.js'
import { HostEnrollmentRecoveryError, HostEnrollmentRecoveryStore } from '../src/host-enrollment-recovery.js'
import { guards } from '../src/host-process-guards.js'
import type { JournalKeyProtector } from '../src/journal-key-protection.js'

const organization = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const identity = { issuer: 'https://id.example.edu', subject: 'fixture-owner', audience: 'urn:fixture-host', clientId: 'fixture-host' }
const code = (name: string) => (cause: unknown) => cause instanceof HostEnrollmentRecoveryError && cause.code === `host.enrollment_recovery.${name}`

test('duplicate guard modules share the same per-realm coordination state', async () => {
  const duplicate = await import(`${pathToFileURL(resolve('host/remote-control/src/host-process-guards.ts')).href}?fixture=${randomBytes(8).toString('hex')}`) as typeof import('../src/host-process-guards.js')
  assert.equal(duplicate.guards, guards)
  assert.equal(duplicate.guards.recoveryPaths, guards.recoveryPaths)
  assert.equal(duplicate.guards.enrollmentApprovals, guards.enrollmentApprovals)
})

function protector(master: Buffer, id = 'fixture-recovery-v1'): JournalKeyProtector {
  return {
    id,
    async wrap(key, context) {
      const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', master, nonce)
      cipher.setAAD(context)
      return Buffer.concat([nonce, cipher.update(key), cipher.final(), cipher.getAuthTag()])
    },
    async unwrap(wrapped, context) {
      const bytes = Buffer.from(wrapped)
      if (bytes.length !== 60) throw new Error('invalid fixture ciphertext')
      const decipher = createDecipheriv('aes-256-gcm', master, bytes.subarray(0, 12))
      decipher.setAAD(context); decipher.setAuthTag(bytes.subarray(44))
      return Buffer.concat([decipher.update(bytes.subarray(12, 44)), decipher.final()])
    },
  }
}

async function fixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-enrollment-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const owner = new AbortController(), master = randomBytes(32)
  t.after(() => { owner.abort(); master.fill(0) })
  const options: HostEnrollmentOptions = { origin: 'https://remote.example.edu', identity,
    publicJwk: keys.publicKey.export({ format: 'jwk' }) as HostEnrollmentOptions['publicJwk'], requiredScopes: ['remote.access'],
    signer: { sign(input) { return sign('sha256', Buffer.from(input), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }) } },
    account: { signal: owner.signal, async acquire() { throw new Error('network must not be used for recovery') } } }
  const client = new HostEnrollmentClient(options)
  t.after(() => client.close())
  const path = join(root, 'pending.bin'), keyProtector = protector(master)
  const store = new HostEnrollmentRecoveryStore({ path, client, protector: keyProtector })
  t.after(() => store.close())
  const prepare = () => client.prepare({ organizationId: organization, alias: 'PRIVATE_FIXTURE_HOST', profileRef: 'profile',
    dshVersion: '0.2.1-rc.2', protocolVersion: 1, workspaceRefs: ['workspace'] })
  return { root, path, owner, master, options, client, keyProtector, store, prepare }
}

test('protected enrollment recovery survives reopen without writing its code or metadata in plaintext', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), attempt = f.prepare(), originalCode = attempt.code
  await f.store.save(attempt, AbortSignal.timeout(5_000))
  await f.store.save(attempt, AbortSignal.timeout(5_000))
  assert.equal((await lstat(f.path)).mode & 0o777, 0o600)
  const bytes = await readFile(f.path)
  assert.equal(bytes.includes(Buffer.from(originalCode)), false)
  assert.equal(bytes.includes(Buffer.from('PRIVATE_FIXTURE_HOST')), false)
  assert.equal(bytes.includes(f.master), false)
  assert.deepEqual((await readdir(f.root)).sort(), ['pending.bin'])
  for (const value of [String(f.store), inspect(f.store), JSON.stringify(f.store)]) {
    assert.equal(value.includes(f.path), false); assert.equal(value.includes(originalCode), false)
  }
  f.store.close(); f.client.close()
  const reopenedClient = new HostEnrollmentClient(f.options)
  const reopened = new HostEnrollmentRecoveryStore({ path: f.path, client: reopenedClient, protector: f.keyProtector })
  t.after(() => { reopened.close(); reopenedClient.close() })
  const recovered = await reopened.load(AbortSignal.timeout(5_000))
  assert.ok(recovered); assert.equal(recovered.requestId, attempt.requestId); assert.equal(recovered.code, originalCode)
  assert.equal(await reopened.remove(recovered, AbortSignal.timeout(5_000)), true)
  assert.equal(await reopened.load(AbortSignal.timeout(5_000)), undefined)
  recovered.destroy()
})

test('recovery store never overwrites another pending attempt or deletes it through a stale one', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), first = f.prepare(), second = f.prepare()
  await f.store.save(first, AbortSignal.timeout(5_000))
  const before = await readFile(f.path)
  await assert.rejects(f.store.save(second, AbortSignal.timeout(5_000)), code('conflict'))
  await assert.rejects(f.store.remove(second, AbortSignal.timeout(5_000)), code('conflict'))
  assert.deepEqual(await readFile(f.path), before)
  const loaded = await f.store.load(AbortSignal.timeout(5_000))
  assert.equal(loaded?.requestId, first.requestId)
  loaded?.destroy()
  assert.equal(await f.store.remove(first, AbortSignal.timeout(5_000)), true)
  assert.equal(await f.store.remove(first, AbortSignal.timeout(5_000)), false)
})

test('protected create persists the attempt before attempting the resource request', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), attempt = f.prepare()
  await assert.rejects(f.store.create(attempt, AbortSignal.timeout(5_000)), error =>
    error instanceof Error && 'code' in error && error.code === 'host.enrollment.unavailable')
  assert.equal((await lstat(f.path)).mode & 0o777, 0o600)
  const recovered = await f.store.load(AbortSignal.timeout(5_000))
  assert.ok(recovered); assert.equal(recovered.requestId, attempt.requestId); assert.equal(recovered.code, attempt.code)
  recovered.destroy()
})

test('protected create keeps the record busy until its resource request finishes', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t), controller = new AbortController()
  let entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const client = new HostEnrollmentClient({ ...f.options, account: { signal: f.owner.signal,
    async acquire() { entered(); return await new Promise<never>(() => {}) } } })
  const store = new HostEnrollmentRecoveryStore({ path: f.path, client, protector: f.keyProtector })
  t.after(() => { store.close(); client.close() })
  const attempt = client.prepare({ organizationId: organization, alias: 'Fixture host', profileRef: 'profile', protocolVersion: 1, workspaceRefs: [] })
  const creating = store.create(attempt, controller.signal)
  await started
  await assert.rejects(f.store.discard(AbortSignal.timeout(1_000)), code('busy'))
  controller.abort()
  await assert.rejects(creating, error => error instanceof Error && 'code' in error && error.code === 'host.enrollment.cancelled')
  assert.equal((await f.store.load(AbortSignal.timeout(5_000)))?.requestId, attempt.requestId)
})

test('recovery rejects different account, path, protector and tampered ciphertext without fallback', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), attempt = f.prepare()
  await f.store.save(attempt, AbortSignal.timeout(5_000))
  const original = await readFile(f.path), wrongMaster = randomBytes(32)
  t.after(() => wrongMaster.fill(0))
  const wrongKey = new HostEnrollmentRecoveryStore({ path: f.path, client: f.client, protector: protector(wrongMaster) })
  const wrongID = new HostEnrollmentRecoveryStore({ path: f.path, client: f.client, protector: protector(f.master, 'another-protector') })
  const otherClient = new HostEnrollmentClient({ ...f.options, identity: { ...identity, subject: 'another-owner' } })
  const wrongOwner = new HostEnrollmentRecoveryStore({ path: f.path, client: otherClient, protector: f.keyProtector })
  const copied = join(f.root, 'copy.bin')
  await writeFile(copied, original, { mode: 0o600 })
  const wrongPath = new HostEnrollmentRecoveryStore({ path: copied, client: f.client, protector: f.keyProtector })
  t.after(() => { wrongKey.close(); wrongID.close(); wrongOwner.close(); wrongPath.close(); otherClient.close() })
  for (const store of [wrongKey, wrongID, wrongOwner, wrongPath]) await assert.rejects(store.load(AbortSignal.timeout(5_000)), code('unavailable'))
  const damaged = Buffer.from(original); damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1
  await writeFile(f.path, damaged, { mode: 0o600 })
  await assert.rejects(f.store.load(AbortSignal.timeout(5_000)), code('unavailable'))
  await assert.rejects(f.store.save(attempt, AbortSignal.timeout(5_000)), code('unavailable'))
  assert.deepEqual(await readFile(f.path), damaged)
  await writeFile(f.path, original, { mode: 0o600 })
  assert.equal((await f.store.load(AbortSignal.timeout(5_000)))?.requestId, attempt.requestId)
})

test('recovery rejects unsafe paths, hard links and permissions while cleaning its interrupted publication link', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), attempt = f.prepare()
  await f.store.save(attempt, AbortSignal.timeout(5_000))
  const orphan = join(f.root, `.pending.bin.${randomBytes(16).toString('hex')}.tmp`)
  await link(f.path, orphan)
  assert.equal((await lstat(f.path)).nlink, 2)
  assert.equal((await f.store.load(AbortSignal.timeout(5_000)))?.requestId, attempt.requestId)
  await assert.rejects(lstat(orphan), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  const alias = join(f.root, 'unrelated-link')
  await link(f.path, alias)
  await assert.rejects(f.store.load(AbortSignal.timeout(5_000)), code('unavailable'))
  assert.equal((await lstat(alias)).isFile(), true)
  await rm(alias)
  await chmod(f.path, 0o644)
  await assert.rejects(f.store.load(AbortSignal.timeout(5_000)), code('unavailable'))
  await chmod(f.path, 0o600)
  const symlinkPath = join(f.root, 'link.bin')
  await symlink(f.path, symlinkPath)
  const symlinkStore = new HostEnrollmentRecoveryStore({ path: symlinkPath, client: f.client, protector: f.keyProtector })
  t.after(() => symlinkStore.close())
  await assert.rejects(symlinkStore.load(AbortSignal.timeout(5_000)), code('unavailable'))
  await chmod(f.root, 0o777)
  await assert.rejects(f.store.load(AbortSignal.timeout(5_000)), code('unavailable'))
  await chmod(f.root, 0o700)
  const parentLink = join(f.root, 'parent-link'), directory = join(f.root, 'actual')
  await mkdir(directory, { mode: 0o700 }); await symlink(directory, parentLink)
  const linkedParent = new HostEnrollmentRecoveryStore({ path: join(parentLink, 'record'), client: f.client, protector: f.keyProtector })
  t.after(() => linkedParent.close())
  await assert.rejects(linkedParent.load(AbortSignal.timeout(5_000)), code('unavailable'))
  const ancestor = join(f.root, 'writable'), protectedDir = join(ancestor, 'protected')
  await mkdir(ancestor, { mode: 0o700 }); await mkdir(protectedDir, { mode: 0o700 }); await chmod(ancestor, 0o777)
  const unsafeAncestor = new HostEnrollmentRecoveryStore({ path: join(protectedDir, 'record'), client: f.client, protector: f.keyProtector })
  t.after(() => unsafeAncestor.close())
  await assert.rejects(unsafeAncestor.save(attempt, AbortSignal.timeout(5_000)), code('unavailable'))
  await chmod(ancestor, 0o700)
  await unsafeAncestor.save(attempt, AbortSignal.timeout(5_000))
})

test('recovery never publishes when the platform protector fails its round-trip check', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), attempt = f.prepare()
  const invalid: JournalKeyProtector = { id: 'fixture-invalid', async wrap() { return Buffer.alloc(60, 1) }, async unwrap() { return Buffer.alloc(32, 2) } }
  const store = new HostEnrollmentRecoveryStore({ path: f.path, client: f.client, protector: invalid })
  t.after(() => store.close())
  await assert.rejects(store.save(attempt, AbortSignal.timeout(5_000)), code('unavailable'))
  await assert.rejects(lstat(f.path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  assert.deepEqual(await readdir(f.root), [])
})

test('expired recovery requires explicit discard and owner cancellation prevents reads', { skip: process.platform !== 'linux' }, async t => {
  const f = await fixture(t), attempt = f.prepare()
  await f.store.save(attempt, AbortSignal.timeout(5_000))
  const now = Date.now
  try {
    Date.now = () => now() + 601_000
    await assert.rejects(f.store.load(AbortSignal.timeout(5_000)), code('unavailable'))
    assert.equal(await f.store.discard(AbortSignal.timeout(5_000)), true)
  } finally { Date.now = now }
  const next = f.prepare()
  await f.store.save(next, AbortSignal.timeout(5_000))
  f.owner.abort()
  await assert.rejects(f.store.load(AbortSignal.timeout(5_000)), code('cancelled'))
  assert.equal((await lstat(f.path)).isFile(), true)
})

test('cancelling an uncooperative protector clears its late result and does not publish a record', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t), attempt = f.prepare(), controller = new AbortController()
  let release!: () => void, entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const late = Buffer.alloc(60, 7)
  const blocked: JournalKeyProtector = { id: 'fixture-blocked',
    async wrap() { entered(); await new Promise<void>(resolve => { release = resolve }); return late },
    async unwrap() { throw new Error('must not run') } }
  const store = new HostEnrollmentRecoveryStore({ path: f.path, client: f.client, protector: blocked })
  t.after(() => store.close())
  const saving = store.save(attempt, controller.signal)
  await started; controller.abort()
  await assert.rejects(saving, code('cancelled'))
  await assert.rejects(lstat(f.path), error => (error as NodeJS.ErrnoException).code === 'ENOENT')
  release()
  await new Promise(resolve => setTimeout(resolve, 25))
  assert.ok(late.every(value => value === 0))
})

test('a second store cannot modify the same path while a save is active', { skip: process.platform !== 'linux', timeout: 5_000 }, async t => {
  const f = await fixture(t), attempt = f.prepare()
  let release!: () => void, entered!: () => void
  const started = new Promise<void>(resolve => { entered = resolve })
  const blocked: JournalKeyProtector = { id: f.keyProtector.id,
    async wrap(value, context, signal) { entered(); await new Promise<void>(resolve => { release = resolve }); return await f.keyProtector.wrap(value, context, signal) },
    unwrap: f.keyProtector.unwrap.bind(f.keyProtector) }
  const store = new HostEnrollmentRecoveryStore({ path: f.path, client: f.client, protector: blocked })
  t.after(() => store.close())
  const duplicateModule = await import(`${pathToFileURL(resolve('host/remote-control/src/host-enrollment-recovery.ts')).href}?fixture=${randomBytes(8).toString('hex')}`) as typeof import('../src/host-enrollment-recovery.js')
  const duplicate = new duplicateModule.HostEnrollmentRecoveryStore({ path: f.path, client: f.client, protector: f.keyProtector })
  t.after(() => duplicate.close())
  const saving = store.save(attempt, AbortSignal.timeout(4_000))
  await started
  await assert.rejects(f.store.load(AbortSignal.timeout(1_000)), code('busy'))
  await assert.rejects(duplicate.load(AbortSignal.timeout(1_000)), error =>
    error instanceof Error && 'code' in error && error.code === 'host.enrollment_recovery.busy')
  release(); await saving
  assert.equal((await f.store.load(AbortSignal.timeout(5_000)))?.requestId, attempt.requestId)
})

test('independent processes cannot overwrite a competing recovery attempt', { skip: process.platform !== 'linux', timeout: 15_000 }, async t => {
  const f = await fixture(t), script = join(f.root, 'writer.mts')
  const clientModule = pathToFileURL(resolve('host/remote-control/src/host-enrollment.ts')).href
  const storeModule = pathToFileURL(resolve('host/remote-control/src/host-enrollment-recovery.ts')).href
  await writeFile(script, [
    "import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'",
    "import { createInterface } from 'node:readline'",
    `import { HostEnrollmentClient } from ${JSON.stringify(clientModule)}`,
    `import { HostEnrollmentRecoveryStore } from ${JSON.stringify(storeModule)}`,
    "const lines=createInterface({input:process.stdin})[Symbol.asyncIterator]()",
    "const material=JSON.parse((await lines.next()).value),master=Buffer.from(material.master,'base64'),recovery=Buffer.from(material.recovery,'base64')",
    `const client=new HostEnrollmentClient({origin:${JSON.stringify(f.options.origin)},identity:${JSON.stringify(identity)},publicJwk:${JSON.stringify(f.options.publicJwk)},requiredScopes:['remote.access'],signer:{sign(){throw new Error('unexpected signing')}},account:{signal:new AbortController().signal,async acquire(){throw new Error('unexpected network')}}})`,
    "const protector={id:'fixture-recovery-v1',async wrap(key,context){const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',master,nonce);cipher.setAAD(context);return Buffer.concat([nonce,cipher.update(key),cipher.final(),cipher.getAuthTag()])},async unwrap(value,context){const bytes=Buffer.from(value),decipher=createDecipheriv('aes-256-gcm',master,bytes.subarray(0,12));decipher.setAAD(context);decipher.setAuthTag(bytes.subarray(44));return Buffer.concat([decipher.update(bytes.subarray(12,44)),decipher.final()])}}",
    `const store=new HostEnrollmentRecoveryStore({path:${JSON.stringify(f.path)},client,protector}),attempt=client.restore(recovery);recovery.fill(0)`,
    "process.stdout.write('READY\\n');await lines.next()",
    "let result='SAVED';try{await store.save(attempt,AbortSignal.timeout(5000))}catch(error){result=error.code==='host.enrollment_recovery.conflict'?'CONFLICT':'ERROR'};await new Promise(resolve=>process.stdout.write(result+'\\n',resolve))",
    "attempt.destroy();store.close();client.close();master.fill(0);process.exit(0)", '',
  ].join('\n'), { mode: 0o600 })
  const runPair = async (first: ReturnType<typeof f.prepare>, second: ReturnType<typeof f.prepare>) => {
    const children = [first, second].map(attempt => {
      const child = spawn(resolve('node_modules/.bin/tsx'), [script], { cwd: f.root, env: { PATH: process.env.PATH ?? '', TMPDIR: f.root }, stdio: ['pipe', 'pipe', 'pipe'] })
      t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL') })
      const output = createInterface({ input: child.stdout })[Symbol.asyncIterator]()
      const exited = once(child, 'close')
      const recovery = attempt.exportRecovery()
      const material = Buffer.from(JSON.stringify({ master: f.master.toString('base64'), recovery: recovery.toString('base64') }) + '\n')
      recovery.fill(0); child.stdin.write(material, () => material.fill(0))
      return { child, output, exited }
    })
    for (const child of children) assert.equal((await child.output.next()).value, 'READY')
    for (const child of children) child.child.stdin.end('GO\n')
    const results = await Promise.all(children.map(async child => (await child.output.next()).value))
    for (const child of children) assert.deepEqual(await child.exited, [0, null])
    return results.sort()
  }
  const first = f.prepare(), second = f.prepare()
  assert.deepEqual(await runPair(first, second), ['CONFLICT', 'SAVED'])
  const winner = await f.store.load(AbortSignal.timeout(5_000))
  assert.ok(winner); assert.ok([first.requestId, second.requestId].includes(winner.requestId))
  assert.equal(await f.store.remove(winner, AbortSignal.timeout(5_000)), true); winner.destroy()
  const same = f.prepare()
  assert.deepEqual(await runPair(same, same), ['SAVED', 'SAVED'])
  const recovered = await f.store.load(AbortSignal.timeout(5_000))
  assert.equal(recovered?.requestId, same.requestId); recovered?.destroy()
})
