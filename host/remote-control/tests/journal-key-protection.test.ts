import test from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto'
import { link, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Context } from '@deepseek-ai/cordis'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { apply, createRemoteControlPlugin } from '../src/index.js'
import type { JournalKeyProtector } from '../src/journal-key-protection.js'
import { parseCommand } from '../src/protocol.js'
import { host } from './harness.js'

const owner = { userId: 'fixture-user', deviceId: 'fixture-device' }

function fixtureProtector(master: Buffer, id = 'fixture-platform-v1'): JournalKeyProtector {
  return {
    id,
    async wrap(key, context) {
      const nonce = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', master, nonce)
      cipher.setAAD(context)
      return Buffer.concat([nonce, cipher.update(key), cipher.final(), cipher.getAuthTag()])
    },
    async unwrap(wrapped, context) {
      const bytes = Buffer.from(wrapped)
      if (bytes.length !== 60) throw new Error('invalid fixture ciphertext')
      const decipher = createDecipheriv('aes-256-gcm', master, bytes.subarray(0, 12))
      decipher.setAAD(context)
      decipher.setAuthTag(bytes.subarray(44))
      return Buffer.concat([decipher.update(bytes.subarray(12, 44)), decipher.final()])
    },
  }
}

function command(text: string, requestID = randomUUID()) {
  return parseCommand({ v: 0, type: 'message.submit', request_id: requestID, runtime_epoch: randomUUID(),
    session_id: '55555555-5555-4555-8555-555555555555', payload: { mode: 'queue', text } })
}

async function absent(path: string): Promise<boolean> {
  try { await lstat(path); return false } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true
    throw error
  }
}

test('protected journal keeps only a wrapped key and requires its protector after restart', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-protected-journal-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const master = randomBytes(32)
  t.after(() => master.fill(0))
  const protector = fixtureProtector(master), runtime = randomUUID(), path = join(root, 'commands.sqlite')
  const input = command('PRIVATE_WRAPPED_COMMAND')
  let journal = await PersistentCommandJournal.open(path, runtime, { protector })
  journal.admit(input, owner)
  journal.close()
  assert.equal(await absent(`${path}.key`), true)
  assert.equal((await lstat(`${path}.wrapped-key`)).mode & 0o777, 0o600)
  const envelope = await readFile(`${path}.wrapped-key`)
  assert.equal(envelope.includes(master), false)
  assert.equal(envelope.includes(Buffer.from('PRIVATE_WRAPPED_COMMAND')), false)
  assert.equal((await readFile(path)).includes(Buffer.from('PRIVATE_WRAPPED_COMMAND')), false)
  await assert.rejects(PersistentCommandJournal.open(path, runtime), /requires its configured key protector/)
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: fixtureProtector(randomBytes(32)) }), /key protection unavailable/)
  await assert.rejects(PersistentCommandJournal.open(path, randomUUID(), { protector }), /key protection unavailable/)
  journal = await PersistentCommandJournal.open(path, runtime, { protector })
  assert.deepEqual(journal.get(input.request_id, owner)?.command, input)
  journal.close()
})

test('legacy key migrates only after database verification and interrupted migration reconciles', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-key-migrate-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtime = randomUUID(), path = join(root, 'commands.sqlite'), input = command('PRIVATE_LEGACY_COMMAND')
  let journal = await PersistentCommandJournal.open(path, runtime)
  journal.admit(input, owner)
  journal.close()
  const original = await readFile(`${path}.key`)
  t.after(() => original.fill(0))
  const wrong = Buffer.from(original)
  wrong[0] = wrong[0]! ^ 1
  await writeFile(`${path}.key`, wrong, { mode: 0o600 })
  const master = randomBytes(32)
  t.after(() => master.fill(0))
  const protector = fixtureProtector(master)
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector }), /journal.integrity_failed/)
  assert.equal(await absent(`${path}.wrapped-key`), true)
  assert.deepEqual(await readFile(`${path}.key`), wrong)
  await writeFile(`${path}.key`, original, { mode: 0o600 })
  journal = await PersistentCommandJournal.open(path, runtime, { protector })
  assert.deepEqual(journal.get(input.request_id, owner)?.command, input)
  journal.close()
  assert.equal(await absent(`${path}.key`), true)
  await writeFile(`${path}.key`, original, { mode: 0o600 })
  let unwraps = 0
  const unstable: JournalKeyProtector = {
    id: protector.id,
    wrap: protector.wrap.bind(protector),
    async unwrap(value, context, signal) {
      unwraps++
      if (unwraps === 2) return new Uint8Array(32).fill(0xff)
      return protector.unwrap(value, context, signal)
    },
  }
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: unstable }), /key protection unavailable/)
  assert.deepEqual(await readFile(`${path}.key`), original)
  journal = await PersistentCommandJournal.open(path, runtime, { protector })
  journal.close()
  assert.equal(await absent(`${path}.key`), true)
  await writeFile(`${path}.key`, wrong, { mode: 0o600 })
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector }), /key protection unavailable/)
  assert.deepEqual(await readFile(`${path}.key`), wrong)
  wrong.fill(0)
})

test('protected key is bound to the exact journal path and refuses corrupt envelopes', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-key-binding-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const master = randomBytes(32)
  t.after(() => master.fill(0))
  const protector = fixtureProtector(master), runtime = randomUUID(), path = join(root, 'commands.sqlite')
  const journal = await PersistentCommandJournal.open(path, runtime, { protector })
  journal.close()
  const envelope = await readFile(`${path}.wrapped-key`)
  const duplicate = join(root, 'copy.sqlite')
  await writeFile(duplicate, await readFile(path), { mode: 0o600 })
  await writeFile(`${duplicate}.wrapped-key`, envelope, { mode: 0o600 })
  await assert.rejects(PersistentCommandJournal.open(duplicate, runtime, { protector }), /key protection unavailable/)
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: fixtureProtector(master, 'another-provider') }), /key protection unavailable/)
  const badID = Buffer.from(envelope)
  badID[9] = badID[9]! ^ 0x80
  await writeFile(`${path}.wrapped-key`, badID, { mode: 0o600 })
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector }), /key protection unavailable/)
  const damaged = Buffer.from(envelope)
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1
  await writeFile(`${path}.wrapped-key`, damaged, { mode: 0o600 })
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector }), /key protection unavailable/)
  await assert.rejects(PersistentCommandJournal.open(path, runtime), /requires its configured key protector/)
  assert.equal(await absent(`${path}.key`), true)
})

test('legacy migration refuses a key with another hard link', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-hardlink-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtime = randomUUID(), path = join(root, 'commands.sqlite'), master = randomBytes(32)
  t.after(() => master.fill(0))
  const journal = await PersistentCommandJournal.open(path, runtime)
  journal.close()
  const second = join(root, 'linked-key')
  await link(`${path}.key`, second)
  const protector = fixtureProtector(master)
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector }), /key protection unavailable/)
  assert.equal(await absent(`${path}.wrapped-key`), true)
  assert.deepEqual(await readFile(`${path}.key`), await readFile(second))
  await rm(second)
  const migrated = await PersistentCommandJournal.open(path, runtime, { protector })
  migrated.close()
  assert.equal(await absent(`${path}.key`), true)
})

test('wrapped-key symlinks never replace or delete either source', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-key-symlink-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtime = randomUUID(), path = join(root, 'commands.sqlite'), master = randomBytes(32)
  t.after(() => master.fill(0))
  const journal = await PersistentCommandJournal.open(path, runtime)
  journal.close()
  const legacy = await readFile(`${path}.key`), outside = join(root, 'outside')
  t.after(() => legacy.fill(0))
  await writeFile(outside, 'PRIVATE_UNRELATED_FILE', { mode: 0o600 })
  await symlink(outside, `${path}.wrapped-key`)
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: fixtureProtector(master) }), /key protection unavailable/)
  await assert.rejects(PersistentCommandJournal.open(path, runtime), /requires its configured key protector/)
  assert.deepEqual(await readFile(`${path}.key`), legacy)
  assert.equal(await readFile(outside, 'utf8'), 'PRIVATE_UNRELATED_FILE')
})

test('protected key creation handles concurrent open without publishing a partial key', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-key-race-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const master = randomBytes(32)
  t.after(() => master.fill(0))
  const protector = fixtureProtector(master), runtime = randomUUID(), path = join(root, 'commands.sqlite')
  const outcomes = await Promise.allSettled(Array.from({ length: 4 }, () => PersistentCommandJournal.open(path, runtime, { protector })))
  const opened = outcomes.filter((item): item is PromiseFulfilledResult<PersistentCommandJournal> => item.status === 'fulfilled')
  assert.ok(opened.length > 0)
  for (const item of opened) item.value.close()
  const journal = await PersistentCommandJournal.open(path, runtime, { protector })
  const input = command('PRIVATE_RACE_COMMAND')
  journal.admit(input, owner)
  journal.close()
  const recovered = await PersistentCommandJournal.open(path, runtime, { protector })
  assert.deepEqual(recovered.get(input.request_id, owner)?.command, input)
  recovered.close()
  assert.equal(await absent(`${path}.key`), true)
  assert.equal((await readdir(root)).some(name => name.endsWith('.tmp')), false)
})

test('concurrent legacy and protected initialization preserves data on a key conflict', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-mixed-race-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const master = randomBytes(32)
  t.after(() => master.fill(0))
  const base = fixtureProtector(master), runtime = randomUUID(), path = join(root, 'commands.sqlite')
  let started!: () => void, release!: () => void
  const ready = new Promise<void>(resolve => { started = resolve })
  const gate = new Promise<void>(resolve => { release = resolve })
  const gated: JournalKeyProtector = {
    id: base.id,
    async wrap(key, context, signal) { started(); await gate; return base.wrap(key, context, signal) },
    unwrap: base.unwrap.bind(base),
  }
  const protectedOpening = PersistentCommandJournal.open(path, runtime, { protector: gated })
  await ready
  const input = command('PRIVATE_MIXED_MODE_COMMAND')
  const legacy = await PersistentCommandJournal.open(path, runtime)
  legacy.admit(input, owner)
  legacy.close()
  release()
  await assert.rejects(protectedOpening, /journal.integrity_failed/)
  assert.equal(await absent(`${path}.key`), false)
  assert.equal(await absent(`${path}.wrapped-key`), false)
  await assert.rejects(PersistentCommandJournal.open(path, runtime), /requires its configured key protector/)
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: base }), /key protection unavailable/)
  // Only the fixture-created, known conflicting envelope is removed here.
  await rm(`${path}.wrapped-key`)
  const recovered = await PersistentCommandJournal.open(path, runtime)
  assert.deepEqual(recovered.get(input.request_id, owner)?.command, input)
  recovered.close()
})

test('cancelled or broken protectors fail closed and do not publish plaintext keys', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-key-cancel-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtime = randomUUID(), path = join(root, 'commands.sqlite')
  const controller = new AbortController()
  let seen: Uint8Array | undefined
  let resolveLate: ((value: Uint8Array) => void) | undefined
  let started: (() => void) | undefined
  const ready = new Promise<void>(resolve => { started = resolve })
  const protector: JournalKeyProtector = {
    id: 'fixture-cancel-v1',
    wrap(key) { seen = key; started?.(); return new Promise(resolve => { resolveLate = resolve }) },
    async unwrap() { throw new Error('PRIVATE_PROTECTOR_ERROR') },
  }
  const opening = PersistentCommandJournal.open(path, runtime, { protector, signal: controller.signal })
  await ready
  controller.abort()
  await assert.rejects(opening, error => error instanceof Error && /key protection unavailable/.test(error.message) && !error.message.includes('PRIVATE_PROTECTOR_ERROR'))
  assert.ok(seen && seen.every(byte => byte === 0))
  const late = new Uint8Array(60).fill(7)
  resolveLate?.(late)
  await new Promise(resolve => setImmediate(resolve))
  assert.ok(late.every(byte => byte === 0))
  assert.equal(await absent(`${path}.key`), true)
  assert.equal(await absent(`${path}.wrapped-key`), true)
  assert.equal(await absent(path), true)
  const broken: JournalKeyProtector = {
    id: 'fixture-broken-v1',
    async wrap() { throw new Error('PRIVATE_PROTECTOR_ERROR') },
    async unwrap() { throw new Error('not reached') },
  }
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: broken }), error => error instanceof Error && /key protection unavailable/.test(error.message) && !error.message.includes('PRIVATE_PROTECTOR_ERROR'))
  const inconsistent: JournalKeyProtector = {
    id: 'fixture-inconsistent-v1',
    async wrap() { return new Uint8Array(60).fill(8) },
    async unwrap() { return new Uint8Array(32).fill(9) },
  }
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: inconsistent }), /key protection unavailable/)
  const oversized = new Uint8Array(16 * 1024 + 1).fill(6)
  const tooLarge: JournalKeyProtector = {
    id: 'fixture-oversized-v1',
    async wrap() { return oversized },
    async unwrap() { throw new Error('not reached') },
  }
  await assert.rejects(PersistentCommandJournal.open(path, runtime, { protector: tooLarge }), /key protection unavailable/)
  assert.ok(oversized.every(byte => byte === 0))
  assert.equal(await absent(`${path}.wrapped-key`), true)
  assert.equal(await absent(`${path}.key`), true)
  assert.equal(await absent(path), true)
})

test('configured protected-key requirement fails before starting a plugin without a protector', async () => {
  await assert.rejects(apply({} as Context, { enabled: true, runtimeId: randomUUID(), socketPath: '/tmp/dsh-test-only.sock', requireProtectedJournalKey: true }), /requires a journal key protector/)
})

test('plugin disposal cancels a pending protector without waiting for its promise', { skip: process.platform === 'win32', timeout: 5_000 }, async () => {
  const h = await host({ probe: false })
  let started!: () => void, aborted = false, seen: Uint8Array | undefined
  const ready = new Promise<void>(resolve => { started = resolve })
  const protector: JournalKeyProtector = {
    id: 'fixture-uncooperative-v1',
    wrap(key, _context, signal) {
      seen = key
      signal.addEventListener('abort', () => { aborted = true }, { once: true })
      started()
      return new Promise(() => {})
    },
    async unwrap() { throw new Error('not reached') },
  }
  const path = join(h.directory, 'protected', 'commands.sqlite')
  const plugin = createRemoteControlPlugin({ async acquire() { throw new Error('not reached') } }, undefined, protector)
  try {
    const fiber = h.ctx.plugin(plugin, { enabled: true, runtimeId: h.runtimeId, socketPath: h.socketPath, commandJournalPath: path,
      requireProtectedJournalKey: true, workspaces: [{ id: 'fixture', cwd: h.cwd, remoteId: randomUUID() }], presets: ['fixture'] })
    await ready
    let timer: NodeJS.Timeout | undefined
    try {
      await Promise.race([fiber.dispose(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('plugin disposal waited for protector')), 1_000) })])
    } finally { if (timer) clearTimeout(timer) }
    assert.equal(aborted, true)
    assert.ok(seen && seen.every(byte => byte === 0))
    assert.equal(await absent(`${path}.key`), true)
    assert.equal(await absent(`${path}.wrapped-key`), true)
    assert.equal(await absent(path), true)
  } finally { await h.close() }
})

test('credential-owner cancellation stops pending protected journal startup', { skip: process.platform === 'win32', timeout: 5_000 }, async () => {
  const h = await host({ probe: false })
  const ownerLifetime = new AbortController()
  let started!: () => void, aborted = false
  const ready = new Promise<void>(resolve => { started = resolve })
  const protector: JournalKeyProtector = {
    id: 'fixture-account-cancel-v1',
    wrap(_key, _context, signal) {
      signal.addEventListener('abort', () => { aborted = true }, { once: true })
      started()
      return new Promise(() => {})
    },
    async unwrap() { throw new Error('not reached') },
  }
  const path = join(h.directory, 'protected-account', 'commands.sqlite')
  const plugin = createRemoteControlPlugin({ signal: ownerLifetime.signal, async acquire() { throw new Error('not reached') } }, undefined, protector)
  try {
    const fiber = h.ctx.plugin(plugin, { enabled: true, runtimeId: h.runtimeId, socketPath: h.socketPath, commandJournalPath: path,
      requireProtectedJournalKey: true, workspaces: [{ id: 'fixture', cwd: h.cwd, remoteId: randomUUID() }], presets: ['fixture'] })
    await ready
    ownerLifetime.abort()
    await assert.rejects(fiber.await(), /key protection unavailable/)
    assert.equal(aborted, true)
    assert.equal(await absent(`${path}.key`), true)
    assert.equal(await absent(`${path}.wrapped-key`), true)
    assert.equal(await absent(path), true)
    await fiber.dispose()
  } finally { await h.close() }
})
