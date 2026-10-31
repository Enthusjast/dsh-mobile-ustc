import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MacOSKeychainJournalProtector } from '../src/macos-keychain-journal-protector.js'

test('Keychain factory refuses a non-macOS host without invoking helpers', { skip: process.platform === 'darwin' }, () => {
  assert.throws(() => new MacOSKeychainJournalProtector({ executable: '/not-invoked/security', keychainPath: '/not-invoked/login.keychain-db', service: 'fixture', account: 'fixture' }), /Keychain protection unavailable/)
})

test('Darwin command protocol fixture covers wrapping, persistence, errors, file boundaries and bounded cancellation', { skip: process.platform === 'win32', timeout: 30_000 }, async t => {
  const child = fileURLToPath(new URL('./fixtures/macos-keychain-child.ts', import.meta.url))
  for (const mode of ['roundtrip', 'errors', 'permissions', 'cancel', 'slots']) {
    await t.test(mode, async t => {
      const root = await mkdtemp(join(tmpdir(), 'dsh-keychain-'))
      t.after(() => rm(root, { recursive: true, force: true }))
      const result = spawnSync(process.execPath, ['--import', 'tsx', child, mode], { env: { ...process.env, MACOS_KEYCHAIN_FIXTURE_ROOT: root }, encoding: 'utf8', timeout: 12_000, maxBuffer: 128 * 1024 })
      assert.equal(result.status, 0, result.stderr)
      const facts = JSON.parse(result.stdout.trim()) as { mode: string; operations: number; platform: string; keychain_sha256: string }
      assert.equal(facts.mode, mode); assert.ok(facts.operations > 0); assert.equal(facts.platform, 'darwin-protocol-fixture')
      assert.equal(facts.keychain_sha256, createHash('sha256').update('opaque-fixture-keychain').digest('hex'))
    })
  }
})
