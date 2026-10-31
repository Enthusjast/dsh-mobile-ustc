import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MacOSKeychainInstallationSigner, type MacOSKeychainInstallationSignerOptions } from '../src/macos-keychain-installation-signer.js'

test('Keychain installation signer refuses unsupported platforms before reading an item', { skip: process.platform === 'darwin' }, () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const publicJwk = pair.publicKey.export({ format: 'jwk' }) as MacOSKeychainInstallationSignerOptions['publicJwk']
  assert.throws(() => new MacOSKeychainInstallationSigner({ executable: '/not-invoked', keychainPath: '/not-invoked', service: 'fixture', account: 'fixture', publicJwk, ownerSignal: new AbortController().signal }), /Keychain signing unavailable/)
})

test('Darwin signing protocol fixture verifies registered identity, encoding, owner cancellation and limits', { skip: process.platform === 'win32', timeout: 25_000 }, async t => {
  const child = fileURLToPath(new URL('./fixtures/macos-keychain-signer-child.ts', import.meta.url))
  for (const mode of ['sign', 'errors', 'owner']) {
    await t.test(mode, async t => {
      const root = await mkdtemp(join(tmpdir(), 'dsh-keychain-sign-'))
      t.after(() => rm(root, { recursive: true, force: true }))
      const result = spawnSync(process.execPath, ['--import', 'tsx', child, mode], { env: { ...process.env, MACOS_KEYCHAIN_SIGNER_ROOT: root }, encoding: 'utf8', timeout: 10_000, maxBuffer: 128 * 1024 })
      assert.equal(result.status, 0, result.stderr)
      const facts = JSON.parse(result.stdout.trim()) as { mode: string; operations: number; platform: string; keychain_sha256: string }
      assert.equal(facts.mode, mode); assert.ok(facts.operations > 0); assert.equal(facts.platform, 'darwin-protocol-fixture')
      assert.equal(facts.keychain_sha256, createHash('sha256').update('opaque-signer-keychain').digest('hex'))
    })
  }
})
