import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { calculateJwkThumbprint } from 'jose'
import { host } from './harness.js'
import { createRemoteControlPlugin, type HostConnectionCredential } from '../src/index.js'

test('the signed plugin starts with Relay only and unload aborts an uncooperative credential provider', async () => {
  const h = await host({ probe: false })
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const publicJWK = keys.publicKey.export({ format: 'jwk' }) as { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  let started!: () => void, aborted = false
  const acquiring = new Promise<void>(resolve => { started = resolve })
  const plugin = createRemoteControlPlugin({ async acquire(signal) {
    started(); signal.addEventListener('abort', () => { aborted = true }, { once: true })
    return await new Promise<HostConnectionCredential>(() => {})
  } }, { hostId: randomUUID(), installationId: randomUUID(), policyVersion: 7, requiredAssurance: { profile: 'fixture/verified', max_auth_age_seconds: 60 },
    authorities: [{ issuer: 'https://remote.example.edu', key_id: 'dsh-approval-authority/plugin-test', public_jwk: publicJWK, key_jkt: await calculateJwkThumbprint(publicJWK), active: true,
      valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 3600_000).toISOString() }] })
  try {
    await h.ctx.plugin(plugin, { enabled: true, runtimeId: h.runtimeId, relayUrl: 'http://127.0.0.1:1', applicationVersion: 'fixture',
      commandJournalPath: join(h.directory, 'relay-only', 'commands.sqlite'), workspaces: [{ id: 'fixture', cwd: h.cwd, remoteId: randomUUID() }], presets: ['fixture'] })
    await acquiring
    await h.ctx.fiber.dispose()
    assert.equal(aborted, true)
    assert.equal(h.errors.length, 0)
  } finally { await h.close() }
})
