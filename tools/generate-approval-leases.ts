/** Explicit fixture regeneration; all generated private keys remain in memory. */
import { createPrivateKey, sign } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { existsSync } from 'node:fs'
import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair } from 'jose'
import { canonicalObject } from '../host/remote-control/src/canonical.js'
import { APPROVAL_AUTHORIZATION_AUDIENCE, APPROVAL_AUTHORIZATION_DOMAIN, APPROVAL_AUTHORIZATION_JWS_TYPE } from '../host/remote-control/src/approval-lease.js'

const source = JSON.parse(await readFile(new URL('../contracts/security/approval-signatures.json', import.meta.url), 'utf8'))
const decision = source.vectors.find((item: any) => item.name === 'node-signed-allow')
const context = source.context
const now = Date.parse(source.now), utc = (value: number) => new Date(value).toISOString()
const pair = await generateKeyPair('ES256', { extractable: true })
const publicJWK = await exportJWK(pair.publicKey)
const authority = { issuer: 'https://remote.example.edu', key_id: 'dsh-approval-authority/node-fixture', public_jwk: publicJWK,
  key_jkt: await calculateJwkThumbprint(publicJWK), active: true, valid_from: utc(now - 3600_000), valid_until: utc(now + 3600_000) }
const lease = {
  domain: APPROVAL_AUTHORIZATION_DOMAIN, protocol_version: 1, issuer: authority.issuer, audience: APPROVAL_AUTHORIZATION_AUDIENCE,
  ...Object.fromEntries(['host_id', 'installation_id', 'runtime_id', 'runtime_epoch', 'session_id', 'approval_id', 'execution_id'].map(field => [field, context[field]])),
  connection_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', lease_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', action: 'approval.decide', role: 'owner',
  binding_sha256: source.binding_sha256, decision_payload_sha256: decision.payload_sha256, policy_version: context.policy_version,
  user_id: source.registered.user_id, device_id: source.registered.device_id, key_version: source.registered.key_version,
  approval_key_jkt: source.registered.approval_key_jkt, approval_public_jwk: source.registered.public_jwk, grant_version: 4,
  assurance_profile: context.required_assurance.profile, authenticated_at: utc(now - 60_000), issued_at: utc(now), expires_at: utc(now + 3000),
}
const header = { alg: 'ES256', kid: authority.key_id, typ: APPROVAL_AUTHORIZATION_JWS_TYPE }
const nodeKey = createPrivateKey({ key: await exportJWK(pair.privateKey), format: 'jwk' })
const rawSigned = (head: Uint8Array, payload: Uint8Array, der = false) => {
  const input = `${Buffer.from(head).toString('base64url')}.${Buffer.from(payload).toString('base64url')}`
  return `${input}.${sign('sha256', Buffer.from(input), { key: nodeKey, dsaEncoding: der ? 'der' : 'ieee-p1363' }).toString('base64url')}`
}
const signed = (value: unknown) => rawSigned(canonicalObject(header), canonicalObject(value))
const valid = await new CompactSign(canonicalObject(lease)).setProtectedHeader(header).sign(pair.privateKey)
const go = process.env.REMOTE_TEST_GO || (existsSync('/opt/go1.26.10/bin/go') ? '/opt/go1.26.10/bin/go' : 'go')
const goFixture = JSON.parse(execFileSync(go, ['run', './internal/approval/testdata/generate'], {
  cwd: fileURLToPath(new URL('../services/remote', import.meta.url)), input: canonicalObject(lease), encoding: 'utf8', stdio: ['pipe', 'pipe', 'inherit'],
}))
const vectors: any[] = [{ name: 'node-signed-authorization', compact: valid, authority: 0 }, { name: 'go-signed-authorization', compact: goFixture.compact, authority: 1 }]
const rejected = source.vectors.find((item: any) => item.name === 'node-signed-reject')
vectors.push({ name: 'node-signed-rejection-authorization', compact: signed({ ...lease, decision_payload_sha256: rejected.payload_sha256 }), decision_jws: rejected.compact, authority: 0 })
const add = (name: string, mutate: (value: any) => void) => { const changed = structuredClone(lease); mutate(changed); vectors.push({ name, compact: signed(changed), authority: 0, invalid: true }) }
const other = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
for (const field of ['host_id', 'installation_id', 'runtime_id', 'runtime_epoch', 'session_id', 'approval_id', 'execution_id', 'connection_id', 'user_id', 'device_id']) add(`wrong-${field}`, value => { value[field] = other })
for (const [name, value] of Object.entries({ domain: 'other', protocol_version: 2, issuer: 'https://attacker.example', audience: 'other', role: 'operator', action: 'grant.manage',
  binding_sha256: 'd'.repeat(64), decision_payload_sha256: 'd'.repeat(64), policy_version: 3, key_version: 3, grant_version: 0, approval_key_jkt: 'A'.repeat(43), assurance_profile: 'weaker',
  authenticated_at: utc(now - 301_000), issued_at: utc(now + 1), expires_at: utc(now + 3001), lease_id: 'not-a-uuid' })) add(`wrong-${name}`, lease => { lease[name] = value })
add('future-authentication', value => { value.authenticated_at = utc(now + 1) })
add('expires-before-issue', value => { value.expires_at = value.issued_at })
add('embedded-key-url', value => { value.approval_public_jwk.jku = 'https://attacker.example/key' })
add('embedded-private-material', value => { value.approval_public_jwk.d = 'private' })
add('embedded-key-case-alias', value => { value.approval_public_jwk.KTY = value.approval_public_jwk.kty; delete value.approval_public_jwk.kty })
add('embedded-unknown-key', value => { value.approval_public_jwk = publicJWK; value.approval_key_jkt = authority.key_jkt })
for (const [name, change] of Object.entries({ typ: 'other', kid: 'dsh-approval-authority/untrusted', alg: 'HS256', jku: 'https://attacker.example', jwk: publicJWK, crit: ['exp'] })) {
  vectors.push({ name: `header-${name}`, compact: rawSigned(canonicalObject({ ...header, [name]: change }), canonicalObject(lease)), authority: 0, invalid: true })
}
const payload = Buffer.from(canonicalObject(lease)).toString()
for (const [name, raw] of Object.entries({
  'case-alias': payload.replace('"runtime_id":', '"RUNTIME_ID":'),
  'duplicate-member': payload.replace('{', '{"issuer":"https://attacker.example",'),
  'noncanonical-json': JSON.stringify(lease),
  'lone-surrogate': payload.replace('approval.decide', 'approval.decide\\ud800'),
})) vectors.push({ name, compact: rawSigned(canonicalObject(header), Buffer.from(raw)), authority: 0, invalid: true })
vectors.push({ name: 'noncanonical-header', compact: rawSigned(Buffer.from(JSON.stringify({ typ: header.typ, kid: header.kid, alg: header.alg })), canonicalObject(lease)), authority: 0, invalid: true })
vectors.push({ name: 'duplicate-header', compact: rawSigned(Buffer.from(Buffer.from(canonicalObject(header)).toString().replace('{', '{"alg":"none",')), canonicalObject(lease)), authority: 0, invalid: true })
vectors.push({ name: 'der-signature', compact: rawSigned(canonicalObject(header), canonicalObject(lease), true), authority: 0, invalid: true })
vectors.push({ name: 'padded-jws', compact: valid + '=', authority: 0, invalid: true })
vectors.push({ name: 'wrong-phone-decision', compact: valid, decision_jws: source.vectors.find((item: any) => item.name === 'node-signed-reject').compact, authority: 0, invalid: true })
for (const [name, changes] of Object.entries({ 'revoked-authority': { active: false }, 'wrong-authority-jkt': { key_jkt: 'A'.repeat(43) }, 'expired-authority': { valid_until: utc(now) },
  'authority-expires-before-lease': { valid_until: utc(now + 1000) }, 'future-authority': { valid_from: utc(now + 1) }, 'wrong-authority-issuer': { issuer: 'https://attacker.example' } })) {
  vectors.push({ name, compact: valid, authority: 0, trusted_overrides: changes, invalid: true })
}
vectors.push({ name: 'lease-expiry-boundary', compact: valid, now: utc(now + 3000), authority: 0, invalid: true })
await writeFile(new URL('../contracts/security/approval-leases.json', import.meta.url), JSON.stringify({ now: source.now, context, decision_jws: decision.compact, connection_id: lease.connection_id,
  lease, authorities: [authority, goFixture.authority], vectors }, null, 2) + '\n')
process.stdout.write(`Wrote ${vectors.length} public authorization vectors; private keys were not persisted.\n`)
