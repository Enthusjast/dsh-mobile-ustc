import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { FileFrame, fileReadProof } from '../src/file-protocol.js'

const load = async (path: string) => JSON.parse(await readFile(new URL(`../../../contracts/${path}`, import.meta.url), 'utf8'))
test('shared Host file handoff goldens match generated schema and strict runtime frames', async () => {
  const ajv = new Ajv2020({ strict: true, allErrors: true })
  ajv.addFormat('uuid', /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
  ajv.addFormat('date-time', (value: string) => Number.isFinite(Date.parse(value)))
  const validate = ajv.compile(await load('ws/v1/file-handoff.schema.json'))
  for (const type of ['file.offer', 'file.renew', 'file.renewed', 'file.staged', 'file.staged.ack', 'file.release', 'file.release.ack']) {
    const golden = await load(`ws/v1/golden/${type}.json`)
    assert.equal(validate(golden), true, ajv.errorsText(validate.errors))
    assert.deepEqual(FileFrame.parse(golden), golden)
    for (const changed of [{ ...golden, receipt_id: 'native-private' }, { ...golden, payload: { ...golden.payload, path: '/private/file' } }]) {
      assert.equal(validate(changed), false)
      assert.equal(FileFrame.safeParse(changed).success, false)
    }
  }
})
test('Node file read proof interoperates with Go pinned-key proof golden', async t => {
  const fixture = await load('security/file-read-proof.json')
  const privateKey = createPrivateKey({ key: fixture.private_jwk, format: 'jwk' })
  const publicKey = createPublicKey({ key: fixture.public_jwk, format: 'jwk' })
  const valid = (compact: string) => {
    const parts = compact.split('.')
    assert.equal(verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2]!, 'base64url')), true)
    assert.deepEqual(JSON.parse(Buffer.from(parts[0]!, 'base64url').toString()), fixture.header)
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString())
  }
  assert.deepEqual(valid(fixture.compact), fixture.claims)
  t.mock.method(Date, 'now', () => Date.parse(fixture.now))
  const fresh = await fileReadProof({ sign(input) { return sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }) } }, fixture.identity)
  const claims = valid(fresh)
  assert.match(claims.jti, /^[0-9a-f-]{36}$/)
  assert.deepEqual({ ...claims, jti: fixture.claims.jti }, fixture.claims)
})
