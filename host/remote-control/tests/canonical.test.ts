import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { canonicalObject, canonicalJSON } from '../src/canonical.js'

test('JCS matches the shared Go/TypeScript Unicode and numeric vectors and rejects ambiguous JSON', async () => {
  const vectors = JSON.parse(await readFile(new URL('../../../contracts/security/jcs-vectors.json', import.meta.url), 'utf8')) as Array<{
    name: string; input?: string; input_base64?: string; canonical?: string; sha256?: string; invalid?: boolean
  }>
  for (const vector of vectors) {
    const input = vector.input_base64 ? Buffer.from(vector.input_base64, 'base64') : vector.input!
    if (vector.invalid) { assert.throws(() => canonicalJSON(input), vector.name); continue }
    const encoded = canonicalJSON(input)
    assert.equal(Buffer.from(encoded).toString('utf8'), vector.canonical, vector.name)
    assert.equal(createHash('sha256').update(encoded).digest('hex'), vector.sha256, vector.name)
  }
})

test('signing values are bounded inert JSON without getters, toJSON, cycles or unsupported values', () => {
  let called = false
  const getter = Object.defineProperty({}, 'value', { enumerable: true, get() { called = true; return 1 } })
  const cyclic: { self?: unknown } = {}; cyclic.self = cyclic
  for (const value of [getter, cyclic, { toJSON() { called = true; return {} } }, { n: Infinity }, { n: NaN }, { b: 1n }, { value: undefined },
    { s: '\ud800' }, new Date(), new Map(), { a: Array(3) }, { s: 'x'.repeat(128 * 1024 + 1) }]) {
    assert.throws(() => canonicalObject(value))
  }
  assert.equal(called, false)
  let nested: unknown = { value: true }
  for (let index = 0; index < 40; index++) nested = { next: nested }
  assert.throws(() => canonicalObject(nested))
  assert.throws(() => canonicalJSON(JSON.stringify(nested)))
})
