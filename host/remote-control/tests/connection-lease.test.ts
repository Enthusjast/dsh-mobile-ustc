import test from 'node:test'
import assert from 'node:assert/strict'
import { HostConnectionLease, type HostConnectionClock } from '../src/connection-lease.js'

const base = Date.UTC(2026, 9, 27, 8)
const at = (offset: number) => new Date(base + offset).toISOString()

function clock() {
  const state = { wall: base, monotonic: 100 }
  const source: HostConnectionClock = { wall: () => state.wall, monotonic: () => state.monotonic }
  return { state, source }
}

test('Host lease uses the shorter absolute and server-relative lifetime', () => {
  const { state, source } = clock()
  const ahead = new HostConnectionLease(at(10_000), at(11_000), source)
  assert.equal(ahead.remaining(), 1000, 'positive server skew extended the credential')
  const behind = new HostConnectionLease(at(-10_000), at(10_000), source)
  assert.equal(behind.remaining(), 10_000, 'negative server skew extended absolute expiry')
  state.monotonic += 1001
  assert.equal(ahead.remaining(), 0, 'frozen/rolled-back wall time extended elapsed authority')
})

test('Host lease rejects clock rollback and enforces forward wall time', () => {
  for (const change of ['wall-back', 'monotonic-back', 'wall-forward', 'invalid-clock'] as const) {
    const { state, source } = clock()
    const lease = new HostConnectionLease(at(0), at(5000), source)
    if (change === 'wall-back') state.wall--
    if (change === 'monotonic-back') state.monotonic--
    if (change === 'wall-forward') state.wall += 5000
    if (change === 'invalid-clock') state.wall = Number.NaN
    assert.equal(lease.remaining(), 0, change)
  }
})

test('Host lease bounds original authority to five minutes with finite thirty-second clock skew', () => {
  const { state, source } = clock()
  const maximum = new HostConnectionLease(at(0), at(300_000), source)
  assert.equal(maximum.remaining(), 300_000)
  for (const [server, expires] of [[at(0), at(300_001)], [at(30_001), at(31_000)], [at(-30_001), at(1000)], [at(0), at(0)], [at(0), at(-1)], ['invalid', at(1000)]]) {
    assert.throws(() => new HostConnectionLease(server!, expires!, source), /protocol.unsupported/)
  }
  state.monotonic += 300_000
  assert.equal(maximum.remaining(), 0)
})
