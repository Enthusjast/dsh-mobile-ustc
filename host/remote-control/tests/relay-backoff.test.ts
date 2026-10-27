import test from 'node:test'
import assert from 'node:assert/strict'
import { HostReconnectBackoff } from '../src/relay-backoff.js'

test('Host reconnect failures are bounded and a short authenticated flap does not reset them', () => {
  let time = 0
  const backoff = new HostReconnectBackoff(() => time, () => 0)
  assert.deepEqual(Array.from({ length: 8 }, () => backoff.retryDelay()), [1000, 2000, 4000, 8000, 16_000, 32_000, 60_000, 60_000])
  backoff.connected()
  time = 29_999
  assert.equal(backoff.retryDelay(), 60_000)
})

test('a stable authenticated connection clears accumulated failure delay before lease renewal', () => {
  let time = 100
  const backoff = new HostReconnectBackoff(() => time, () => 0)
  for (let index = 0; index < 8; index++) backoff.retryDelay()
  backoff.connected()
  time += 30_000
  assert.equal(backoff.retryDelay(), 1000)
  assert.equal(backoff.retryDelay(), 2000, 'a later failed handshake reused an old stable connection marker')
})

test('Host jitter stays positive within the original quarter-window at the cap', () => {
  const backoff = new HostReconnectBackoff(() => 0, () => .999)
  assert.equal(backoff.retryDelay(), 1249)
  for (let index = 0; index < 7; index++) backoff.retryDelay()
  assert.equal(backoff.retryDelay(), 74_985)
})
