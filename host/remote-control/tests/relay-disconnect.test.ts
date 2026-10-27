import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { setTimeout as delay } from 'node:timers/promises'
import { relayPayloadDigest, startHostRelay, type HostHandshakeSigner, type HostRelayOptions } from '../src/relay-client.js'
import type { Command } from '../src/protocol.js'

const ws = createRequire(import.meta.url)('ws') as { WebSocketServer: new (options: object) => any }
const runtimeId = '33333333-3333-4333-8333-333333333333'
const epoch = '44444444-4444-4444-8444-444444444444'
const sessionId = '55555555-5555-4555-8555-555555555555'
const installationId = '88888888-8888-4888-8888-888888888888'

async function until(predicate: () => boolean, timeout = 2000): Promise<void> {
  const end = Date.now() + timeout
  while (!predicate()) {
    if (Date.now() >= end) assert.fail('Host did not retire its disconnected frame queue')
    await delay(5)
  }
}

async function fixture(t: test.TestContext, dispatch: HostRelayOptions['runtime']['dispatch'], options: { signer?: HostHandshakeSigner; waitReady?: boolean } = {}) {
  const http = createServer()
  const server = new ws.WebSocketServer({ server: http })
  const sockets: any[] = []
  const hellos: string[] = []
  const headers: string[] = []
  const receipts: any[][] = []
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  server.on('connection', (socket: any, request: any) => {
    sockets.push(socket)
    headers.push(request.headers.authorization)
    const received: any[] = []
    receipts.push(received)
    const connectionId = randomUUID()
    socket.on('message', (raw: Buffer) => {
      const frame = JSON.parse(raw.toString('utf8'))
      if (frame.type === 'command.receipt') received.push(frame)
      if (frame.type !== 'hello.proof') return
      hellos.push(connectionId)
      socket.send(JSON.stringify({ v: 1, type: 'hello.ok', payload: {
        role: 'host', connection_id: connectionId, installation_id: installationId,
        runtime_id: runtimeId, runtime_epoch: epoch, protocol_version: 1, protocols: [1],
        capabilities: ['command.relay.v1', 'connection.heartbeat.v1'], server_time: new Date().toISOString(),
        heartbeat_seconds: 20, max_frame_bytes: 65_536, lease_expires_at: new Date(Date.now() + 60_000).toISOString(),
      } }))
    })
    socket.send(JSON.stringify({ v: 1, type: 'challenge', payload: {
      connection_id: connectionId, challenge_id: randomUUID(), nonce: Buffer.alloc(32, 7).toString('base64url'),
      role: 'installation', expires_at: new Date(Date.now() + 10_000).toISOString(),
    } }))
  })
  await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve))
  const address = http.address()
  assert.ok(address && typeof address === 'object')
  let acquisitions = 0
  const relay = startHostRelay({
    url: `ws://127.0.0.1:${address.port}/v1/realtime`,
    dshVersion: '0.2.1-rc.2', applicationVersion: 'bounded-disconnect-fixture', pluginVersion: 'test',
    runtime: { epoch, client: { runtimeId, async sessionCatalog() { return [] }, watchSessionCatalog() { return () => {} } }, async *follow() {}, dispatch },
    credentials: { async acquire() { acquisitions++; return {
      installationId, credential: (acquisitions === 1 ? 'A' : 'B').repeat(43),
      signer: options.signer ?? { sign(input: Uint8Array) { return sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }) } },
    } } },
  })
  t.after(async () => {
    await relay.close()
    for (const socket of sockets) socket.terminate()
    await new Promise<void>(resolve => server.close(resolve))
    await new Promise<void>(resolve => http.close(() => resolve()))
  })
  if (options.waitReady !== false) await until(() => hellos.length === 1)
  const command = (text = 'bounded original command') => {
    const payload = { mode: 'queue' as const, content: [{ type: 'text' as const, text }] }
    return { v: 1, type: 'message.submit', request_id: randomUUID(), runtime_id: runtimeId, runtime_epoch: epoch,
      session_id: sessionId, user_id: '77777777-7777-4777-8777-777777777777', device_id: '22222222-2222-4222-8222-222222222222',
      payload_sha256: relayPayloadDigest(sessionId, payload), payload }
  }
  return { sockets, hellos, headers, receipts, command, relay }
}

test('Host shutdown does not wait for a pending handshake signature or send its late result', async t => {
  let signing = false
  let release!: (value: Uint8Array) => void
  const signature = new Promise<Uint8Array>(resolve => { release = resolve })
  const peer = await fixture(t, async () => { assert.fail('signing did not authenticate a runtime') }, {
    waitReady: false,
    signer: { sign() { signing = true; return signature } },
  })
  await until(() => signing)
  try {
    let closed = false
    const closing = peer.relay.close().then(() => { closed = true })
    await until(() => closed, 750)
    await closing
    release(new Uint8Array(64))
    await delay(20)
    assert.deepEqual(peer.hellos, [], 'retired signature was sent after connection shutdown')
  } finally { release(new Uint8Array(64)) }
})

test('Host reconnect does not await an uncooperative dispatch or send its late receipt on the new socket', async t => {
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  let active: AbortSignal | undefined
  let lateFinished = false
  const peer = await fixture(t, async (_command, signal, _owner, observe) => {
    active = signal
    try { await held; await observe?.('agent_queued') }
    finally { lateFinished = true }
  })
  try {
    const command = peer.command()
    peer.sockets[0].send(JSON.stringify(command))
    await until(() => active !== undefined)
    peer.sockets[0].close(1012, 'retire blocked native call')
    await until(() => active?.aborted === true, 750)
    await until(() => peer.hellos.length === 2, 3000)
    release()
    await until(() => lateFinished)
    await delay(20)
    assert.deepEqual(peer.receipts, [[], []], 'late receipt crossed connection ownership')
  } finally { release() }
})

test('server draining retires the old queue before any trailing command', async t => {
  const routed: string[] = []
  const peer = await fixture(t, async command => { routed.push(command.request_id) })
  peer.sockets[0].send(JSON.stringify({ v: 1, type: 'server.draining', payload: {} }))
  peer.sockets[0].send(JSON.stringify(peer.command('trailing retired command')))
  await until(() => peer.hellos.length === 2, 3000)
  assert.deepEqual(routed, [])
})

for (const scenario of ['transport-close', 'frame-limit', 'byte-limit'] as const) {
  test(`Host retires a blocked dispatch and queued commands on ${scenario}`, async t => {
    const routed: string[] = []
    let activeSignal: AbortSignal | undefined
    const peer = await fixture(t, async (command: Command, signal: AbortSignal) => {
      routed.push(command.request_id)
      if (routed.length !== 1) return
      activeSignal = signal
      await new Promise<void>(resolve => {
        signal.addEventListener('abort', () => resolve(), { once: true })
        if (signal.aborted) resolve()
      })
      signal.throwIfAborted()
    })
    const original = peer.command()
    peer.sockets[0].send(JSON.stringify(original))
    await until(() => routed.length === 1)
    const queued = Array.from({ length: scenario === 'frame-limit' ? 34 : scenario === 'byte-limit' ? 10 : 4 }, () =>
      peer.command(scenario === 'byte-limit' ? '界'.repeat(20_000) : 'queued on retired transport'))
    for (const frame of queued) peer.sockets[0].send(JSON.stringify(frame))
    if (scenario === 'transport-close') peer.sockets[0].close(1012, 'bounded reconnect fixture')
    await until(() => activeSignal?.aborted === true, 750)
    await until(() => peer.sockets[0].readyState === 3)
    assert.deepEqual(routed, [original.request_id], 'retired transport dispatched its buffered commands')
    await until(() => peer.hellos.length >= 2, 3000)
    assert.equal(peer.hellos.length, 2)
    assert.notEqual(peer.hellos[0], peer.hellos[1])
    assert.deepEqual(peer.headers, [`DSH-Host ${'A'.repeat(43)}`, `DSH-Host ${'B'.repeat(43)}`])
    await delay(30)
    assert.deepEqual(routed, [original.request_id], 'reconnect replayed a prior connection queue')
    const fresh = peer.command('explicit operation after fresh handshake')
    peer.sockets[1].send(JSON.stringify(fresh))
    await until(() => routed.length === 2)
    assert.deepEqual(routed, [original.request_id, fresh.request_id])
  })
}
