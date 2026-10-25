import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { readFile } from 'node:fs/promises'
import { startHostRelay } from '../src/relay-client.js'
import type { ProbeRuntime } from '../src/runtime.js'
import { ProbeError } from '../src/protocol.js'

const ws = createRequire(import.meta.url)('ws') as { WebSocketServer: new (options: object) => any }

test('Relay file reconciliation uses only the dedicated read-only runtime entry', async () => {
  const frame = JSON.parse(await readFile(new URL('../../../contracts/ws/v1/golden/message-file-reconcile.forwarded.json', import.meta.url), 'utf8'))
  const installation = '88888888-8888-4888-8888-888888888888'
  const connection = '11111111-1111-4111-8111-111111111111'
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey
  const http = createServer()
  const server = new ws.WebSocketServer({ server: http })
  let calls = 0, admissions = 0, closed = 0
  let timer: NodeJS.Timeout | undefined
  const result = new Promise<any>((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('read-only Relay route timed out')), 5000)
    server.on('connection', (socket: any) => {
      socket.send(JSON.stringify({ v: 1, type: 'challenge', payload: { connection_id: connection,
        challenge_id: '22222222-2222-4222-8222-222222222222', nonce: 'A'.repeat(43), role: 'installation', expires_at: new Date(Date.now() + 10_000).toISOString() } }))
      socket.on('message', (raw: Buffer) => {
        const incoming = JSON.parse(raw.toString())
        if (incoming.type === 'hello.proof') {
          assert.ok(incoming.payload.capabilities.includes('message.files.reconcile.v1'))
          socket.send(JSON.stringify({ v: 1, type: 'hello.ok', payload: { role: 'host', connection_id: connection,
            installation_id: installation, runtime_id: frame.runtime_id, runtime_epoch: frame.runtime_epoch,
            protocol_version: 1, protocols: [1], capabilities: incoming.payload.capabilities, server_time: new Date().toISOString(),
            heartbeat_seconds: 20, max_frame_bytes: 65536, lease_expires_at: new Date(Date.now() + 300_000).toISOString() } }))
          socket.send(JSON.stringify(frame))
        } else if (incoming.type === 'session.catalog' && incoming.payload.complete) {
          socket.send(JSON.stringify({ v: 1, type: 'session.catalog.ack', request_id: incoming.request_id,
            runtime_id: frame.runtime_id, runtime_epoch: frame.runtime_epoch, payload: { session_count: 0, server_time: new Date().toISOString() } }))
        } else if (incoming.type === 'command.receipt') resolve(incoming)
      })
    })
  })
  await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve))
  const address = http.address(); assert.ok(address && typeof address === 'object')
  const relay = startHostRelay({ url: `ws://127.0.0.1:${address.port}`, dshVersion: '0.2.1-rc.2', applicationVersion: 'fixture', pluginVersion: 'fixture',
    runtime: { epoch: frame.runtime_epoch, client: { runtimeId: frame.runtime_id, async sessionCatalog() { return [] }, watchSessionCatalog() { return () => {} } },
      async *follow() {}, async dispatch() { admissions++; assert.fail('reconciliation used ordinary dispatch') },
      async reconcileFileMessage(...[command, signal, owner, observe]: Parameters<ProbeRuntime['reconcileFileMessage']>) {
        calls++; assert.equal(command.type, 'message.submit'); assert.equal(command.request_id, frame.request_id)
        assert.deepEqual(command.payload, frame.payload); assert.equal(signal.aborted, false)
        assert.deepEqual(owner, { userId: frame.user_id, deviceId: frame.device_id })
        await observe?.('outcome_unknown'); throw new ProbeError('command.outcome_unknown')
      } },
    credentials: { async acquire() { return { installationId: installation, credential: 'A'.repeat(43), signer: { sign(input) { return sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }) } } } } },
    files() { return { async handle() { return false }, close() { closed++ } } },
  })
  try {
    const receipt = await result
    assert.equal(receipt.request_id, frame.request_id); assert.equal(receipt.payload.payload_sha256, frame.payload_sha256)
    assert.equal(receipt.payload.state, 'outcome_unknown'); assert.equal(calls, 1); assert.equal(admissions, 0)
  } finally {
    if (timer) clearTimeout(timer)
    await relay.close()
    for (const client of server.clients) client.terminate()
    server.close(); http.closeAllConnections()
    await new Promise<void>(resolve => http.close(() => resolve()))
  }
  assert.equal(closed, 1)
})
