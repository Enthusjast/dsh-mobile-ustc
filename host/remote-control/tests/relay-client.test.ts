import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createPrivateKey, generateKeyPairSync, sign, verify } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { once } from 'node:events'
import { hostHelloDigest, relayPayloadDigest, startHostRelay } from '../src/relay-client.js'
import { mobileSessionId, type SessionCatalogChange } from '../src/dsh-client.js'

const ws = createRequire(import.meta.url)('ws') as { WebSocketServer: new (options: object) => any }
const runtimeId = '33333333-3333-4333-8333-333333333333'
const runtimeEpoch = '44444444-4444-4444-8444-444444444444'
const sessionId = '55555555-5555-4555-8555-555555555555'
const requestId = '66666666-6666-4666-8666-666666666666'
const userId = '77777777-7777-4777-8777-777777777777'
const deviceId = '22222222-2222-4222-8222-222222222222'

function decodePart(value: string): any { return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) }

async function waitFor(predicate: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.fail('timed out waiting for Relay event')
}

test('host hello digest matches the Go length-prefixed protocol golden', () => {
  assert.equal(hostHelloDigest([
    'host', runtimeId, runtimeEpoch, '0.2.1-rc.2', '1.2.3', '0.0.1', '1',
    ['command.relay.v1', 'connection.heartbeat.v1', 'session.catalog.v1'].join('\n'),
  ]), 'dR6VN0kayU_d0sHLIYNLHe97lBZ9n9pQhKfwTM4gR8c')
})

test('Relay shutdown does not wait on a credential provider that ignores cancellation', async () => {
  const runtime = {
    epoch: runtimeEpoch,
    client: { runtimeId, async sessionCatalog() { return [] }, watchSessionCatalog() { return () => {} } },
    async dispatch() { throw new Error('unused') },
  }
  const relay = startHostRelay({
    url: 'ws://127.0.0.1:1', runtime, dshVersion: '0.2.1-rc.2', applicationVersion: 'test', pluginVersion: '0.0.1',
    credentials: { acquire() { return new Promise(() => {}) } },
  })
  await relay.close()
})

test('Relay host client proves the installation key and routes only digest-matching text frames', async t => {
  const { publicKey, privateKey: generatedPrivateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const privateJwk = generatedPrivateKey.export({ format: 'jwk' })
  const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' })
  const httpServer = createServer()
  const webSocketServer = new ws.WebSocketServer({ server: httpServer })
  await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve))
  const address = httpServer.address()
  assert.ok(address && typeof address === 'object')
  const url = `ws://127.0.0.1:${address.port}/v1/realtime`
  const credential = 'A'.repeat(43)
  const installationId = '88888888-8888-4888-8888-888888888888'
  const challengeId = '99999999-9999-4999-8999-999999999999'
  const connectionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  const nonce = Buffer.alloc(32, 7).toString('base64url')
  const payload = { mode: 'queue' as const, content: [{ type: 'text' as const, text: 'Continue the current task.' }] }
  const catalog = Array.from({ length: 300 }, (_, index) => ({
    session_id: mobileSessionId(runtimeId, `native:workspace/session-${index}`), dsh_session_id: `native:workspace/session-${index}`,
    workspace_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', state: 'running' as const, last_persisted_seq: 17,
  }))
  const forwarded = {
    v: 1, type: 'message.submit', request_id: requestId, runtime_id: runtimeId,
    runtime_epoch: runtimeEpoch, session_id: sessionId, user_id: userId, device_id: deviceId,
    payload_sha256: relayPayloadDigest(sessionId, payload), payload,
  }
  const received: unknown[] = []
  const catalogPages: any[] = []
  const catalogSnapshots = new Map<string, any[]>()
  let catalogChanged: ((change: SessionCatalogChange) => void) | undefined
  const routed: { command: unknown; owner: unknown }[] = []
  let relaySocket: any
  let helloClaims: any
  const ready = new Promise<void>((resolve, reject) => {
    webSocketServer.on('connection', (socket: any, request: any) => {
      relaySocket = socket
      if (request.headers.authorization !== `DSH-Host ${credential}`) reject(new Error('missing host Authorization header'))
      socket.send(JSON.stringify({ v: 1, type: 'challenge', payload: {
        connection_id: connectionId, challenge_id: challengeId, nonce, role: 'installation',
        expires_at: new Date(Date.now() + 10_000).toISOString(),
      } }))
      socket.on('message', (raw: Buffer) => {
        const frame = JSON.parse(raw.toString('utf8'))
        received.push(frame)
        if (frame.type === 'hello.proof') {
          const [headerPart, payloadPart, signaturePart] = frame.payload.proof.split('.')
          const signingInput = `${headerPart}.${payloadPart}`
          const claims = decodePart(payloadPart)
          const valid = decodePart(headerPart).typ === 'dsh-relay-handshake-proof+jwt'
            && claims.iss === installationId && claims.aud === 'urn:dsh-mobile-ustc:realtime'
            && claims.challenge_id === challengeId && claims.connection_id === connectionId
            && claims.nonce === nonce && claims.runtime_id === runtimeId && claims.runtime_epoch === runtimeEpoch
            && claims.hello_sha256 === 'dR6VN0kayU_d0sHLIYNLHe97lBZ9n9pQhKfwTM4gR8c'
            && verify('sha256', Buffer.from(signingInput), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signaturePart, 'base64url'))
          if (!valid) return reject(new Error('host hello proof did not match the challenge'))
          helloClaims = claims
          socket.send(JSON.stringify({ v: 1, type: 'hello.ok', payload: {
            role: 'host', connection_id: connectionId, installation_id: installationId,
            runtime_id: runtimeId, runtime_epoch: runtimeEpoch, protocol_version: 1, protocols: [1],
            capabilities: ['command.relay.v1', 'connection.heartbeat.v1', 'session.catalog.v1'], server_time: new Date().toISOString(),
            heartbeat_seconds: 20, max_frame_bytes: 65_536, lease_expires_at: new Date(Date.now() + 300_000).toISOString(),
          } }))
          resolve()
        }
        if (frame.type === 'session.catalog') {
          catalogPages.push(frame)
          const snapshot = catalogSnapshots.get(frame.request_id) ?? []
          snapshot.push(...frame.payload.items)
          catalogSnapshots.set(frame.request_id, snapshot)
          if (frame.payload.complete) socket.send(JSON.stringify({
            v: 1, type: 'session.catalog.ack', request_id: frame.request_id,
            runtime_id: runtimeId, runtime_epoch: runtimeEpoch,
            payload: {
              session_count: snapshot.length,
              server_time: new Date().toISOString(),
            },
          }))
        }
      })
    })
  })
  t.after(async () => {
    webSocketServer.close()
    httpServer.close()
    await once(httpServer, 'close').catch(() => {})
  })

  const runtime = {
    epoch: runtimeEpoch,
    client: {
      runtimeId,
      async sessionCatalog(_signal: AbortSignal, ids?: readonly string[]) {
        return ids === undefined ? catalog : catalog.filter(item => ids.includes(item.dsh_session_id))
      },
      watchSessionCatalog(onChange: (change: SessionCatalogChange) => void) { catalogChanged = onChange; return () => { catalogChanged = undefined } },
    },
    async dispatch(command: unknown, signal: AbortSignal, owner: unknown, observe?: (state: 'host_accepted' | 'dispatching' | 'agent_queued') => void | Promise<void>) {
      signal.throwIfAborted()
      routed.push({ command, owner })
      await observe?.('host_accepted')
      await observe?.('dispatching')
      await observe?.('agent_queued')
    },
  }
  const relay = startHostRelay({
    url, runtime, dshVersion: '0.2.1-rc.2', applicationVersion: '1.2.3', pluginVersion: '0.0.1',
    credentials: { async acquire() {
      return {
        installationId, credential,
        signer: { sign(input: Uint8Array) { return sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }) } },
      }
    } },
  })
  try {
    await Promise.race([ready, new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Relay handshake timed out')), 3000))])
    await waitFor(() => catalogPages.some(page => page.payload.complete))
    assert.deepEqual(catalogPages.flatMap(page => page.payload.items), catalog)
    assert.ok(catalogPages.length > 1)
    assert.ok(catalogPages.every(page => page.payload.items.length <= 256 && Buffer.byteLength(JSON.stringify(page)) <= 65_536))
    catalogChanged?.({ kind: 'delta', sessionIds: catalog.map(item => item.dsh_session_id) })
    await waitFor(() => catalogPages.some(page => page.payload.mode === 'delta' && page.payload.complete))
    assert.deepEqual(catalogPages.filter(page => page.payload.mode === 'delta').flatMap(page => page.payload.items), catalog)
    assert.equal(helloClaims.iat <= Math.floor(Date.now() / 1000), true)
    relaySocket.send(JSON.stringify(forwarded))
    await waitFor(() => routed.length === 1 && received.filter(frame => (frame as { type?: string }).type === 'command.receipt').length === 3)
    assert.deepEqual(routed[0]?.owner, { userId, deviceId })
    assert.deepEqual(routed[0]?.command, {
      v: 0, type: 'message.submit', request_id: requestId, runtime_epoch: runtimeEpoch,
      session_id: sessionId, payload,
    })
    assert.deepEqual(received.filter(frame => (frame as { type?: string }).type === 'command.receipt').map((frame: any) => frame.payload.state),
      ['host_accepted', 'dispatching', 'agent_queued'])
    assert.ok(received.filter(frame => (frame as { type?: string }).type === 'command.receipt')
      .every((frame: any) => frame.payload.payload_sha256 === forwarded.payload_sha256))

    relaySocket.send(JSON.stringify({ ...forwarded, payload_sha256: createHash('sha256').update('tampered').digest('hex') }))
    await waitFor(() => relaySocket.readyState !== 1)
    assert.equal(routed.length, 1)
  } finally {
    await relay.close()
  }
})
