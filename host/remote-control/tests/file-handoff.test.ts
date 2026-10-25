import test from 'node:test'
import type { TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto'
import { createServer, type ServerResponse } from 'node:http'
import { host } from './harness.js'
import { DshClient, mobileSessionId } from '../src/dsh-client.js'
import type { SessionId } from '@deepseek-ai/dsh-session'
import { NativeFileRegistry } from '../src/file-registry.js'
import { RelayFiles } from '../src/relay-files.js'
import type { FileOffer } from '../src/file-protocol.js'

const owner = { userId: randomUUID(), deviceId: randomUUID() }
const missing = (error: unknown) => error instanceof Error && error.message === 'file.staging_required'
async function waitFor(read: () => boolean, milliseconds = 5000) {
  const until = Date.now() + milliseconds
  while (Date.now() < until) { if (read()) return; await new Promise(resolve => setTimeout(resolve, 10)) }
  assert.fail('timed out waiting for file handoff')
}

async function fixture(t: TestContext) {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const agent = await h.ctx.agents.create({ sessionId: randomUUID() as SessionId, meta: { cwd: h.cwd, agentPreset: 'fixture' }, agentOptions: { provider: 'fixture', model: 'fixture' } })
  const session = mobileSessionId(h.runtimeId, agent.agent.id)
  await client.checkpoint(agent.agent.id)
  const registry = new NativeFileRegistry(client, randomUUID())
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const lifetime = new AbortController()
  const installation = randomUUID(), connection = randomUUID()
  const body = Buffer.from('remote attachment bytes\x00\xff')
  const sent: any[] = [], proofs: any[] = []
  let reads = 0, sourceCancelled = false, failed = false
  let mode: 'bytes' | 'corrupt' | 'redirect' | 'hold' | 'encoded' = 'bytes'
  let held: ServerResponse | undefined
  const server = createServer((request, response) => {
    reads++
    const proof = String(request.headers['x-dsh-file-proof']).split('.')
    assert.equal(proof.length, 3)
    const claims = JSON.parse(Buffer.from(proof[1]!, 'base64url').toString())
    assert.deepEqual(JSON.parse(Buffer.from(proof[0]!, 'base64url').toString()), { typ: 'dsh-file-read-proof+jwt', alg: 'ES256' })
    assert.equal(verify('sha256', Buffer.from(`${proof[0]}.${proof[1]}`), { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(proof[2]!, 'base64url')), true)
    assert.equal(claims.htm, 'GET'); assert.equal(claims.htu, `${origin}${request.url}`)
    assert.equal(claims.iss, installation); assert.equal(claims.connection_id, connection)
    assert.equal(claims.runtime_id, client.runtimeId); assert.equal(claims.runtime_epoch, registry.epoch)
    assert.equal(claims.ath, createHash('sha256').update(String(request.headers.authorization).slice('DSH-File '.length)).digest('base64url'))
    proofs.push(claims)
    if (mode === 'redirect') { response.writeHead(302, { location: '/leaked-ticket' }); response.end(); return }
    response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(body.length), ...(mode === 'encoded' ? { 'content-encoding': 'gzip' } : {}) })
    if (mode === 'hold') { held = response; request.on('close', () => { sourceCancelled = true }); response.flushHeaders(); return }
    response.end(mode === 'corrupt' ? Buffer.alloc(body.length, 1) : body)
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address(); assert.ok(address && typeof address === 'object')
  const origin = `http://127.0.0.1:${address.port}`
  const relay = new RelayFiles(registry, { installationId: installation, connectionId: connection, origin,
    signer: { sign(input) { return sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }) } }, signal: lifetime.signal,
    async send(frame) { sent.push(frame) }, fail() { failed = true } })
  t.after(async () => { lifetime.abort(); relay.close(); registry.close(); held?.destroy(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); await h.close() })
  const makeOffer = (lease = 5000): FileOffer => ({ handoff_id: randomUUID(), file_id: randomUUID(), ...ownerToWire(),
    key_version: 1, grant_version: 1, name: 'attachment.txt', sha256: createHash('sha256').update(body).digest('hex'), size_bytes: body.length,
    download_token: Buffer.alloc(32, 1).toString('base64url'), lease_until: new Date(Date.now() + lease).toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString() })
  const deliver = (offer: FileOffer) => relay.handle({ v: 1, type: 'file.offer', request_id: randomUUID(), runtime_id: client.runtimeId, runtime_epoch: registry.epoch, session_id: session, payload: offer })
  const ack = (frame: any, payload = frame.payload) => relay.handle({ ...frame, type: `${frame.type}.ack`, payload: { handoff_id: payload.handoff_id, file_id: payload.file_id } })
  const renew = (frame: any, leases: any[]) => relay.handle({ ...frame, type: 'file.renewed', payload: { leases } })
  return { h, client, session, agent, registry, relay, body, lifetime, sent, proofs, makeOffer, deliver, ack, renew,
    mode(value: typeof mode) { mode = value }, get reads() { return reads }, get cancelled() { return sourceCancelled }, get failed() { return failed } }
}
function ownerToWire() { return { user_id: owner.userId, device_id: owner.deviceId } }

test('protected handoff verifies bytes in the real Loader, binds native receipt to actor/session and waits for stage ack', async t => {
  const f = await fixture(t), offer = f.makeOffer()
  await f.deliver(offer)
  await waitFor(() => f.sent.some(frame => frame.type === 'file.staged'))
  const staged = f.sent.find(frame => frame.type === 'file.staged')
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, owner), missing)
  await assert.rejects(f.ack(staged, { ...staged.payload, file_id: randomUUID() }), /acknowledgement/)
  await f.ack(staged)
  const part = f.registry.resolve(offer.file_id, f.session, owner)
  assert.equal(part.type, 'file')
  assert.throws(() => f.registry.resolve(offer.file_id, randomUUID(), owner), missing)
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, { ...owner, deviceId: randomUUID() }), missing)
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, { ...owner, userId: randomUUID() }), missing)
  assert.deepEqual(f.registry.resolve(offer.file_id, f.session, owner), part)
  const native = await f.client.resolve(f.session, f.lifetime.signal)
  if (part.type !== 'file') assert.fail('missing native receipt')
  const uploaded = f.h.ctx.fileUploads.resolve(f.h.ctx.agents.get(native)!, part.receiptId)
  assert.ok(uploaded)
  const received: Buffer[] = []
  for await (const bytes of f.h.ctx.attachments.readFileStream(uploaded)) received.push(Buffer.from(bytes))
  assert.deepEqual(Buffer.concat(received), f.body)
  assert.equal(JSON.stringify(f.sent).includes(part.receiptId), false)
  assert.equal(JSON.stringify(f.sent).includes(offer.download_token), false)
  assert.equal(JSON.stringify(f.sent).includes(f.h.cwd), false)
  assert.equal(f.proofs[0].file_id, offer.file_id)
  f.lifetime.abort()
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, owner), missing)
  assert.equal(f.client.fileStaged(native, part.receiptId), false)
})

test('hash mismatch, encoded source, redirect and expired offer never mint a usable native receipt', async t => {
  const f = await fixture(t)
  for (const mode of ['corrupt', 'encoded', 'redirect'] as const) {
    f.mode(mode)
    const offer = f.makeOffer()
    await f.deliver(offer)
    await waitFor(() => f.sent.some(frame => frame.type === 'file.release' && frame.payload.handoff_id === offer.handoff_id))
    assert.throws(() => f.registry.resolve(offer.file_id, f.session, owner), missing)
    assert.equal(f.sent.some(frame => frame.type === 'file.staged' && frame.payload.file_id === offer.file_id), false)
  }
  assert.equal(f.reads, 3, 'redirect target must never receive a request')
  await f.deliver(f.makeOffer(-1))
  await new Promise(resolve => setTimeout(resolve, 50))
  assert.equal(f.reads, 3)
  assert.equal(f.failed, false)
})

test('missing renewed authority cancels a stalled native download and allows later renewals', async t => {
  const f = await fixture(t)
  f.mode('hold')
  const offer = f.makeOffer()
  await f.deliver(offer)
  await waitFor(() => f.sent.some(frame => frame.type === 'file.renew'))
  await f.renew(f.sent.find(frame => frame.type === 'file.renew'), [])
  await waitFor(() => f.cancelled)
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, owner), missing)
  f.mode('bytes')
  const next = f.makeOffer()
  await f.deliver(next)
  await waitFor(() => f.sent.filter(frame => frame.type === 'file.renew').length >= 2)
  const renewed = f.sent.filter(frame => frame.type === 'file.renew').at(-1)
  await f.renew(renewed, [{ handoff_id: next.handoff_id, lease_until: new Date(Date.now() + 4500).toISOString(), expires_at: next.expires_at }])
  assert.equal(f.failed, false)
})

test('lost renewal replies expire all affected transfers without blocking subsequent offers', async t => {
  const f = await fixture(t), offer = f.makeOffer()
  await f.deliver(offer)
  await waitFor(() => f.sent.some(frame => frame.type === 'file.staged'))
  await f.ack(f.sent.find(frame => frame.type === 'file.staged'))
  f.registry.resolve(offer.file_id, f.session, owner)
  await waitFor(() => f.sent.some(frame => frame.type === 'file.release' && frame.payload.file_id === offer.file_id))
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, owner), missing)
  const count = f.sent.filter(frame => frame.type === 'file.renew').length
  await f.deliver(f.makeOffer())
  await waitFor(() => f.sent.filter(frame => frame.type === 'file.renew').length > count)
})

test('native session disposal removes receipt authority and a fresh handoff can restage', async t => {
  const f = await fixture(t), offer = f.makeOffer()
  await f.deliver(offer)
  await waitFor(() => f.sent.some(frame => frame.type === 'file.staged'))
  await f.ack(f.sent.find(frame => frame.type === 'file.staged'))
  const original = f.registry.resolve(offer.file_id, f.session, owner)
  const native = await f.client.resolve(f.session, f.lifetime.signal)
  await f.client.checkpoint(native)
  await f.agent.dispose()
  assert.throws(() => f.registry.resolve(offer.file_id, f.session, owner), missing)
  const next = { ...f.makeOffer(), file_id: offer.file_id }
  await f.deliver(next)
  await waitFor(() => f.sent.some(frame => frame.type === 'file.staged' && frame.payload.handoff_id === next.handoff_id))
  await f.ack(f.sent.find(frame => frame.type === 'file.staged' && frame.payload.handoff_id === next.handoff_id))
  assert.notDeepEqual(f.registry.resolve(next.file_id, f.session, owner), original)
})
