import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { RelaySessions, encodeSessionFrames, type SessionReaderRuntime } from '../src/relay-sessions.js'
import type { Frame } from '../src/protocol.js'

const runtimeId = randomUUID(), epoch = randomUUID(), sessionId = randomUUID(), subscriptionId = randomUUID(), requestId = randomUUID(), syncId = randomUUID()
const subscribe = {
  v: 1, type: 'session.subscribe', request_id: requestId, runtime_id: runtimeId, runtime_epoch: epoch,
  session_id: sessionId, subscription_id: subscriptionId, payload: { max_messages: 30 },
}

async function waitFor(predicate: () => boolean) {
  const deadline = Date.now() + 3000
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('session transport condition timed out')
    await new Promise(resolve => setTimeout(resolve, 5))
  }
}

test('session fragments preserve Unicode payloads and visible routing within the 64 KiB frame limit', () => {
  const payload = { cursor: 7, records: [{ text: '中文🙂'.repeat(20_000) }], assistant: null, has_more: true }
  const envelope = { ...subscribe, type: 'session.snapshot', sync_id: syncId, payload }
  const frames = encodeSessionFrames(envelope)
  assert.ok(frames.length > 1)
  const joined = Buffer.concat(frames.map((frame: any, index) => {
    assert.equal(frame.payload.index, index)
    assert.equal(frame.payload.count, frames.length)
    assert.equal(frame.subscription_id, subscriptionId)
    assert.equal(frame.sync_id, syncId)
    assert.ok(Buffer.byteLength(JSON.stringify(frame)) <= 65_536)
    return Buffer.from(frame.payload.data, 'base64')
  }))
  assert.deepEqual(JSON.parse(joined.toString('utf8')), payload)
  assert.throws(() => encodeSessionFrames({ ...envelope, payload: { text: 'x'.repeat(2 * 1024 * 1024) } }), /snapshot_too_large/)
})

test('host session reads retain sync identity, page on the same cut, and abort only the canceled follower', async () => {
  const sent: any[] = []
  const signals: AbortSignal[] = []
  const pages: unknown[] = []
  const runtime: SessionReaderRuntime = {
    epoch, client: { runtimeId },
    async *follow(command, signal) {
      signals.push(signal)
      yield { v: 0, type: 'session.snapshot', runtime_epoch: epoch, request_id: command.request_id,
        session_id: sessionId, sync_id: syncId, payload: { cursor: 7, has_more: true, records: [], assistant: null } }
      await once(signal, 'abort')
    },
    async dispatch(command) { pages.push(command); return { payload: { records: [], has_more: false, through_seq: 7 } } },
  }
  const transport = new RelaySessions(runtime, async frame => { sent.push(frame) })
  try {
    assert.equal(transport.handle(subscribe), true)
    await waitFor(() => sent.length === 1)
    assert.equal(sent[0].sync_id, syncId)
    const pageId = randomUUID()
    transport.handle({ ...subscribe, type: 'session.page', request_id: pageId,
      payload: { sync_id: syncId, through_seq: 7, before_seq: 8, max_messages: 5 } })
    await waitFor(() => sent.length === 2)
    assert.equal(sent[1].type, 'session.page.result')
    assert.equal(sent[1].request_id, pageId)
    assert.deepEqual(pages, [{ v: 0, type: 'session.page', request_id: pageId, runtime_epoch: epoch, session_id: sessionId,
      payload: { sync_id: syncId, through_seq: 7, before_seq: 8, max_messages: 5 } }])
    transport.handle({ ...subscribe, request_id: randomUUID(), subscription_id: randomUUID() })
    await waitFor(() => signals.length === 2)
    transport.handle({ ...subscribe, type: 'session.unsubscribe', payload: {} })
    assert.equal(signals[0]?.aborted, true)
    assert.equal(signals[1]?.aborted, false)
    transport.handle({ ...subscribe, type: 'session.page', request_id: randomUUID(), payload: { sync_id: syncId, through_seq: 7, before_seq: 8, max_messages: 5 } })
    await waitFor(() => sent.some(frame => frame.type === 'session.error'))
    assert.equal(sent.find(frame => frame.type === 'session.error').payload.code, 'protocol.resync_required')
    assert.throws(() => transport.handle({ ...subscribe, runtime_epoch: randomUUID() }), /runtime.changed/)
  } finally { transport.close() }
  assert.equal(signals[1]?.aborted, true)
})

test('a blocked socket cannot grow the native follower queue without bound', async () => {
  const sent: any[] = []
  let produced = 0
  let stopped = false
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  const runtime: SessionReaderRuntime = {
    epoch, client: { runtimeId },
    async *follow(_command, signal) {
      try {
        for (let index = 0; index < 200; index++) {
          signal.throwIfAborted()
          produced++
          yield { v: 0, type: index === 0 ? 'session.snapshot' : 'session.event', runtime_epoch: epoch,
            session_id: sessionId, sync_id: syncId, payload: { text: 'x'.repeat(60_000) } } as Frame
        }
      } finally { stopped = true }
    },
    async dispatch() { throw new Error('unused') },
  }
  const transport = new RelaySessions(runtime, async (frame: any) => {
    sent.push(frame)
    if (frame.type !== 'session.error') await held
  })
  try {
    transport.handle(subscribe)
    await waitFor(() => stopped && sent.some(frame => frame.type === 'session.error'))
    assert.ok(produced < 100, `${produced} native frames were read while the socket was blocked`)
    assert.equal(sent.find(frame => frame.type === 'session.error').payload.code, 'protocol.resync_required')
  } finally { transport.close(); release() }
})

test('timed UI claims stay bound to a negotiated subscription and release on explicit release, unsubscribe and socket close', async () => {
  const sent: any[] = [], claims: AbortSignal[] = []
  const runtime: SessionReaderRuntime = {
    epoch, client: { runtimeId },
    async *follow(command, signal) {
      yield { v: 0, type: 'session.snapshot', runtime_epoch: epoch, request_id: command.request_id, session_id: sessionId,
        sync_id: syncId, payload: { cursor: 0, records: [], has_more: false, assistant: null } }
      await once(signal, 'abort')
    },
    async dispatch() { throw new Error('unused') },
    async *claimQuestion(_session, _question, signal) {
      claims.push(signal)
      yield { remaining_ms: 1000, expires_at: new Date(Date.now() + 1000).toISOString() }
      await once(signal, 'abort')
    },
  }
  const transport = new RelaySessions(runtime, async frame => { sent.push(frame) }, true)
  try {
    transport.handle({ ...subscribe, payload: { max_messages: 30, timed_questions: true } })
    await waitFor(() => sent.some(frame => frame.type === 'session.snapshot'))
    const claimId = randomUUID(), questionId = randomUUID()
    const claim = { ...subscribe, type: 'question.claim', request_id: claimId, sync_id: syncId, payload: { question_id: questionId } }
    transport.handle({ ...claim, sync_id: randomUUID() })
    await waitFor(() => sent.some(frame => frame.type === 'session.error'))
    assert.equal(claims.length, 0)
    transport.handle(claim)
    await waitFor(() => sent.some(frame => frame.type === 'question.claimed'))
    assert.equal(sent.find(frame => frame.type === 'question.claimed').request_id, claimId)
    transport.handle({ ...claim, type: 'question.release', request_id: randomUUID(), payload: { claim_id: claimId } })
    await waitFor(() => claims[0]?.aborted === true)
    assert.throws(() => transport.handle(claim), /protocol.invalid/, 'retired claim identity was reused')
    transport.handle({ ...claim, request_id: randomUUID() })
    await waitFor(() => claims.length === 2)
    transport.handle({ ...subscribe, type: 'session.unsubscribe', payload: {} })
    assert.equal(claims[1]?.aborted, true)
    transport.handle({ ...subscribe, subscription_id: randomUUID(), payload: { max_messages: 30, timed_questions: true } })
    await waitFor(() => sent.filter(frame => frame.type === 'session.snapshot').length === 2)
    const nextSubscription = sent.filter(frame => frame.type === 'session.snapshot')[1].subscription_id
    transport.handle({ ...claim, subscription_id: nextSubscription, request_id: randomUUID() })
    await waitFor(() => claims.length === 3)
  } finally { transport.close() }
  assert.equal(claims[2]?.aborted, true)
})
