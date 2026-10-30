import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readModelPage, MAX_MODEL_PAGE_BYTES } from '../src/model-catalog.js'
import { RelaySessions } from '../src/relay-sessions.js'
import { once } from 'node:events'

const binding = () => ({ runtimeId: randomUUID(), runtimeEpoch: randomUUID(), sessionId: randomUUID(), syncId: randomUUID() })
const catalog = (count: number) => ({ default: { secret: 'PRIVATE_DEFAULT' }, failures: [{ message: 'PRIVATE_FAILURE' }],
  groups: [{ id: 'fixture', name: '目录', api_key: 'PRIVATE_KEY', models: Array.from({ length: count }, (_, index) => ({
    id: `model-${String(index).padStart(4, '0')}`, name: `模型 ${index}`, description: 'PRIVATE_DESCRIPTION',
    reasoning: { efforts: [{ id: 'high', name: '深入', description: 'PRIVATE_REASONING' }] },
  })).reverse() }] })

test('model pages are complete, ordered, bounded and omit configuration/default/failure messages', async () => {
  const owner = {}, scope = binding(), source = catalog(257)
  let cursor: string | undefined
  const ids: string[] = []
  do {
    const page = await readModelPage(owner, async () => source, scope, { sync_id: scope.syncId, limit: 25, ...(cursor ? { cursor } : {}) }, AbortSignal.timeout(2000))
    assert.ok(Buffer.byteLength(JSON.stringify(page)) <= MAX_MODEL_PAGE_BYTES)
    assert.equal(JSON.stringify(page).includes('PRIVATE_'), false)
    assert.equal(page.unavailable_provider_count, 1)
    ids.push(...page.items.map(item => item.model.id))
    cursor = page.next_cursor ?? undefined
  } while (cursor)
  assert.equal(ids.length, 257)
  assert.equal(new Set(ids).size, 257)
  assert.deepEqual(ids, [...ids].sort())
})

test('model cursors reject changed catalogs and other session/sync/epoch bindings', async () => {
  const owner = {}, scope = binding(), source = catalog(3)
  const page = await readModelPage(owner, async () => source, scope, { sync_id: scope.syncId, limit: 1 }, AbortSignal.timeout(2000))
  assert.ok(page.next_cursor)
  const request = { sync_id: scope.syncId, limit: 1, cursor: page.next_cursor }
  for (const changed of [{ ...scope, sessionId: randomUUID() }, { ...scope, syncId: randomUUID() }, { ...scope, runtimeEpoch: randomUUID() }, { ...scope, runtimeId: randomUUID() }])
    await assert.rejects(readModelPage(owner, async () => source, changed, request, AbortSignal.timeout(2000)), /protocol.resync_required/)
  source.groups[0]!.models[0]!.name = '更新'
  await assert.rejects(readModelPage(owner, async () => source, scope, request, AbortSignal.timeout(2000)), /protocol.resync_required/)
})

test('model page byte budget includes JSON escaping at the Relay', async () => {
  const scope = binding(), source = catalog(50)
  for (const model of source.groups[0]!.models) model.name = '<>&\u2028'.repeat(64)
  const page = await readModelPage({}, async () => source, scope, { sync_id: scope.syncId, limit: 50 }, AbortSignal.timeout(2000))
  assert.ok(page.next_cursor)
  assert.ok(page.items.length < 50)
  const escaped = JSON.stringify(page).replace(/[<>&\u2028\u2029]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'))
  assert.ok(Buffer.byteLength(escaped) <= MAX_MODEL_PAGE_BYTES)
})

test('cancelled callers share one outstanding native lookup until it actually settles', async () => {
  const owner = {}, scope = binding()
  let finish!: (value: unknown) => void, calls = 0
  const held = new Promise(resolve => { finish = resolve })
  const load = async () => { calls++; return held }
  const first = new AbortController()
  const request = { sync_id: scope.syncId, limit: 1 }
  const pending = readModelPage(owner, load, scope, request, first.signal)
  first.abort()
  await assert.rejects(pending)
  for (let index = 0; index < 5; index++) {
    const aborted = new AbortController()
    const waiter = readModelPage(owner, load, scope, request, aborted.signal)
    aborted.abort(); await assert.rejects(waiter)
  }
  assert.equal(calls, 1)
  const last = readModelPage(owner, load, scope, request, AbortSignal.timeout(2000))
  finish(catalog(2))
  assert.equal((await last).items.length, 1)
  assert.equal(calls, 1)
  await readModelPage(owner, async () => { calls++; return catalog(2) }, scope, request, AbortSignal.timeout(2000))
  assert.equal(calls, 2)
})

test('catalog duplicates and unbounded native metadata cannot produce a partial success', async () => {
  const scope = binding()
  for (const source of [catalog(8193), (() => { const source = catalog(2); source.groups[0]!.models[1]!.id = source.groups[0]!.models[0]!.id; return source })(),
    (() => { const source = catalog(1); source.groups[0]!.models[0]!.name = 'x'.repeat(257); return source })()])
    await assert.rejects(readModelPage({}, async () => source, scope, { sync_id: scope.syncId, limit: 50 }, AbortSignal.timeout(2000)))
})

test('subscription model reads bound concurrency and discard results after cancellation', async () => {
  const scope = binding(), owner = {}, sent: any[] = []
  let finish!: (value: unknown) => void, calls = 0
  const held = new Promise(resolve => { finish = resolve })
  const transport = new RelaySessions({ epoch: scope.runtimeEpoch, client: { runtimeId: scope.runtimeId,
    modelPage: (binding, request, signal) => readModelPage(owner, async () => { calls++; return held }, binding, request, signal) },
    async *follow(command, signal) {
      yield { v: 0, type: 'session.snapshot', request_id: command.request_id, runtime_epoch: scope.runtimeEpoch,
        session_id: scope.sessionId, sync_id: scope.syncId, payload: { cursor: -1, records: [], has_more: false, assistant: null } }
      await once(signal, 'abort')
    }, async dispatch() { throw new Error('catalog lookup became a command') },
  }, async frame => { sent.push(frame) }, false, true)
  const base = { v: 1, request_id: randomUUID(), runtime_id: scope.runtimeId, runtime_epoch: scope.runtimeEpoch,
    session_id: scope.sessionId, subscription_id: randomUUID() }
  try {
    transport.handle({ ...base, type: 'session.subscribe', payload: { max_messages: 5 } })
    await new Promise(resolve => setImmediate(resolve))
    for (let index = 0; index < 3; index++) transport.handle({ ...base, request_id: randomUUID(), type: 'session.models.get', payload: { sync_id: scope.syncId, limit: 1 } })
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(calls, 1)
    assert.equal(sent.filter(frame => frame.type === 'session.models.error' && frame.payload.code === 'rate.limited').length, 1)
    transport.close()
    finish(catalog(2))
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(sent.some(frame => frame.type === 'session.models.result'), false)
  } finally { transport.close(); finish(catalog(2)) }
})
