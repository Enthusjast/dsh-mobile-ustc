import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { InteractionRouter } from '../src/interaction-router.js'
import { RelayQuestionReferences } from '../src/relay-question-references.js'
import { questionReferencesFrame, type LocalQuestionReference, type QuestionReferenceSource } from '../src/question-reference-protocol.js'

async function until(check: () => boolean) {
  const deadline = Date.now() + 3000
  while (Date.now() < deadline) { if (check()) return; await delay(5) }
  throw new Error('question metadata did not arrive')
}

test('ordinary reference ownership and end events do not require a foreground session watcher', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const agent = h.ctx.agents.get(await client.resolve(created.session_id, new AbortController().signal))!
  const source = new InteractionRouter(h.ctx, h.runtimeId, candidate => candidate === agent, [], 2000)
  let changes = 0
  const stop = source.watchReferences(() => { changes++ })
  try {
    const first = h.ctx.userQuestions.ask({ agent, questions: [{ id: 'one', question: 'PRIVATE_QUESTION_ONE' }] })
    const second = h.ctx.userQuestions.ask({ agent, questions: [{ id: 'two', question: 'PRIVATE_QUESTION_TWO' }] })
    const references = source.references()
    assert.equal(references.length, 2)
    assert.equal(new Set(references.map(item => item.reference.question_id)).size, 2)
    assert.ok(references.every(item => item.nativeSessionId === agent.id && item.reference.session_id === created.session_id))
    assert.ok(!JSON.stringify(references).includes('PRIVATE_QUESTION'))
    source.answerQuestion(created.session_id, references[0]!.reference.question_id, { answers: [{ id: 'one', selected: [], custom: 'PRIVATE_ANSWER' }] })
    await first
    assert.equal(source.references().length, 1)
    stop()
    source.answerQuestion(created.session_id, references[1]!.reference.question_id, { answers: [{ id: 'two', selected: [], custom: 'answer' }] })
    await second
    assert.equal(source.references().length, 0)
    assert.equal(changes, 3)
  } finally { stop(); source.close(); await h.close() }
})

function fixture() {
  const listeners = new Set<() => void>(), lifetime = new AbortController()
  let items: LocalQuestionReference[] = []
  const source: QuestionReferenceSource = { references: () => structuredClone(items), watchReferences(changed) { listeners.add(changed); return () => { listeners.delete(changed) } } }
  const sent: ReturnType<typeof questionReferencesFrame.parse>[] = [], catalog: string[] = []
  const runtime = randomUUID(), epoch = randomUUID()
  let failed = 0
  const peer = new RelayQuestionReferences(source, { runtimeId: runtime, epoch, signal: lifetime.signal,
    async publishCatalog(native) { catalog.push(native) }, async send(value) { sent.push(questionReferencesFrame.parse(value)) }, fail() { failed++ } }, 600, 1500)
  const acknowledge = async () => {
    const frame = sent.at(-1)!
    return peer.handle({ ...frame, type: 'question.references.ack', payload: { sequence: frame.payload.sequence, item_count: frame.payload.items.length } })
  }
  return { peer, sent, catalog, listeners, lifetime, acknowledge, failed: () => failed,
    set(next: LocalQuestionReference[]) { items = next; listeners.forEach(listener => listener()) },
    item(): LocalQuestionReference { return { nativeSessionId: 'PRIVATE_NATIVE_SESSION', reference: { question_id: randomUUID(), session_id: randomUUID(), kind: 'question', state: 'pending', expires_at: new Date(Date.now() + 60_000).toISOString() } } },
  }
}

test('runtime snapshots are acknowledged, leased and coalesced without losing independent same-session IDs', async () => {
  const h = fixture()
  try {
    await until(() => h.sent.length === 1)
    assert.deepEqual(h.sent[0]!.payload.items, [])
    const first = h.item(), second = { ...h.item(), reference: { ...h.item().reference, session_id: first.reference.session_id } }
    h.set([first, second])
    await delay(120)
    assert.equal(h.sent.length, 1, 'an unacknowledged snapshot was bypassed')
    await h.acknowledge(); await until(() => h.sent.length === 2)
    assert.equal(h.sent[1]!.payload.sequence, 2)
    assert.equal(h.sent[1]!.payload.items.length, 2)
    assert.ok(!JSON.stringify(h.sent).includes('PRIVATE_NATIVE_SESSION'))
    assert.ok(h.catalog.includes('PRIVATE_NATIVE_SESSION'))
    await h.acknowledge()
    await until(() => h.sent.length >= 3)
    assert.equal(h.sent[2]!.payload.sequence, 3, 'an unchanged snapshot did not renew its lease')
    assert.equal(h.catalog.length, 1, 'lease renewal unnecessarily touched native session persistence')
    await h.acknowledge()
  } finally { h.peer.close(); assert.equal(h.listeners.size, 0); h.lifetime.abort() }
})

test('wrong acknowledgements and missing acknowledgements cannot silently authorize a feed', async () => {
  const h = fixture()
  try {
    await until(() => h.sent.length === 1)
    const frame = h.sent[0]!
    await assert.rejects(h.peer.handle({ ...frame, type: 'question.references.ack', runtime_epoch: randomUUID(), payload: { sequence: 1, item_count: 0 } }), /route mismatch/)
    await assert.rejects(h.peer.handle({ ...frame, type: 'question.references.ack', payload: { sequence: 1, item_count: 1 } }), /acknowledgement mismatch/)
    await until(() => h.failed() === 1)
    assert.equal(h.listeners.size, 0)
    assert.equal(h.sent.length, 1)
  } finally { h.peer.close(); h.lifetime.abort() }
})

test('question reference transport refuses bodies and invalid native-state combinations', async () => {
  const h = fixture()
  try {
    const item = h.item()
    h.set([{ ...item, reference: { ...item.reference, questions: 'PRIVATE_BODY' } as unknown as LocalQuestionReference['reference'] }])
    await until(() => h.failed() === 1)
    assert.deepEqual(h.sent, [])
    assert.equal(h.listeners.size, 0)
    assert.equal(questionReferencesFrame.safeParse({ v: 1, type: 'question.references', request_id: randomUUID(), runtime_id: randomUUID(), runtime_epoch: randomUUID(),
      payload: { sequence: 1, items: [{ ...item.reference, kind: 'timed_question', state: 'continued' }] } }).success, false)
  } finally { h.peer.close(); h.lifetime.abort() }
})
