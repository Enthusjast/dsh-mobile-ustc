import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import * as askUser from '@deepseek-ai/dsh-tool-ask-user'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { InteractionRouter } from '../src/interaction-router.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand } from '../src/protocol.js'

async function until<T>(read: () => T | undefined): Promise<T> {
  const deadline = Date.now() + 3500
  while (Date.now() < deadline) { const value = read(); if (value !== undefined) return value; await delay(5) }
  throw new Error('native timed question did not reach expected state')
}

async function fixture() {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const agent = h.ctx.agents.get(await client.resolve(created.session_id, new AbortController().signal))!
  const interactions = new InteractionRouter(h.ctx, h.runtimeId, candidate => candidate === agent, [], 2000)
  return { ...h, client, agent, interactions, sessionId: created.session_id, async close() { interactions.close(); await h.close() } }
}

test('a claimed native timed question accepts a foreground answer and releases every claim', async () => {
  const h = await fixture()
  const signal = new AbortController()
  try {
    const callId = ToolCallId(randomUUID())
    const waiting = h.ctx.userQuestions.askTimed({ agent: h.agent, signal: signal.signal,
      questions: [{ id: 'choice', question: 'Continue?', options: [{ label: 'Continue' }] }] }, callId, 1500)
    void waiting.catch(() => {})
    const opened = h.interactions.timed.snapshot(h.sessionId).items[0]!
    assert.equal(opened.state, 'open')
    assert.equal(opened.expires_at, null, 'unclaimed native deadline was fabricated')
    const claim = h.interactions.timed.claim(h.sessionId, opened.question_id, signal.signal)[Symbol.asyncIterator]()
    const initial = await claim.next()
    assert.equal(initial.done, false)
    assert.ok(initial.value!.remaining_ms > 0 && initial.value!.remaining_ms <= 1500)
    assert.ok(h.interactions.timed.snapshot(h.sessionId).items[0]?.expires_at)
    assert.throws(() => h.interactions.timed.answer(randomUUID(), opened.question_id, { answers: [] }), /interaction.stale/)
    const answer = { answers: [{ id: 'choice', selected: ['Continue'] }] }
    assert.deepEqual(h.interactions.timed.answer(h.sessionId, opened.question_id, answer), { accepted: true, delivery: 'foreground' })
    assert.deepEqual(await waiting, answer)
    assert.equal((await claim.next()).done, true)
    assert.deepEqual(h.interactions.timed.snapshot(h.sessionId).items, [])
    assert.throws(() => h.interactions.timed.answer(h.sessionId, opened.question_id, answer), /interaction.stale/)
    const skip = h.ctx.userQuestions.askTimed({ agent: h.agent, questions: [{ id: 'optional', question: 'Optional choice?' }] }, ToolCallId(randomUUID()), 1500)
    const optional = h.interactions.timed.snapshot(h.sessionId).items[0]!
    const skipped = { answers: [{ id: 'optional', selected: [] }] }
    assert.equal(h.interactions.timed.answer(h.sessionId, optional.question_id, skipped).delivery, 'foreground')
    assert.deepEqual(await skip, skipped, 'a submitted skip was treated as a timeout')
  } finally { signal.abort(); await h.close() }
})

test('claim release, foreground timeout, cancellation and unload preserve native timed outcomes', async t => {
  for (const scenario of ['unclaimed', 'release', 'held-timeout', 'cancel', 'unload'] as const) await t.test(scenario, async () => {
    const h = await fixture()
    const signal = new AbortController(), ui = new AbortController()
    try {
      const callId = ToolCallId(randomUUID())
      const waiting = h.ctx.userQuestions.askTimed({ agent: h.agent, signal: signal.signal, questions: [{ id: 'choice', question: 'Continue?' }] }, callId,
        scenario === 'cancel' || scenario === 'unload' ? 5000 : 120)
      void waiting.catch(() => {})
      const opened = h.interactions.timed.snapshot(h.sessionId).items[0]!
      const claim = scenario === 'unclaimed' ? undefined : h.interactions.timed.claim(h.sessionId, opened.question_id, ui.signal)[Symbol.asyncIterator]()
      if (claim) assert.equal((await claim.next()).done, false)
      if (scenario === 'release') ui.abort()
      if (scenario === 'cancel') signal.abort()
      if (scenario === 'unload') h.interactions.close()
      if (scenario === 'cancel' || scenario === 'unload') await assert.rejects(waiting, error => (error as { code?: string }).code === 'ASK_ABORTED')
      else assert.deepEqual(await waiting, { pending: true, callId })
      if (claim) assert.equal((await claim.next()).done, true)
      assert.deepEqual(h.interactions.timed.snapshot(h.sessionId).items, [])
    } finally { signal.abort(); ui.abort(); await h.close() }
  })
})

test('a real timed question tool continues once and its late reply becomes one native user message', async () => {
  const h = await fixture()
  const lifetime = new AbortController()
  const held = h.model.holdNext()
  let reloaded: InteractionRouter | undefined
  try {
    await h.ctx.plugin(askUser, { mode: 'timed', timeout: 1 })
    const original = h.model.stream.bind(h.model)
    const callId = ToolCallId(randomUUID())
    let issued = false
    h.model.stream = async function* (options) {
      if (issued) { yield* original(options); return }
      issued = true
      const args = JSON.stringify({ timeout: 1, questions: [{ id: 'plan', question: 'Continue?', options: [{ label: 'Continue' }, { label: 'Cancel' }] }] })
      yield { type: 'block-start', index: 0, blockType: 'tool-call' }
      yield { type: 'tool-call-delta', index: 0, id: callId, name: 'ask_user_question', argumentsDelta: args }
      yield { type: 'block-end', index: 0, block: { type: 'tool-call', id: callId, name: 'ask_user_question', arguments: args } }
      yield { type: 'finish', reason: { kind: 'tool-calls' } }
    }
    await h.client.prompt(h.agent.id, randomUUID(), 'queue', 'Ask the timed fixture question', lifetime.signal)
    const opened = await until(() => h.interactions.timed.snapshot(h.sessionId).items.find(item => item.state === 'open'))
    const continued = await until(() => h.interactions.timed.snapshot(h.sessionId).items.find(item => item.state === 'continued'))
    assert.equal(continued.question_id, opened.question_id, 'native timeout changed the question identity')
    await held.started
    const before = h.agent.session.snapshotEvents().filter(event => event.type === 'tool/result' && event.data.message.toolCallId === callId)
    assert.equal(before.length, 1)
    assert.ok(JSON.stringify(before).includes('"pending":true') || JSON.stringify(before).includes('\\"pending\\":true'))
    h.interactions.close()
    reloaded = new InteractionRouter(h.ctx, h.runtimeId, candidate => candidate === h.agent, [], 2000)
    const restored = reloaded.timed.snapshot(h.sessionId).items[0]!
    assert.equal(restored.state, 'continued')
    assert.notEqual(restored.question_id, continued.question_id, 'reload reused an old callback identity')
    const answer = { answers: [{ id: 'plan', selected: ['Continue'], custom: 'late fixture reply' }] }
    assert.throws(() => reloaded!.timed.answer(h.sessionId, continued.question_id, answer), /interaction.stale/)
    assert.throws(() => reloaded!.timed.answer(h.sessionId, restored.question_id, { answers: [{ id: 'plan', selected: ['invented'] }] }), /interaction.invalid_answer/)
    const runtime = new ProbeRuntime(h.client, reloaded)
    const command = parseCommand({ v: 0, type: 'question.timed.answer', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: h.sessionId,
      payload: { question_id: restored.question_id, ...answer } })
    const receipts: string[] = []
    const queued = await runtime.dispatch(command, lifetime.signal, undefined, state => { receipts.push(state) })
    assert.deepEqual(receipts, ['host_accepted', 'dispatching', 'agent_queued'])
    assert.equal((queued.payload as { checkpoint: { state: string } }).checkpoint.state, 'persisted')
    assert.deepEqual(await runtime.dispatch(command, lifetime.signal), queued)
    assert.throws(() => reloaded!.timed.answer(h.sessionId, restored.question_id, answer), /interaction.stale/)
    held.release()
    await h.agent.whenIdle()
    const events = h.agent.session.snapshotEvents()
    const replies = events.filter(event => event.type === 'user/message' && event.data.source.kind === 'user-question-reply')
    assert.equal(replies.length, 1)
    assert.ok(JSON.stringify(replies).includes('late fixture reply'))
    assert.equal(events.filter(event => event.type === 'tool/result' && event.data.message.toolCallId === callId).length, 1, 'late reply completed the old tool again')
    assert.deepEqual(reloaded.timed.snapshot(h.sessionId).items, [])
    assert.equal(h.errors.length, 0)
    runtime.close()
  } finally { held.release(); lifetime.abort(); reloaded?.close(); await h.close() }
})

test('a failed late-answer checkpoint remains unknown and cannot enqueue the reply again', async () => {
  let answers = 0
  const client = { runtimeId: randomUUID(), async resolve() { return 'native' }, async checkpoint() { return { state: 'failed' } } } as unknown as DshClient
  const interactions = { timed: { answer() { answers++; return { accepted: true, delivery: 'late_message' } } }, close() {} } as unknown as InteractionRouter
  const runtime = new ProbeRuntime(client, interactions)
  const command = parseCommand({ v: 0, type: 'question.timed.answer', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: randomUUID(),
    payload: { question_id: randomUUID(), answers: [{ id: 'choice', selected: ['Reply'] }] } })
  const states: string[] = []
  try {
    const unknown = await runtime.dispatch(command, new AbortController().signal, undefined, state => { states.push(state) })
    assert.equal((unknown.payload as { command_state: string }).command_state, 'outcome_unknown')
    assert.deepEqual(states, ['host_accepted', 'dispatching', 'outcome_unknown'])
    await assert.rejects(runtime.dispatch(command, new AbortController().signal), /command.outcome_unknown/)
    assert.equal(answers, 1)
  } finally { runtime.close() }
})
