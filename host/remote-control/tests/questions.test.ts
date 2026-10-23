import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { InteractionRouter } from '../src/interaction-router.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand, type Frame } from '../src/protocol.js'
import { commandDigest } from '../src/command-journal.js'
import type { QuestionSnapshot } from '../src/questions.js'

async function until<T>(read: () => T | undefined): Promise<T> {
  const deadline = Date.now() + 2500
  while (Date.now() < deadline) { const value = read(); if (value !== undefined) return value; await delay(5) }
  throw new Error('question state did not arrive')
}

test('blocking questions stream current state and accept one session-bound answer with durable retry', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const native = await client.resolve(created.session_id, new AbortController().signal)
  const agent = h.ctx.agents.get(native)!
  const interactions = new InteractionRouter(h.ctx, h.runtimeId, candidate => candidate === agent, ['protected'], 2000)
  const runtime = new ProbeRuntime(client, interactions)
  const lifetime = new AbortController()
  const frames: Frame[] = []
  const subscribe = parseCommand({ v: 0, type: 'session.subscribe', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id, payload: {} })
  if (subscribe.type !== 'session.subscribe') throw new Error('fixture')
  const reader = (async () => { for await (const frame of runtime.follow(subscribe, lifetime.signal)) frames.push(frame) })()
  void reader.catch(() => {})
  let pending: Promise<unknown> | undefined
  try {
    await until(() => frames.find(frame => frame.type === 'question.snapshot' && !(frame.payload as QuestionSnapshot).items.length))
    pending = h.ctx.userQuestions.ask({ agent, questions: [{ id: 'plan', question: 'Continue?', detail: 'Review this plan', header: 'Plan',
      options: [{ label: 'Continue', description: 'Proceed' }, { label: 'Cancel' }], intent: { kind: 'plan-review', approve: 'Continue' } }] })
    void pending.catch(() => {})
    const opened = await until(() => frames.find(frame => frame.type === 'question.snapshot' && (frame.payload as QuestionSnapshot).items.length === 1))
    const view = (opened.payload as QuestionSnapshot).items[0]!
    assert.deepEqual(view.questions[0]?.intent, { kind: 'plan-review', approve: 'Continue' })
    assert.equal(interactions.snapshot(randomUUID()).items.length, 0)
    const answer = parseCommand({ v: 0, type: 'question.answer', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id,
      payload: { question_id: view.question_id, answers: [{ id: 'plan', selected: ['Continue'] }] } })
    assert.notEqual(commandDigest(answer), commandDigest({ ...answer, runtime_epoch: randomUUID() }))
    const states: string[] = []
    await assert.rejects(runtime.dispatch({ ...answer, session_id: randomUUID() } as typeof answer, lifetime.signal, undefined, state => { states.push(state) }), /interaction.stale/)
    assert.equal(states.at(-1), 'rejected')
    const validAnswer = { ...answer, request_id: randomUUID() }
    const first = await runtime.dispatch(validAnswer, lifetime.signal)
    assert.deepEqual(await pending, { answers: [{ id: 'plan', selected: ['Continue'] }] })
    assert.deepEqual(first.payload, { accepted: true })
    assert.deepEqual(await runtime.dispatch(validAnswer, lifetime.signal), first)
    await until(() => frames.find(frame => frame.type === 'question.snapshot' && (frame.payload as QuestionSnapshot).revision > (opened.payload as QuestionSnapshot).revision && !(frame.payload as QuestionSnapshot).items.length))
    await assert.rejects(runtime.dispatch({ ...answer, request_id: randomUUID() }, lifetime.signal, { userId: 'another', deviceId: 'another' }), /interaction.stale/)
    assert.ok(frames.filter(frame => frame.type === 'question.snapshot').every(frame => frame.session_id === created.session_id && frame.sync_id === opened.sync_id))
    assert.equal(h.errors.length, 0)
  } finally {
    lifetime.abort()
    await reader.catch(() => {})
    runtime.close()
    await pending?.catch(() => {})
    await h.close()
  }
})

test('expired questions disappear and removing a listener leaves a live question answerable', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const agent = h.ctx.agents.get(await client.resolve(created.session_id, new AbortController().signal))!
  const interactions = new InteractionRouter(h.ctx, h.runtimeId, candidate => candidate === agent, [], 75)
  const snapshots: QuestionSnapshot[] = []
  const dispose = interactions.watch(created.session_id, () => { snapshots.push(interactions.snapshot(created.session_id)) })
  try {
    const pending = h.ctx.userQuestions.ask({ agent, questions: [{ id: 'choice', question: 'Choose', options: [{ label: 'A' }] }] })
    const failed = assert.rejects(pending, /question.cancelled/)
    await until(() => snapshots.find(item => item.items.length === 1))
    await failed
    assert.equal(snapshots.at(-1)?.items.length, 0)
    const another = h.ctx.userQuestions.ask({ agent, questions: [{ id: 'text', question: 'Type a reply' }] })
    void another.catch(() => {})
    const view = interactions.snapshot(created.session_id).items[0]!
    dispose()
    assert.deepEqual(interactions.answerQuestion(created.session_id, view.question_id, { answers: [{ id: 'text', selected: [], custom: 'reply' }] }), { accepted: true })
    assert.deepEqual(await another, { answers: [{ id: 'text', selected: [], custom: 'reply' }] })
    assert.throws(() => interactions.answerQuestion(created.session_id, view.question_id, { answers: [] }), /interaction.stale/)
  } finally { dispose(); interactions.close(); await h.close() }
})
