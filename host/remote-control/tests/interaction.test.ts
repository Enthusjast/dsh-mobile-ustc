import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import { host } from './harness.js'
import { request } from 'node:http'

async function command(socketPath: string, type: string, payload: unknown = {}) {
  const send = (path: string, body?: unknown): Promise<any> => new Promise((accept, reject) => {
    const req = request({ socketPath, path, method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json' } }, res => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => { try { accept(JSON.parse(data)) } catch (error) { reject(error) } })
      res.on('error', reject)
    })
    req.on('error', reject)
    req.end(body === undefined ? undefined : JSON.stringify(body))
  })
  const probe = await send('/m0/probe')
  return send('/m0/command', { v: 0, type, request_id: randomUUID(), runtime_epoch: probe.runtime_epoch, payload })
}

async function fixture(timeoutMs = 1000) {
  const h = await host({ timeoutMs })
  const created = await h.ctx.sessionController.create({ cwd: h.cwd, agentPreset: 'fixture' })
  const agent = h.ctx.agents.get(created.sessionId)!
  agent.session.append('turn/start', { turn: 1 })
  let calls = 0
  h.ctx.tools.register(defineContentToolFixture({
    name: 'protected', description: 'Fixture with observable side effects', parameters: { value: { type: 'string', description: 'Fixture input' } },
    async execute() { calls++; return [{ type: 'text', text: 'executed' }] },
  }))
  const execute = (signal = new AbortController().signal) => h.ctx.tools.execute({
    agent, callId: ToolCallId(randomUUID()), name: 'protected', arguments: { value: 'exact arguments' }, signal,
  })
  const pending = async (): Promise<any> => {
    for (let attempt = 0; attempt < 100; attempt++) {
      const response = await command(h.socketPath, 'interaction.list')
      if (response.payload.items?.length) return response.payload.items[0]
      await setTimeout(10)
    }
    throw new Error('interaction did not become pending')
  }
  return { ...h, agent, execute, pending, calls: () => calls }
}

test('native approval plus final guard executes only the locally allowed exact invocation once', async () => {
  const h = await fixture()
  try {
    const result = h.execute()
    const pending = await h.pending()
    assert.equal(pending.kind, 'approval')
    assert.deepEqual(pending.detail.arguments, { value: 'exact arguments' })
    assert.equal(h.calls(), 0)
    await command(h.socketPath, 'interaction.answer', { interaction_id: pending.interaction_id, answer: { decision: 'allow_once' } })
    assert.equal((await result).isError, false)
    assert.equal(h.calls(), 1)
    const replay = await command(h.socketPath, 'interaction.answer', { interaction_id: pending.interaction_id, answer: { decision: 'allow_once' } })
    assert.equal(replay.payload.code, 'interaction.stale')
    assert.equal(h.calls(), 1)
  } finally { await h.close() }
})

test('rejection, cancellation and timeout do not execute the protected tool', async t => {
  for (const mode of ['reject', 'abort', 'timeout'] as const) await t.test(mode, async () => {
    const h = await fixture(mode === 'timeout' ? 100 : 1000)
    try {
      const abort = new AbortController()
      const result = h.execute(abort.signal)
      const pending = await h.pending()
      if (mode === 'reject') await command(h.socketPath, 'interaction.answer', { interaction_id: pending.interaction_id, answer: { decision: 'reject' } })
      if (mode === 'abort') abort.abort()
      assert.equal((await result).isError, true)
      assert.equal(h.calls(), 0)
      assert.deepEqual((await command(h.socketPath, 'interaction.list')).payload.items, [])
    } finally { await h.close() }
  })
})

test('earlier desktop/automatic allow-listeners cannot bypass the final guard', async t => {
  for (const event of ['tools/pre-execute', 'approval/request'] as const) await t.test(event, async () => {
    const h = await fixture()
    try {
      if (event === 'tools/pre-execute') h.ctx.on(event, async () => ({ kind: 'allow' }), { prepend: true })
      else h.ctx.on(event, async () => 'allowed-once', { prepend: true })
      assert.equal((await h.execute()).isError, true)
      assert.equal(h.calls(), 0)
      assert.deepEqual((await command(h.socketPath, 'interaction.list')).payload.items, [])
    } finally { await h.close() }
  })
})

test('ordinary question and plan review answers use the native question service, with invalid batches rejected', async () => {
  const h = await fixture()
  try {
    const waiting = h.ctx.userQuestions.ask({ agent: h.agent, questions: [{ id: 'plan', question: 'Continue?', detail: 'Fixture plan',
      options: [{ label: 'Continue' }, { label: 'Cancel' }], intent: { kind: 'plan-review', approve: 'Continue' } }] })
    const pending = await h.pending()
    assert.equal(pending.kind, 'question')
    const invalid = await command(h.socketPath, 'interaction.answer', { interaction_id: pending.interaction_id, answer: { answers: [{ id: 'plan', selected: ['invented'] }] } })
    assert.equal(invalid.payload.code, 'interaction.invalid_answer')
    const answer = { answers: [{ id: 'plan', selected: ['Continue'] }] }
    await command(h.socketPath, 'interaction.answer', { interaction_id: pending.interaction_id, answer })
    assert.deepEqual(await waiting, answer)
    assert.equal(h.calls(), 0)
  } finally { await h.close() }
})

test('unload settles pending approval and a reload has a new epoch', async () => {
  const h = await fixture()
  try {
    const waiting = h.execute()
    await h.pending()
    const fiber = h.ctx.loader.resolve('remote').fiber!
    await fiber.dispose()
    assert.equal((await waiting).isError, true)
    assert.equal(h.calls(), 0)
  } finally { await h.close() }
})
