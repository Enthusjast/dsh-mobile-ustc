import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { SessionId } from '@deepseek-ai/dsh-session'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import { host } from './harness.js'
import { InteractionRouter } from '../src/interaction-router.js'

test('owned children preserve the pinned native delegated-caller refusal', async () => {
  const h = await host({ probe: false })
  const root = await h.ctx.agents.create({ sessionId: SessionId(`root-${randomUUID()}`), meta: { cwd: h.cwd }, agentOptions: { provider: 'fixture', model: 'fixture' } })
  const child = await h.ctx.agents.create({ sessionId: SessionId(`child-${randomUUID()}`), parentAgent: root.agent,
    meta: { cwd: h.cwd, parentSession: root.agent.id, origin: 'subagent' }, agentOptions: { provider: 'fixture', model: 'fixture' } })
  const source = new InteractionRouter(h.ctx, h.runtimeId, agent => agent?.session.header.cwd === h.cwd, [], 2000)
  try {
    const questions = [{ id: 'choice', question: 'Unresolved child question', options: [{ label: 'A' }] }]
    const delegated = (error: unknown) => (error as { code?: string }).code === 'DELEGATED_CALLER'
    await assert.rejects(h.ctx.userQuestions.ask({ agent: child.agent, questions }), delegated)
    await assert.rejects(h.ctx.userQuestions.askTimed({ agent: child.agent, questions }, ToolCallId(randomUUID()), 500), delegated)
    assert.deepEqual(source.references(), [])
  } finally { source.close(); await child.dispose(); await root.dispose(); await h.close() }
})

test('lineage outside the remote directory remains with the native answerer and cannot poison the feed', async () => {
  const h = await host({ probe: false })
  const root = await h.ctx.agents.create({ sessionId: SessionId(`root-${randomUUID()}`), meta: { cwd: h.cwd }, agentOptions: { provider: 'fixture', model: 'fixture' } })
  const fork = await h.ctx.agents.create({ sessionId: SessionId(`fork-${randomUUID()}`), meta: { cwd: h.cwd, parentSession: root.agent.id }, agentOptions: { provider: 'fixture', model: 'fixture' } })
  const source = new InteractionRouter(h.ctx, h.runtimeId, agent => agent?.session.header.cwd === h.cwd, [], 2000)
  let local = 0
  const answer = { answers: [{ id: 'choice', selected: ['A'] }] }
  const stop = h.ctx.on('user-questions/request', async () => { local++; return answer })
  try {
    const questions = [{ id: 'choice', question: 'Local fork question', options: [{ label: 'A' }] }]
    assert.ok(h.ctx.agents.roots().includes(fork.agent), 'fixture is a native independent runtime root')
    assert.deepEqual(await h.ctx.userQuestions.ask({ agent: fork.agent, questions }), answer)
    assert.deepEqual(await h.ctx.userQuestions.askTimed({ agent: fork.agent, questions }, ToolCallId(randomUUID()), 500), answer)
    assert.equal(local, 2)
    assert.deepEqual(source.references(), [])
    assert.deepEqual(source.snapshot('11111111-1111-4111-8111-111111111111').items, [])
  } finally { stop(); source.close(); await fork.dispose(); await root.dispose(); await h.close() }
})
