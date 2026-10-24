import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { fenceExecutionSignal, fenceToolDefinition, type ExecutionSignalFence } from '../src/execution-fence.js'

test('native dispatch fences validate after async wrappers and preserve one actual body entry', async t => {
  for (const mode of ['allow', 'expired', 'swapped', 'signal-replaced', 'retry', 'long-body', 'disposed'] as const) await t.test(mode, async () => {
    const h = await host({ probe: false })
    let calls = 0, checks = 0, valid = true
    let signal: ExecutionSignalFence | undefined
    const definition = defineContentToolFixture({ name: 'protected', description: 'Body-boundary fixture', parameters: {}, async execute() {
      calls++
      if (mode === 'long-body') { valid = false; await new Promise(resolve => setTimeout(resolve, 15)) }
      return [{ type: 'text', text: 'body' }]
    } })
    let unregister = h.ctx.tools.register(definition)
    const fence = fenceToolDefinition(definition)
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const agent = h.ctx.agents.get(await client.resolve(created.session_id, new AbortController().signal))!
    const armed = new Set<symbol>()
    h.ctx.on('tools/pre-execute', async (exec, next) => {
      const previous = await next()
      if (previous.kind === 'deny' || previous.kind === 'cancel') return previous
      fence.arm(exec, (_args, body) => { checks++; if (!valid) throw new Error('expired'); signal!.enterBody(); assert.equal(body.token, exec.token) })
      armed.add(exec.token)
      return { kind: 'allow' }
    }, { prepend: true })
    h.ctx.tools.guard(exec => {
      if (!armed.has(exec.token)) return 'unapproved'
      signal = fenceExecutionSignal(exec, () => valid && h.ctx.tools.get(exec.name, exec.agent) === definition && definition.execute === fence.execute)
    })
    h.ctx.on('tools/execute', async (exec, next) => {
      await Promise.resolve()
      if (mode === 'expired' || mode === 'signal-replaced') valid = false
      if (mode === 'signal-replaced') exec.signal = new AbortController().signal
      if (mode === 'swapped') {
        unregister()
        unregister = h.ctx.tools.register(defineContentToolFixture({ name: 'protected', description: 'Replacement', parameters: {}, async execute() { calls++; return [] } }))
      }
      if (mode === 'disposed') { fence.block(exec); signal!.cancel() }
      const result = await next()
      if (mode === 'retry') { try { await next() } catch { /* The native waterfall or body fence must refuse a second body. */ } }
      return result
    }, { prepend: true })
    h.ctx.on('tools/result', exec => { fence.block(exec); signal?.release() })
    try {
      const result = await h.ctx.tools.execute({ agent, callId: ToolCallId(randomUUID()), name: 'protected', arguments: {}, signal: new AbortController().signal })
      const executed = ['allow', 'retry', 'long-body'].includes(mode)
      assert.equal(calls, executed ? 1 : 0)
      assert.equal(checks, executed ? 1 : 0)
      if (mode !== 'retry') assert.equal(result.isError, !executed)
      assert.equal(h.errors.length, 0)
    } finally { unregister(); await h.close() }
  })
})

test('body adapters leave untracked executions scoped by the native registry and reject frozen definitions', async () => {
  const h = await host({ probe: false })
  try {
    const definition = defineContentToolFixture({ name: 'ordinary', description: 'Unmanaged fixture', parameters: {}, async execute() { return [{ type: 'text', text: 'ordinary' }] } })
    fenceToolDefinition(definition)
    h.ctx.tools.register(definition)
    const result = await h.ctx.tools.execute({ callId: ToolCallId(randomUUID()), name: 'ordinary', arguments: {}, signal: new AbortController().signal })
    assert.equal(result.isError, false)
    const frozen = Object.freeze(defineContentToolFixture({ name: 'frozen', description: 'Frozen fixture', parameters: {}, async execute() { return [] } }))
    assert.throws(() => fenceToolDefinition(frozen), /authority unavailable/)
  } finally { await h.close() }
})
