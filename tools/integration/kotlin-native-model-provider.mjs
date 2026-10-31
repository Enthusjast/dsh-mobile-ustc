import { LlmAdapter, isAgentLoopRequest } from '@deepseek-ai/dsh-llm'
import { appendFile } from 'node:fs/promises'

class NativeModels extends LlmAdapter {
  providerInfo(provider) { return { id: provider, name: 'Duplicate provider' } }
  async listModels(provider) {
    return ['  model/α  ', 'model/β'].map(id => ({ provider, id, name: 'Duplicate model' }))
  }
  async resolveModel(provider, model) {
    return { provider, id: model, name: 'Duplicate model', inputModalities: ['text'], reasoning: {
      efforts: [{ id: 'effort/low', name: 'Duplicate effort' }, { id: 'effort/high', name: 'Duplicate effort' }], defaultEffort: 'effort/low',
    } }
  }
  async *stream(options) {
    options.signal?.throwIfAborted()
    await appendFile(process.env.NATIVE_MODELS_CALLS, JSON.stringify({ provider: options.provider, model: options.model, effort: options.reasoningEffort, agent: isAgentLoopRequest(options) }) + '\n', { mode: 0o600 })
    const text = 'Native selected offline response'
    yield { type: 'block-start', index: 0, blockType: 'text' }
    yield { type: 'text-delta', index: 0, text }
    yield { type: 'block-end', index: 0, block: { type: 'text', text } }
    yield { type: 'finish', reason: { kind: 'stop' } }
  }
}
export const name = 'native-kotlin-models-fixture'
export const inject = ['llm']
export function apply(ctx) {
  ctx.effect(() => ctx.llm.registerAdapter(['opaque/provider-A', 'opaque/provider-B'], new NativeModels()), 'native-kotlin-models-fixture')
}
