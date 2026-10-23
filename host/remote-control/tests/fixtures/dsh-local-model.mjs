import { LlmAdapter } from '@deepseek-ai/dsh-llm'

class LocalModel extends LlmAdapter {
  providerInfo(provider) { return { id: provider, name: 'Local DSH integration fixture' } }
  async listModels(provider) { return [{ provider, id: 'offline', name: 'Offline fixture' }] }
  async *stream(options) {
    options.signal?.throwIfAborted()
    yield { type: 'block-start', index: 0, blockType: 'text' }
    yield { type: 'text-delta', index: 0, text: 'DSH local integration fixture response' }
    yield { type: 'block-end', index: 0, block: { type: 'text', text: 'DSH local integration fixture response' } }
    yield { type: 'finish', reason: { kind: 'stop' } }
  }
}

export const name = 'dsh-mobile-local-model-fixture'
export const inject = ['llm']

export function apply(ctx) {
  const adapter = new LocalModel()
  ctx.effect(() => ctx.llm.registerAdapter(['dsh-m0-test'], adapter), 'dsh-mobile.local-model-fixture')
}
