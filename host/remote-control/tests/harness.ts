import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { LlmAdapter, type GenerateOptions, type StreamChunk } from '@deepseek-ai/dsh-llm'
import { mkdtemp, rm, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { randomUUID } from 'node:crypto'
import type { EntryOptions } from '@deepseek-ai/cordis-plugin-loader'
import type {} from '@deepseek-ai/dsh-agent-preset-registry'

/** The only model in offline tests is deterministic; no real identity or provider is exercised. */
export class TestModel extends LlmAdapter {
  private readonly holds: { started(): void; resume: Promise<void>; release(): void }[] = []

  override providerInfo() { return { id: 'fixture', name: 'Offline fixture' } }
  override async listModels() { return [{ provider: 'fixture', id: 'fixture', name: 'Offline fixture' }] }

  holdNext() {
    let start!: () => void
    let resume!: () => void
    const held = {
      started: new Promise<void>(resolve => { start = resolve }),
      resume: new Promise<void>(resolve => { resume = resolve }),
      release: resume,
    }
    this.holds.push({ started: start, resume: held.resume, release: held.release })
    return held
  }

  override async *stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
    options.signal?.throwIfAborted()
    const held = this.holds.shift()
    if (held) {
      held.started()
      let abort!: () => void
      const aborted = new Promise<void>(resolve => { abort = resolve })
      const onAbort = () => abort()
      options.signal?.addEventListener('abort', onAbort, { once: true })
      try { await Promise.race([held.resume, aborted]) }
      finally { options.signal?.removeEventListener('abort', onAbort) }
      options.signal?.throwIfAborted()
    }
    yield { type: 'block-start', index: 0, blockType: 'text' }
    yield { type: 'text-delta', index: 0, text: 'offline reply' }
    yield { type: 'block-end', index: 0, block: { type: 'text', text: 'offline reply' } }
    yield { type: 'finish', reason: { kind: 'stop' } }
  }
}

export async function host(options: { probe?: boolean; timeoutMs?: number; directory?: string; retainDirectory?: boolean; runtimeId?: string } = {}) {
  const directory = options.directory ?? await mkdtemp(join(tmpdir(), 'dsh-mobile-'))
  const cleanupDirectory = options.retainDirectory !== true
  const cwd = join(directory, 'workspace')
  await mkdir(cwd, { recursive: true })
  const ctx = new Context()
  const errors: unknown[] = []
  ctx.on('agent/error', ({ error }) => { errors.push(error) }, { global: true })
  await ctx.plugin(Loader, { baseUrl: pathToFileURL(resolve('.') + '/').href })
  const rows: EntryOptions[] = [
    { id: 'sessions', name: '@deepseek-ai/dsh-session' },
    { id: 'persistence', name: '@deepseek-ai/dsh-session-persistence-jsonl', config: { root: join(directory, 'sessions'), compression: 'none' } },
    { id: 'projections', name: '@deepseek-ai/dsh-session-projection' },
    { id: 'storage', name: '@deepseek-ai/dsh-storage' },
    { id: 'storage-json', name: '@deepseek-ai/dsh-storage-json', config: { root: join(directory, 'storage') } },
    { id: 'storage-domain', name: '@deepseek-ai/dsh-storage-domain', config: { backend: 'json' } },
    { id: 'workspace', name: '@deepseek-ai/dsh-workspace' },
    { id: 'title', name: '@deepseek-ai/dsh-session-title', config: { fallbackMaxWords: 5, fallbackMaxBytes: 40, maxTitleBytes: 80 } },
    { id: 'query', name: '@deepseek-ai/dsh-session-query' },
    { id: 'agents', name: '@deepseek-ai/dsh-agent' },
    { id: 'llm', name: '@deepseek-ai/dsh-llm' },
    { id: 'prompt', name: '@deepseek-ai/dsh-system-prompt', config: { includeHarnessIdentity: false, includeRuntimeContext: false } },
    { id: 'tools', name: '@deepseek-ai/dsh-tools' },
    { id: 'approval', name: '@deepseek-ai/dsh-user-approval' },
    { id: 'typert', name: '@deepseek-ai/dsh-typert-registry' },
    { id: 'access', name: '@deepseek-ai/dsh-api-remote-access' },
    { id: 'questions', name: '@deepseek-ai/dsh-user-questions' },
    { id: 'defaults', name: '@deepseek-ai/dsh-agent-default-model', config: { provider: 'fixture', model: 'fixture' } },
    { id: 'fs', name: '@deepseek-ai/dsh-fs-local' },
    { id: 'working-directory', name: '@deepseek-ai/dsh-working-directory' },
    { id: 'attachments', name: '@deepseek-ai/dsh-attachment-local', config: { dshHome: directory } },
    { id: 'credentials', name: '@deepseek-ai/dsh-credentials-local', config: { path: join(directory, 'credentials.yaml') } },
    { id: 'connection', name: '@deepseek-ai/dsh-client-connection' },
    { id: 'commands', name: '@deepseek-ai/dsh-commands' },
    { id: 'file-upload', name: '@deepseek-ai/dsh-client-file-upload' },
    { id: 'controller', name: '@deepseek-ai/dsh-api-session-controller' },
    { id: 'presets', name: '@deepseek-ai/dsh-agent-preset-registry', config: { default: 'fixture' } },
    { id: 'loop', name: '@deepseek-ai/dsh-agent-loop', config: { agents: [] } },
  ]
  try {
    await ctx.loader.root.update(rows)
    await ctx.loader.await()
    await Promise.all([...ctx.loader.entries()].map(entry => entry.fiber?.await()))
    if (errors.length) throw new AggregateError(errors, 'fixture Loader errors')
    const model = new TestModel()
    ctx.llm.registerAdapter(['fixture'], model)
    const disposePreset = await ctx.agentPresets.register({ id: 'fixture', plugins: [] })
    const socketPath = join(directory, 'debug', 'probe.sock')
    const runtimeId = options.runtimeId ?? randomUUID()
    const config = { enabled: true, runtimeId, socketPath, commandJournalPath: join(directory, 'debug', 'commands.sqlite'), workspaces: [{ id: 'fixture', cwd }], presets: ['fixture'], highRiskTools: ['protected'], interactionTimeoutMs: options.timeoutMs ?? 1000 }
    if (options.probe !== false) {
      await ctx.loader.root.update([...rows, { id: 'remote', name: './host/remote-control/lib/index.js', config }])
      await ctx.loader.await()
      await Promise.all([...ctx.loader.entries()].map(entry => entry.fiber?.await()))
      if (errors.length) throw new AggregateError(errors, 'probe Loader errors')
    }
    return { ctx, cwd, directory, socketPath, runtimeId, config, errors, model, async close() {
      await disposePreset()
      await ctx.fiber.dispose()
      if (cleanupDirectory) await rm(directory, { recursive: true, force: true })
    } }
  } catch (error) {
    await ctx.fiber.dispose()
    if (cleanupDirectory) await rm(directory, { recursive: true, force: true })
    throw error
  }
}
