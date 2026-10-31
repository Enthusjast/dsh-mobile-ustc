/** Native metadata producer driven by the isolated Go/TLS acceptance test. */
import assert from 'node:assert/strict'
import { createPrivateKey, sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { host } from '../../host/remote-control/tests/harness.js'
import { DshClient } from '../../host/remote-control/src/dsh-client.js'
import { createRemoteControlPlugin } from '../../host/remote-control/src/index.js'

const config = JSON.parse(await readFile(process.argv[2]!, 'utf8')) as {
  runtime: string; workspace: string; installation: string; credential: string; privateKey: string; url: string
}
const key = createPrivateKey(config.privateKey)
const h = await host({ probe: false, runtimeId: config.runtime })
try {
  const workspaces = [{ id: 'fixture', cwd: h.cwd, remoteId: config.workspace, label: 'NOT_A_NATIVE_NAME' }]
  let workspace = h.ctx.workspaceRegistry.list().find(entry => entry.path === h.cwd) ??
    await h.ctx.workspaceRegistry.create(h.cwd, '原生目录验收工作区')
  await workspace.setTitle('原生目录验收工作区')
  const client = new DshClient(h.ctx, h.runtimeId, workspaces, ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const native = await client.resolve(created.session_id, AbortSignal.timeout(10_000))
  let prompts = 0
  const prompt = h.ctx.sessionController.prompt.bind(h.ctx.sessionController)
  h.ctx.sessionController.prompt = async (...args) => { prompts++; return prompt(...args) }
  const plugin = createRemoteControlPlugin({ async acquire() {
    return { installationId: config.installation, credential: config.credential,
      signer: { sign(input) { return sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }) } } }
  } })
  const start = async (mapped: boolean) => {
    const scope = h.ctx.plugin({ name: 'directory-metadata-fixture-owner', async apply(ctx) {
      await plugin.apply(ctx, { enabled: true, runtimeId: config.runtime, workspaces: mapped ? workspaces : [],
        presets: ['fixture'], commandJournalPath: join(h.directory, 'commands.sqlite'), relayUrl: config.url,
        applicationVersion: 'native-directory-fixture' })
    } })
    await scope.await()
    return scope
  }
  let scope = await start(true)
  const report = async (type: string) => {
    const signal = AbortSignal.timeout(10_000)
    const row = (await client.sessionCatalog(signal)).find(row => row.session_id === created.session_id)
    assert.ok(row?.metadata)
    assert.equal(JSON.stringify(row.metadata).includes(h.cwd), false)
    assert.equal(JSON.stringify(row.metadata).includes('NOT_A_NATIVE_NAME'), false)
    const summary = (await h.ctx.sessionController.list({}, signal)).items.find(row => row.sessionId === native)
    assert.equal(row.metadata.title_source, row.metadata.title === null ? null : summary?.projections?.kind ?? null)
    assert.equal(row.metadata.title_as_of_seq, row.metadata.title === null ? null : summary?.projections?.asOfSeq ?? null)
    process.stdout.write(JSON.stringify({ type, session_id: created.session_id, metadata: row.metadata,
      last_persisted_seq: row.last_persisted_seq, prompt_calls: prompts }) + '\n')
  }
  await report('ready')
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity })
  for await (const line of input) {
    if (line === 'stop') break
    if (line === 'rename-first') {
      await h.ctx.sessionController.rename({ sessionId: native, title: '原生标题第一次' })
    } else if (line === 'rename-second') {
      await h.ctx.sessionController.rename({ sessionId: native, title: '原生标题第二次' })
      await workspace.setTitle('更新后的原生工作区')
    } else if (line === 'withdraw-workspace') {
      assert.equal(await h.ctx.workspaceRegistry.delete(workspace.id), true)
    } else if (line === 'withdraw-mapping') {
      await scope.dispose()
      scope = await start(false)
    } else if (line === 'restore-mapping') {
      await scope.dispose()
      workspace = await h.ctx.workspaceRegistry.create(h.cwd, '恢复后的原生工作区')
      await h.ctx.sessionController.rename({ sessionId: native, title: '恢复后的原生标题' })
      scope = await start(true)
    } else throw new Error('unknown metadata fixture command')
    await report(line)
  }
  input.close(); process.stdin.pause()
  assert.equal(prompts, 0, 'directory publication must not prompt a model to derive titles')
  assert.equal(h.errors.length, 0)
} finally { await h.close() }
