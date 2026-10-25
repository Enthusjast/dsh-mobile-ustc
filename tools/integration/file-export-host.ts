/** Real npm DSH + normal plugin. Only public fixture result metadata goes to stdout. */
import assert from 'node:assert/strict'
import { createHash, createPrivateKey, randomUUID, sign } from 'node:crypto'
import { readFile, mkdir, writeFile, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { host } from '../../host/remote-control/tests/harness.js'
import { DshClient } from '../../host/remote-control/src/dsh-client.js'
import { createRemoteControlPlugin } from '../../host/remote-control/src/index.js'

const config = JSON.parse(await readFile(process.argv[2]!, 'utf8')) as { runtime: string; workspace: string; installation: string; credential: string; privateKey: string; url: string }
const key = createPrivateKey(config.privateKey)
const h = await host({ probe: false, runtimeId: config.runtime })
try {
  const workspaces = [{ id: 'fixture', cwd: h.cwd, remoteId: config.workspace, exportRoots: [{ id: 'reports', directory: 'output' }] }]
  await mkdir(join(h.cwd, 'output'))
  const artifact = Buffer.from('real DSH workspace artifact\0\xff'), attachment = Buffer.from('real DSH persisted attachment\0\xff')
  await writeFile(join(h.cwd, 'output', 'report.bin'), artifact)
  await writeFile(join(h.cwd, 'output', 'empty.bin'), Buffer.alloc(0))
  await writeFile(join(h.cwd, 'private'), 'not an export source')
  await symlink(join(h.cwd, 'private'), join(h.cwd, 'output', 'outside-link'))
  const client = new DshClient(h.ctx, h.runtimeId, workspaces, ['fixture'])
  const session = (await client.create('fixture', 'fixture')).session_id, native = await client.resolve(session, new AbortController().signal)
  const uploaded = await client.uploadFile(session, { name: 'attached.bin', size_bytes: attachment.length, sha256: createHash('sha256').update(attachment).digest('hex') }, (async function* () { yield attachment })(), new AbortController().signal)
  await client.prompt(native, randomUUID(), 'queue', [{ type: 'file', receiptId: uploaded.receiptId }], new AbortController().signal)
  await h.ctx.agents.get(native)!.whenIdle(); assert.equal((await client.checkpoint(native)).state, 'persisted')
  let prompts = 0
  const prompt = h.ctx.sessionController.prompt.bind(h.ctx.sessionController)
  h.ctx.sessionController.prompt = async (...args) => { prompts++; return prompt(...args) }
  const plugin = createRemoteControlPlugin({ async acquire() { return { installationId: config.installation, credential: config.credential, signer: { sign(input) { return sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }) } } } } })
  await plugin.apply(h.ctx, { enabled: true, runtimeId: config.runtime, workspaces, presets: ['fixture'], commandJournalPath: join(h.directory, 'commands.sqlite'), relayUrl: config.url, applicationVersion: 'native-export-fixture' })
  process.stdout.write(JSON.stringify({ type: 'ready', session_id: session, artifact_sha256: createHash('sha256').update(artifact).digest('hex'), attachment_sha256: createHash('sha256').update(attachment).digest('hex') }) + '\n')
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity })
  for await (const line of input) {
    if (line === 'stop') break
    if (line === 'change-artifact') { await writeFile(join(h.cwd, 'output', 'report.bin'), 'changed after listing'); process.stdout.write('{"type":"changed"}\n'); continue }
    if (line !== 'inspect') throw new Error('unknown fixture action')
    assert.equal(prompts, 0)
    process.stdout.write(JSON.stringify({ type: 'inspected', prompt_calls: prompts, human_messages: h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message' && event.data.source.kind === 'user').length }) + '\n')
  }
  input.close(); process.stdin.pause(); assert.equal(h.errors.length, 0)
} finally { await h.close() }
