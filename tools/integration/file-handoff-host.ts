/** Isolated real npm DSH Loader peer for the Go/PostgreSQL/TLS handoff composition. */
import assert from 'node:assert/strict'
import { createHash, createPrivateKey, sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { once } from 'node:events'
import { host } from '../../host/remote-control/tests/harness.js'
import { DshClient } from '../../host/remote-control/src/dsh-client.js'
import { createRemoteControlPlugin } from '../../host/remote-control/src/index.js'

const config = JSON.parse(await readFile(process.argv[2]!, 'utf8')) as {
  runtime: string; workspace: string; installation: string; credential: string; privateKey: string; url: string
}
const key = createPrivateKey(config.privateKey)
const h = await host({ probe: false, runtimeId: config.runtime })
let interval: NodeJS.Timeout | undefined
try {
  const workspaces = [{ id: 'fixture', cwd: h.cwd, remoteId: config.workspace }]
  const client = new DshClient(h.ctx, h.runtimeId, workspaces, ['fixture'])
  const created = await client.create('fixture', 'fixture')
  const native = await client.resolve(created.session_id, new AbortController().signal)
  const upload = h.ctx.fileUploads.uploadStream.bind(h.ctx.fileUploads)
  h.ctx.fileUploads.uploadStream = async request => {
    const value = await upload(request)
    assert.equal(request.sessionId, native)
    const hash = createHash('sha256')
    let size = 0
    for await (const bytes of h.ctx.attachments.readFileStream(value.file)) { hash.update(bytes); size += bytes.byteLength }
    assert.ok(h.ctx.fileUploads.resolve(h.ctx.agents.get(native)!, value.receiptId))
    process.stdout.write(JSON.stringify({ type: 'native.upload', size_bytes: size, sha256: hash.digest('hex') }) + '\n')
    interval = setInterval(() => {
      const agent = h.ctx.agents.get(native)
      if (agent && h.ctx.fileUploads.resolve(agent, value.receiptId)) return
      clearInterval(interval)
      process.stdout.write(JSON.stringify({ type: 'native.retired' }) + '\n')
    }, 50)
    return value
  }
  const plugin = createRemoteControlPlugin({ async acquire() { return { installationId: config.installation, credential: config.credential,
    signer: { sign(input) { return sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }) } } } } })
  await plugin.apply(h.ctx, { enabled: true, runtimeId: config.runtime, workspaces, presets: ['fixture'],
    commandJournalPath: `${h.directory}/commands.sqlite`, relayUrl: config.url, applicationVersion: 'native-file-handoff-fixture' })
  process.stdout.write(JSON.stringify({ type: 'ready', session_id: created.session_id }) + '\n')
  process.stdin.resume()
  await once(process.stdin, 'data')
  process.stdin.pause()
  assert.equal(h.errors.length, 0)
} finally { if (interval) clearInterval(interval); await h.close() }
