import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { PinnedExportSource } from '../src/file-export-source.js'
import { FileExportRegistry } from '../src/file-export-registry.js'
import { putExportSource } from '../src/export-upload.js'

const supported = await PinnedExportSource.supported()
async function fixture(body: Buffer, run: (registry: FileExportRegistry, entry: Awaited<ReturnType<FileExportRegistry['registerWorkspaceArtifact']>>, session: string, actor: {owner:{userId:string;deviceId:string};signal:AbortSignal;current():void}) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-export-put-')), signal = new AbortController().signal
  await writeFile(join(root, 'source.bin'), body)
  const registry = new FileExportRegistry({ workspaceExportSource: async (_session, _root, _parts, lifetime, current) => PinnedExportSource.open({ root, parts: ['source.bin'] }, lifetime, current), attachmentExportSource: async () => { throw new Error('not used') } })
  const actor = { owner: { userId: randomUUID(), deviceId: randomUUID() }, signal, current() {} }, session = randomUUID()
  try { const entry = await registry.registerWorkspaceArtifact(session, 'root', ['source.bin'], actor); await run(registry, entry, session, actor) }
  finally { await registry.close(); await rm(root, { recursive: true, force: true }) }
}
const capability = () => ({ url: 'https://objects.example.edu/private?signature=fixture', method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, expires_at: new Date(Date.now() + 30_000).toISOString() })

test('export transport streams exact anonymous bytes and closes consumed sources, including empty objects', { skip: !supported }, async () => {
  const original = globalThis.fetch
  try {
    for (const body of [Buffer.alloc(0), Buffer.alloc(180_000, 37)]) await fixture(body, async (registry, entry, session, actor) => {
      let calls = 0
      globalThis.fetch = (async (_url, options) => {
        calls++
        assert.equal(options?.method, 'PUT'); assert.equal(options?.redirect, 'error'); assert.equal(options?.credentials, 'omit')
        const headers = new Headers(options?.headers)
        for (const key of ['authorization', 'dpop', 'cookie']) assert.equal(headers.get(key), null)
        assert.equal(headers.get('content-length'), String(body.length)); assert.equal(headers.get('cache-control'), 'no-store')
        const value = options?.body
        const parts: Uint8Array[] = []
        if (value instanceof ReadableStream) { const reader = value.getReader(); for (;;) { const next = await reader.read(); if (next.done) break; assert.ok(next.value.byteLength <= 65536); parts.push(next.value) } }
        else if (value instanceof Uint8Array) parts.push(value)
        else assert.fail('unexpected body transport')
        assert.deepEqual(Buffer.concat(parts), body)
        return new Response(null, { status: 200 })
      }) as typeof fetch
      await putExportSource(registry, entry, session, actor, capability(), actor.signal)
      assert.equal(calls, 1); assert.throws(() => registry.describe(entry.export_id, session, actor), /file.export_unavailable/)
    })
  } finally { globalThis.fetch = original }
})

test('unsafe export capabilities fail before another request or private headers can be sent', { skip: !supported }, async () => {
  const original = globalThis.fetch
  try {
    let sent = 0
    globalThis.fetch = (async () => { sent++; return new Response(null, { status: 307 }) }) as typeof fetch
    await fixture(Buffer.from('bytes'), async (registry, entry, session, actor) => {
      const base = capability()
      for (const unsafe of [
        { ...base, url: 'http://objects.example.edu/private' }, { ...base, url: 'https://user:secret@objects.example.edu/private' },
        { ...base, url: base.url + '#private' }, { ...base, expires_at: new Date(Date.now() - 1).toISOString() },
        { ...base, headers: { ...base.headers, Authorization: 'private' } }, { ...base, headers: { ...base.headers, DPoP: 'private' } },
        { ...base, headers: { ...base.headers, 'content-type': 'application/octet-stream' } }, { ...base, headers: { ...base.headers, 'Content-Length': '7' } },
      ]) await assert.rejects(putExportSource(registry, entry, session, actor, unsafe, actor.signal))
      assert.equal(sent, 0)
      await assert.rejects(putExportSource(registry, entry, session, actor, base, actor.signal), /file.export_unavailable/)
      assert.equal(sent, 1)
    })
  } finally { globalThis.fetch = original }
})
