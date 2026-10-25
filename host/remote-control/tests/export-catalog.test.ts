import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID, createHash } from 'node:crypto'
import { mkdir, writeFile, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { FileExportRegistry } from '../src/file-export-registry.js'
import { PinnedExportSource } from '../src/file-export-source.js'
import { ExportCatalog, type CatalogAuthority } from '../src/export-catalog.js'
import { PhoneExportFrame, ExportFrame } from '../src/export-protocol.js'

const supported = await PinnedExportSource.supported()
const signal = () => new AbortController().signal
const authority = (): CatalogAuthority => ({ owner: { userId: randomUUID(), deviceId: randomUUID() }, keyVersion: 1, grantVersion: 1, allowWorkspace: true, signal: signal(), current() {}, expiresAt: Date.now() + 290_000 })

test('opaque export directories page exact metadata without following links or accepting another scope', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd, exportRoots: [{ id: 'reports', directory: 'output' }] }], ['fixture'])
  const registry = new FileExportRegistry(client), catalog = new ExportCatalog(client, registry)
  try {
    await mkdir(join(h.cwd, 'output')); await mkdir(join(h.cwd, 'output', 'nested'))
    for (let i = 0; i < 35; i++) await writeFile(join(h.cwd, 'output', `report-${i}.txt`), `body-${i}`)
    await writeFile(join(h.cwd, 'private'), 'must not become an export')
    await symlink(join(h.cwd, 'private'), join(h.cwd, 'output', 'link'))
    const session = (await client.create('fixture', 'fixture')).session_id, actor = authority()
    const roots = await catalog.list(session, actor), directory = roots.items.find(item => item.name === 'reports')!.source_id
    const names = new Set<string>(); let cursor: string | undefined; let file: string | undefined
    do {
      const page = await catalog.list(session, actor, directory, cursor)
      assert.ok(page.items.length <= 16); assert.equal(JSON.stringify(page).includes(h.cwd), false)
      for (const item of page.items) { assert.ok(!names.has(item.name)); names.add(item.name); if (item.name === 'report-0.txt') file = item.source_id }
      cursor = page.cursor ?? undefined
    } while (cursor)
    assert.equal(names.size, 36); assert.ok(!names.has('link')); assert.ok(file)
    await assert.rejects(catalog.prepare(session, file!, { ...actor, owner: { ...actor.owner, deviceId: randomUUID() } }), /file.export_unavailable/)
    await assert.rejects(catalog.prepare(session, file!, { ...actor, allowWorkspace: false }), /access.denied/)
    await assert.rejects(catalog.prepare(session, file!, { ...actor, grantVersion: 2 }), /file.export_unavailable/)
    const narrow = await catalog.list(session, { ...actor, allowWorkspace: false })
    assert.deepEqual(narrow.items.map(item => item.origin), ['session_attachment'])
    await writeFile(join(h.cwd, 'output', 'report-0.txt'), 'different version')
    await assert.rejects(catalog.prepare(session, file!, actor), /file.export_changed/)
    assert.equal(JSON.stringify(catalog), '{}')
  } finally { await catalog.close(); await registry.close(); await h.close() }
})

test('attachment catalog discovers persisted native references and prepares only their original bytes', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new FileExportRegistry(client), catalog = new ExportCatalog(client, registry)
  try {
    const session = (await client.create('fixture', 'fixture')).session_id, native = await client.resolve(session, signal())
    const body = Buffer.from('catalog native attachment'), manifest = { name: '会话资料.bin', size_bytes: body.length, sha256: createHash('sha256').update(body).digest('hex') }
    const staged = await client.uploadFile(session, manifest, (async function* () { yield body })(), signal())
    await client.prompt(native, randomUUID(), 'queue', [{ type: 'file', receiptId: staged.receiptId }], signal()); await h.ctx.agents.get(native)!.whenIdle()
    const actor = { ...authority(), allowWorkspace: false }, roots = await catalog.list(session, actor)
    const page = await catalog.list(session, actor, roots.items[0]!.source_id)
    const item = page.items.find(item => item.kind === 'file' && item.name === manifest.name)!
    assert.ok(item); assert.equal(JSON.stringify(page).includes(staged.file.attachmentId), false)
    const entry = await catalog.prepare(session, item.source_id, actor)
    const chunks: Uint8Array[] = []; for await (const chunk of registry.read(entry.export_id, session, actor)) chunks.push(chunk)
    assert.deepEqual(Buffer.concat(chunks), body)
  } finally { await catalog.close(); await registry.close(); await h.close() }
})

test('phone export frames cannot supply actor authority, native references or filesystem paths', () => {
  const route = { v: 1, type: 'file.export.request', request_id: randomUUID(), runtime_id: randomUUID(), runtime_epoch: randomUUID(), session_id: randomUUID(), payload: { source_id: randomUUID() } }
  assert.ok(PhoneExportFrame.safeParse(route).success)
  for (const extra of [{ path: '/private' }, { receiptId: randomUUID() }, { user_id: randomUUID() }, { allow_workspace: true }, { lease_until: new Date().toISOString() }]) {
    assert.equal(PhoneExportFrame.safeParse({ ...route, payload: { ...route.payload, ...extra } }).success, false)
  }
  assert.equal(ExportFrame.safeParse({ ...route, type: 'file.export.manifest', payload: { source_id: route.payload.source_id, origin: 'workspace_artifact', name: '../private', size_bytes: 1, sha256: 'a'.repeat(64), source_expires_at: new Date().toISOString() } }).success, false)
})
