import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { host } from './harness.js'
import { mediaPixelPNG } from './media-fixtures.js'
import { DshClient } from '../src/dsh-client.js'
import { FileExportRegistry } from '../src/file-export-registry.js'
import { PinnedExportSource } from '../src/file-export-source.js'
import { ExportCatalog, type CatalogAuthority } from '../src/export-catalog.js'
import { projectEvent } from '../src/projection.js'
import { visibleMediaReference } from '../src/media-protocol.js'

const supported = await PinnedExportSource.supported()

test('a visible native image resolves to the same authorized export pipeline and retires with its exact sync', { skip: !supported }, async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new FileExportRegistry(client)
  const sync = randomUUID()
  let active = true
  const catalog = new ExportCatalog(client, registry, (_session, selectedSync) => active && selectedSync === sync)
  const signal = new AbortController().signal
  const authority: CatalogAuthority = { owner: { userId: randomUUID(), deviceId: randomUUID() }, keyVersion: 1, grantVersion: 7,
    allowWorkspace: false, expiresAt: Date.now() + 60_000, signal, current() {} }
  try {
    const session = (await client.create('fixture', 'fixture')).session_id, native = await client.resolve(session, signal)
    await client.prompt(native, randomUUID(), 'queue', [{ type: 'image', mediaType: 'image/png', data: mediaPixelPNG().toString('base64'), name: 'history.png' }], signal)
    const agent = h.ctx.agents.get(native)!; await agent.whenIdle()
    const checkpoint = await client.checkpoint(native)
    if (checkpoint.state !== 'persisted') assert.fail('native image checkpoint unavailable')
    const event = agent.session.snapshotEvents().find(item => item.type === 'user/message' && item.data.source.kind === 'user')!
    if (event.type !== 'user/message') assert.fail('missing persisted image message')
    const image = event.data.content[0]!
    if (image.type !== 'image') assert.fail('native prompt did not persist an actual image')
    const page = await client.page(native, { throughSeq: checkpoint.through_seq, beforeSeq: event.seq + 1, maxMessages: 1 }, signal)
    const wireEvent = page.records.find(record => record.event.seq === event.seq)?.event
    assert.ok(wireEvent, 'the actual controller must serialize the persisted native event')
    const projected = projectEvent(wireEvent, true)
    const reference = visibleMediaReference.parse((projected.data.content as Array<{ reference: unknown }>)[0]!.reference)
    const source = await catalog.resolveMedia(session, sync, reference, authority)
    assert.equal(source.origin, 'session_attachment'); assert.equal(source.kind, 'file')
    await assert.rejects(catalog.prepare(session, source.source_id, { ...authority, owner: { ...authority.owner, deviceId: randomUUID() } }), /file.export_unavailable/)
    await assert.rejects(catalog.resolveMedia(session, sync, { ...reference, manifest: { ...reference.manifest, sha256: '0'.repeat(64) } }, authority), /file.export_changed/)
    await assert.rejects(catalog.resolveMedia(session, sync, { ...reference, event_version_sha256: '0'.repeat(64) }, authority), /file.export_changed/)
    const entry = await catalog.prepare(session, source.source_id, authority)
    const chunks: Uint8Array[] = []
    for await (const chunk of registry.read(entry.export_id, session, authority)) chunks.push(chunk)
    const expected = await h.ctx.attachments.readImage(image.attachment)
    assert.deepEqual(Buffer.concat(chunks), Buffer.from(expected.data))
    assert.equal(entry.sha256, reference.manifest.sha256)
    active = false
    await assert.rejects(catalog.prepare(session, source.source_id, authority), /file.export_unavailable/)
    await assert.rejects(catalog.resolveMedia(session, sync, reference, authority), /protocol.resync_required/)
    assert.equal(h.ctx.agents.get(native), agent)
    assert.equal(agent.session.snapshotEvents().filter(item => item.type === 'user/message' && item.data.source.kind === 'user').length, 1)
    assert.equal(h.errors.length, 0)
  } finally { await catalog.close(); await registry.close(); await h.close() }
})
