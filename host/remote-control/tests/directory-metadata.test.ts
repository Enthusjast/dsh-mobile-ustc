import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { directoryMetadataSchema, directoryName, nativeDirectoryMetadata, ordinaryDirectorySession } from '../src/directory-metadata.js'
import { DshClient } from '../src/dsh-client.js'
import { host } from './harness.js'

test('native summary hints preserve provenance and null withdrawal without invented labels', () => {
  assert.deepEqual(nativeDirectoryMetadata(undefined), { v: 1, title: null, workspace_title: null, title_source: null, title_as_of_seq: null })
  const projected = nativeDirectoryMetadata({ kind: 'cached', asOfSeq: 7, values: { title: '真正标题' } }, '真正工作区')
  assert.deepEqual(projected, { v: 1, title: '真正标题', workspace_title: '真正工作区', title_source: 'cached', title_as_of_seq: 7 })
  assert.equal(nativeDirectoryMetadata({ kind: 'sequenced', asOfSeq: 9, values: { title: null } }).title, null)
  assert.equal(nativeDirectoryMetadata({ kind: 'cached', asOfSeq: NaN, values: { title: 'bad cut' } }).title, null)
  assert.equal(directoryMetadataSchema.safeParse({ ...projected, cwd: '/private/path' }).success, false)
  assert.equal(directoryMetadataSchema.safeParse({ ...projected, v: 2 }).success, false)
  assert.equal(directoryMetadataSchema.safeParse({ ...projected, title: null }).success, false)
})

test('plain names enforce UTF16 and UTF8 bounds and reject forged display controls', () => {
  for (const value of ['', ' ', 'a'.repeat(257), '😀'.repeat(129), 'line\nname', 'spoof\u202ename', '\ud800', 'a\u0085b'])
    assert.equal(directoryName.safeParse(value).success, false)
  assert.equal(directoryName.safeParse('😀'.repeat(128)).success, true)
  assert.equal(directoryName.safeParse('中'.repeat(256)).success, true)
  assert.equal(nativeDirectoryMetadata({ kind: 'cached', asOfSeq: 1, values: { title: 'bad\nname' } }, 'bad\nworkspace').workspace_title, null)
})

test('only native seeded ordinary forks escape the parent-only directory exclusion', () => {
  assert.equal(ordinaryDirectorySession({}), true)
  assert.equal(ordinaryDirectorySession({ parentSession: 'parent' }), false)
  assert.equal(ordinaryDirectorySession({ parentSession: 'parent', isSeeded: true }), true)
  assert.equal(ordinaryDirectorySession({ origin: 'subagent', parentSession: 'parent', isSeeded: true }), false)
})

test('actual native title and workspace changes publish through the existing catalog watcher', async () => {
  const h = await host({ probe: false })
  const signal = AbortSignal.timeout(10_000)
  let stop = () => {}
  try {
    const workspace = h.ctx.workspaceRegistry.list().find(entry => entry.path === h.cwd) ??
      await h.ctx.workspaceRegistry.create(h.cwd, '原生工作区')
    await workspace.setTitle('原生工作区')
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd, remoteId: randomUUID(), label: 'NOT_NATIVE_LABEL' }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, signal)
    const changes: unknown[] = []
    stop = client.watchSessionCatalog(change => changes.push(change))
    await h.ctx.sessionController.rename({ sessionId: native, title: '原生会话标题' })
    await delay(300)
    assert.ok(changes.length > 0)
    const row = (await client.sessionCatalog(signal)).find(entry => entry.session_id === created.session_id)
    assert.equal(row?.metadata?.title, '原生会话标题')
    assert.equal(row?.metadata?.workspace_title, '原生工作区')
    assert.equal(row?.metadata?.title_source, 'sequenced')
    assert.equal(JSON.stringify(row).includes(h.cwd), false)
    assert.equal(JSON.stringify(row).includes('NOT_NATIVE_LABEL'), false)
    changes.length = 0
    await workspace.setTitle('更新工作区')
    await delay(300)
    assert.ok(changes.length > 0)
    assert.equal((await client.sessionCatalog(signal)).find(entry => entry.session_id === created.session_id)?.metadata?.workspace_title, '更新工作区')
    const hidden = new DshClient(h.ctx, h.runtimeId, [], [])
    const withdrawn = await hidden.sessionCatalog(signal, [String(native)])
    assert.equal(withdrawn[0]?.metadata?.title, null)
    assert.equal(withdrawn[0]?.metadata?.workspace_title, null)
  } finally { stop(); await h.close() }
})
