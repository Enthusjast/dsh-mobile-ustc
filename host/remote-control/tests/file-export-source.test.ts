import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, open, rm, symlink, link, readdir, readlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { inspect } from 'node:util'
import { MAX_EXPORT_FILE_BYTES, PinnedExportSource } from '../src/file-export-source.js'
import { ProbeError } from '../src/protocol.js'

const signal = () => new AbortController().signal
const current = () => {}
const digest = (value: Uint8Array) => createHash('sha256').update(value).digest('hex')
async function fixture(run: (root: string) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-export-source-'))
  try { await run(directory) } finally { await rm(directory, { recursive: true, force: true }) }
}
async function bytes(source: PinnedExportSource) {
  const parts: Uint8Array[] = []
  for await (const chunk of source.read(signal())) { assert.ok(chunk.byteLength <= 65536); parts.push(chunk) }
  return Buffer.concat(parts)
}
async function descriptors(root: string) {
  return (await Promise.all((await readdir('/proc/self/fd')).map(name => readlink(`/proc/self/fd/${name}`).catch(() => '')))).filter(path => path.startsWith(root)).length
}
const supported = await PinnedExportSource.supported()

test('an fd-pinned source hashes then streams bounded exact bytes, including empty files', { skip: !supported }, async () => {
  await fixture(async root => {
    for (const body of [Buffer.alloc(0), Buffer.from([0, 255, 10]), Buffer.alloc(180_000, 37)]) {
      await writeFile(join(root, '资料.bin'), body)
      const source = await PinnedExportSource.open({ root, parts: ['资料.bin'] }, signal(), current)
      const manifest = await source.prepare(signal())
      assert.deepEqual(manifest, { name: '资料.bin', size_bytes: body.length, sha256: digest(body) })
      manifest.sha256 = '0'.repeat(64) // A caller cannot replace the private prepared digest.
      assert.deepEqual(await bytes(source), body)
      await assert.rejects(source.prepare(signal()))
    }
    assert.equal(await descriptors(root), 0)
  })
})

test('export traversal refuses final links, parent links, root links and directories without following them', { skip: !supported }, async () => {
  await fixture(async root => {
    await mkdir(join(root, 'allowed')); await mkdir(join(root, 'elsewhere'))
    await writeFile(join(root, 'elsewhere', 'secret'), 'private bytes')
    await symlink(join(root, 'elsewhere'), join(root, 'allowed', 'via-directory'))
    await symlink(join(root, 'elsewhere', 'secret'), join(root, 'allowed', 'via-file'))
    await symlink(join(root, 'allowed'), join(root, 'root-link'))
    for (const spec of [
      { root: join(root, 'allowed'), parts: ['via-file'] },
      { root: join(root, 'allowed'), parts: ['via-directory', 'secret'] },
      { root: join(root, 'root-link'), parts: ['via-file'] },
      { root, parts: ['elsewhere'] },
    ]) {
      await assert.rejects(PinnedExportSource.open(spec, signal(), current), /file.export_unavailable/)
    }
    assert.equal(await descriptors(root), 0)
  })
})

test('workspace hard links are refused; native immutable aliases require their authoritative manifest', { skip: !supported }, async () => {
  await fixture(async root => {
    const body = Buffer.from('native immutable file')
    await writeFile(join(root, 'object'), body); await link(join(root, 'object'), join(root, 'alias.bin'))
    await assert.rejects(PinnedExportSource.open({ root, parts: ['alias.bin'] }, signal(), current), /file.export_unavailable/)
    const attachment = { name: 'alias.bin', size_bytes: body.length, sha256: digest(body) }
    const source = await PinnedExportSource.open({ root, parts: ['alias.bin'], attachment }, signal(), current)
    assert.deepEqual(await source.prepare(signal()), attachment); assert.deepEqual(await bytes(source), body)
    const corrupt = await PinnedExportSource.open({ root, parts: ['alias.bin'], attachment: { ...attachment, sha256: '0'.repeat(64) } }, signal(), current)
    await assert.rejects(corrupt.prepare(signal()), /file.export_changed/)
    assert.equal(await descriptors(root), 0)
  })
})

test('changes after preparation or between chunks cannot publish changed bytes', { skip: !supported }, async () => {
  await fixture(async root => {
    const path = join(root, 'artifact.bin')
    await writeFile(path, Buffer.alloc(190_000, 11))
    const source = await PinnedExportSource.open({ root, parts: ['artifact.bin'] }, signal(), current)
    await source.prepare(signal())
    const stream = source.read(signal())
    assert.equal((await stream.next()).value?.byteLength, 65536)
    const writer = await open(path, 'r+')
    try { await writer.write(Buffer.from('replacement secret'), 0, 18, 130_000) } finally { await writer.close() }
    await assert.rejects(stream.next(), /file.export_changed/)
    await writeFile(path, 'stable')
    const later = await PinnedExportSource.open({ root, parts: ['artifact.bin'] }, signal(), current)
    await later.prepare(signal()); await writeFile(path, 'changed')
    await assert.rejects(bytes(later), /file.export_changed/)
    assert.equal(await descriptors(root), 0)
  })
})

test('a directory swapped to a link after pinning cannot redirect an already opened source', { skip: !supported }, async () => {
  await fixture(async root => {
    const { rename } = await import('node:fs/promises')
    await mkdir(join(root, 'allowed')); await mkdir(join(root, 'other'))
    await writeFile(join(root, 'allowed', 'artifact'), 'original authorized bytes')
    await writeFile(join(root, 'other', 'artifact'), 'unrelated secret')
    const source = await PinnedExportSource.open({ root, parts: ['allowed', 'artifact'] }, signal(), current)
    await source.prepare(signal())
    await rename(join(root, 'allowed'), join(root, 'original'))
    await symlink(join(root, 'other'), join(root, 'allowed'))
    assert.equal((await bytes(source)).toString(), 'original authorized bytes')
    assert.equal(await descriptors(root), 0)
  })
})

test('revocation, cancellation and early consumer return close the descriptor and stop the source', { skip: !supported }, async () => {
  await fixture(async root => {
    await writeFile(join(root, 'artifact'), Buffer.alloc(170_000, 8))
    let authorized = true
    const source = await PinnedExportSource.open({ root, parts: ['artifact'] }, signal(), () => { if (!authorized) throw new ProbeError('access.denied') })
    await source.prepare(signal()); const stream = source.read(signal()); await stream.next()
    authorized = false
    await assert.rejects(stream.next(), /access.denied/)
    const abort = new AbortController()
    const cancelled = await PinnedExportSource.open({ root, parts: ['artifact'] }, abort.signal, current)
    abort.abort(); await assert.rejects(cancelled.prepare(signal()), { name: 'AbortError' })
    const early = await PinnedExportSource.open({ root, parts: ['artifact'] }, signal(), current)
    await early.prepare(signal()); const stopped = early.read(signal()); await stopped.next(); await stopped.return(undefined)
    assert.equal(await descriptors(root), 0)
  })
})

test('the two GB bound, invalid path components and source redaction are enforced before export', { skip: !supported }, async () => {
  await fixture(async root => {
    const big = await open(join(root, 'too-large'), 'w')
    try { await big.truncate(MAX_EXPORT_FILE_BYTES + 1) } finally { await big.close() }
    await assert.rejects(PinnedExportSource.open({ root, parts: ['too-large'] }, signal(), current), /file.too_large/)
    for (const parts of [[], ['..', 'secret'], ['x/y'], ['x\\y'], ['.'], ['\ud800'], ['x\n']]) {
      await assert.rejects(PinnedExportSource.open({ root, parts }, signal(), current), /file.export_invalid/)
    }
    await writeFile(join(root, 'PRIVATE_SOURCE_NAME'), 'bytes')
    const source = await PinnedExportSource.open({ root, parts: ['PRIVATE_SOURCE_NAME'] }, signal(), current)
    assert.equal(JSON.stringify(source), '{}'); assert.equal(inspect(source), 'PinnedExportSource')
    await source.close(); assert.equal(await descriptors(root), 0)
  })
})
