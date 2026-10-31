import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm, chmod, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

test('Linux WAL ENOSPC and sync EIO preserve honest native receipts and restart reconciliation', { skip: process.platform !== 'linux', timeout: 60_000 }, async t => {
  const available = spawnSync('cc', ['--version'], { stdio: 'ignore' })
  if (available.error || available.status !== 0) return t.skip('C compiler unavailable for isolated VFS fault fixture')
  const build = await mkdtemp(join(tmpdir(), 'dsh-journal-io-build-'))
  t.after(() => rm(build, { recursive: true, force: true }))
  const library = join(build, 'fault.so')
  const source = fileURLToPath(new URL('./fixtures/journal-io-fault.c', import.meta.url))
  const child = fileURLToPath(new URL('./fixtures/journal-io-child.ts', import.meta.url))
  const approvalChild = fileURLToPath(new URL('./fixtures/journal-io-approval-child.ts', import.meta.url))
  const compiled = spawnSync('cc', ['-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', library, '-ldl', '-pthread'], { encoding: 'utf8', timeout: 10_000 })
  assert.equal(compiled.status, 0, compiled.stderr)
  for (const mode of ['admit-write', 'start-sync', 'result-write', 'result-sync', 'checkpoint-sync']) {
    await t.test(mode, async t => {
      const root = await mkdtemp(join(tmpdir(), 'dsh-journal-io-'))
      t.after(() => rm(root, { recursive: true, force: true }))
      const env = { ...process.env, LD_PRELOAD: library, DSH_JOURNAL_IO_ROOT: root }
      const result = spawnSync(process.execPath, ['--import', 'tsx', child, mode], { env, encoding: 'utf8', timeout: 15_000, maxBuffer: 128 * 1024 })
      assert.equal(result.status, 0, result.stderr)
      const facts = JSON.parse(result.stdout.trim().split('\n').at(-1)!) as { mode: string; before: number; after: number; restored: string | null; faults: number; receipts: string[]; code: number | null; journalFailed: number }
      assert.equal(facts.mode, mode)
      assert.equal(facts.after, 1)
      assert.ok(facts.faults > 0)
      assert.equal(facts.before, mode === 'admit-write' || mode === 'start-sync' ? 0 : 1)
      if (mode !== 'checkpoint-sync') {
        assert.equal(facts.receipts.includes('agent_queued'), false)
        assert.ok(facts.journalFailed > 0, 'failed durable transaction missing from observations')
      } else assert.equal(facts.journalFailed, 0, 'raw checkpoint is outside transaction timing')
      if (mode.endsWith('write')) assert.equal(facts.code! % 256, 13)
      t.diagnostic(JSON.stringify(facts))
    })
  }
  for (const phase of ['decision-write', 'consume-sync']) {
    await t.test(phase, async t => {
      const root = await mkdtemp(join(tmpdir(), 'dsh-journal-io-'))
      t.after(() => rm(root, { recursive: true, force: true }))
      const result = spawnSync(process.execPath, ['--import', 'tsx', approvalChild, phase], {
        env: { ...process.env, LD_PRELOAD: library, DSH_JOURNAL_IO_ROOT: root }, encoding: 'utf8', timeout: 10_000, maxBuffer: 128 * 1024,
      })
      assert.equal(result.status, 0, result.stderr)
      const facts = JSON.parse(result.stdout.trim().split('\n').at(-1)!) as { phase: string; executions: number; restored: string; faults: number; journalFailed: number }
      assert.equal(facts.phase, phase); assert.equal(facts.executions, 0); assert.ok(facts.faults > 0)
      assert.ok(['invalidated', 'outcome_unknown'].includes(facts.restored))
      assert.ok(facts.journalFailed > 0, 'failed approval transaction missing from observations')
      t.diagnostic(JSON.stringify(facts))
    })
  }
  const guardedWrite = `const fs=require('node:fs'),path=require('node:path'),{DatabaseSync}=require('node:sqlite');
    const root=process.env.DSH_JOURNAL_IO_ROOT,dbpath=path.join(root,'state','commands.sqlite');
    fs.mkdirSync(path.dirname(dbpath),{mode:0o700});fs.writeFileSync(dbpath,'',{mode:0o600});
    const db=new DatabaseSync(dbpath);db.exec('PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;CREATE TABLE proof(value TEXT)');
    fs.writeFileSync(path.join(root,'inject'),'write-wal',{mode:0o600});db.exec("INSERT INTO proof VALUES('unaffected')");db.close();
    if(fs.existsSync(path.join(root,'faults')))process.exit(7);process.stdout.write('guarded-ok');`
  for (const boundary of ['wrong-prefix', 'unsafe-mode', 'symlink-root']) {
    await t.test(boundary, async t => {
      const root = await mkdtemp(join(tmpdir(), boundary === 'wrong-prefix' ? 'dsh-other-io-' : 'dsh-journal-io-'))
      t.after(() => rm(root, { recursive: true, force: true }))
      let selected = root
      if (boundary === 'unsafe-mode') await chmod(root, 0o755)
      if (boundary === 'symlink-root') {
        selected = root + '-alias'
        await symlink(root, selected)
        t.after(() => rm(selected, { force: true }))
      }
      const result = spawnSync(process.execPath, ['-e', guardedWrite], {
        env: { ...process.env, LD_PRELOAD: library, DSH_JOURNAL_IO_ROOT: selected }, encoding: 'utf8', timeout: 5000,
      })
      assert.equal(result.status, 0, result.stderr)
      assert.equal(result.stdout, 'guarded-ok')
    })
  }
})
