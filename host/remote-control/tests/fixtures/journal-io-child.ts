import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { lstat, readFile, realpath, unlink, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { host } from '../harness.js'
import { journalDatabase } from '../journal-capacity-fixture.js'
import { PersistentCommandJournal } from '../../src/command-journal.js'
import { DshClient } from '../../src/dsh-client.js'
import { ProbeRuntime } from '../../src/runtime.js'
import { parseCommand } from '../../src/protocol.js'
import type { InteractionRouter } from '../../src/interaction-router.js'

const mode = process.argv[2]
assert.ok(mode && ['admit-write', 'start-sync', 'result-write', 'result-sync', 'checkpoint-sync'].includes(mode))
const root = process.env.DSH_JOURNAL_IO_ROOT
assert.ok(root && root.startsWith('/') && /^dsh-journal-io-[A-Za-z0-9_-]+$/.test(basename(root)))
assert.equal(await realpath(root), root)
const metadata = await lstat(root)
assert.equal(metadata.uid, process.getuid!()); assert.equal(metadata.mode & 0o777, 0o700)
const flag = join(root, 'inject'), path = join(root, 'state', 'commands.sqlite')
const disable = () => unlink(flag).catch(error => { if (error.code !== 'ENOENT') throw error })
const activate = async (fault: string) => {
  await writeFile(flag, fault, { mode: 0o600 })
  // Same process and root, but a different file: the shim must leave it alone.
  await writeFile(join(root, 'unrelated'), 'unaffected', { mode: 0o600 })
  assert.equal(await readFile(join(root, 'unrelated'), 'utf8'), 'unaffected')
}
const fixture = await host({ probe: false, directory: join(root, 'native') })
let journal = await PersistentCommandJournal.open(path, fixture.runtimeId)
let client = new DshClient(fixture.ctx, fixture.runtimeId, [{ id: 'fixture', cwd: fixture.cwd }], ['fixture'])
let runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
const signal = new AbortController(), owner = { userId: randomUUID(), deviceId: randomUUID() }
const receipts: string[] = []
let code: number | undefined, closedWithError = false
try {
  journalDatabase(journal).exec('PRAGMA wal_autocheckpoint=0')
  const created = await client.create('fixture', 'fixture')
  const native = await client.resolve(created.session_id, signal.signal)
  const agent = fixture.ctx.agents.get(native)!
  const command = parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: runtime.epoch,
    session_id: created.session_id, payload: { mode: 'queue', text: `PRIVATE_IO_FAULT_${randomUUID()}` } })
  const messages = () => agent.session.snapshotEvents().filter(event => event.type === 'user/message'
    && (event.data.source as unknown as { rpcId?: string }).rpcId === `m0:${owner.deviceId}:${command.request_id}`)
  if (mode.startsWith('result-')) {
    const prompt = client.prompt.bind(client)
    client.prompt = async (...args) => {
      const result = await prompt(...args)
      assert.equal(result.checkpoint.state, 'persisted')
      await activate(mode === 'result-write' ? 'write-wal' : 'sync-wal')
      return result
    }
  }
  if (mode === 'admit-write') await activate('write-wal')
  let failure: unknown
  try {
    await runtime.dispatch(command, signal.signal, owner, async state => {
      receipts.push(state)
      if (mode === 'start-sync' && state === 'host_accepted') await activate('sync-wal')
    })
    if (mode === 'checkpoint-sync') {
      await activate('sync-db')
      journalDatabase(journal).exec('PRAGMA wal_checkpoint(TRUNCATE)')
    }
  } catch (error) { failure = error; if (error instanceof Error && 'errcode' in error) code = Number(error.errcode) }
  assert.ok(failure, 'injected I/O failure was not observed')
  await disable()
  const faults = await readFile(join(root, 'faults'), 'utf8')
  assert.ok(faults.length > 0 && /^[wsm]+$/.test(faults))
  assert.ok(faults.includes(mode === 'checkpoint-sync' ? 'm' : mode.endsWith('write') ? 'w' : 's'))
  await agent.whenIdle()
  const before = messages().length
  assert.equal(before, mode === 'admit-write' || mode === 'start-sync' ? 0 : 1)
  if (mode !== 'checkpoint-sync') assert.equal(receipts.includes('agent_queued'), false, 'failed durable I/O emitted success')
  runtime.close()
  try { journal.close() } catch { closedWithError = true; assert.equal(journalDatabase(journal).isOpen, false) }
  journal = await PersistentCommandJournal.open(path, fixture.runtimeId)
  assert.equal(journalDatabase(journal).prepare('PRAGMA integrity_check').get()?.integrity_check, 'ok')
  const restored = journal.lookup(command, owner)?.state
  if (mode === 'checkpoint-sync') assert.equal(restored, 'agent_queued')
  client = new DshClient(fixture.ctx, fixture.runtimeId, [{ id: 'fixture', cwd: fixture.cwd }], ['fixture'])
  runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
  const retry = { ...command, runtime_epoch: runtime.epoch }
  if (restored === 'outcome_unknown') await assert.rejects(runtime.dispatch(retry, signal.signal, owner), /command.outcome_unknown/)
  else {
    await runtime.dispatch(retry, signal.signal, owner)
    await runtime.dispatch(retry, signal.signal, owner)
  }
  await agent.whenIdle()
  assert.equal(messages().length, 1, 'I/O recovery or original-ID retry duplicated native work')
  process.stdout.write(JSON.stringify({ mode, before, after: messages().length, restored: restored ?? null, receipts, faults: faults.length, code: code ?? null, closedWithError }) + '\n')
} finally {
  await disable()
  signal.abort(); runtime.close()
  try { journal.close() } finally { await fixture.close() }
}
