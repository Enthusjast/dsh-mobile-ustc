import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { NativeObservations, bindNativeObservations, nativePair } from '../src/native-observations.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { parseCommand } from '../src/protocol.js'
import { journalDatabase } from './journal-capacity-fixture.js'

test('journal observations require separate negotiation before reading the clock and stay in their connection', () => {
  let clockReads = 0
  const source = new NativeObservations(() => clockReads++), frames: any[] = []
  const identity = { connectionId: randomUUID(), runtimeId: randomUUID(), epoch: randomUUID() }
  source.start('journal_command')('persisted')
  const legacy = bindNativeObservations(source, identity, frame => { frames.push(frame); return true })
  source.start('journal_command')('persisted'); source.start('journal_approval')('failed')
  legacy.flush()
  assert.equal(clockReads, 0); assert.equal(frames.length, 0)
  source.start('prompt')('ok'); legacy.flush()
  assert.equal(frames[0].payload.series[0].operation, 'prompt')
  const current = bindNativeObservations(source, { ...identity, connectionId: randomUUID() }, frame => { frames.push(frame); return true }, true)
  legacy.close()
  const previous = source.start('journal_command')
  const replacement = bindNativeObservations(source, { ...identity, connectionId: randomUUID() }, frame => { frames.push(frame); return true }, true)
  try {
    current.close(); previous('persisted'); replacement.flush()
    assert.equal(frames.length, 1)
    source.start('journal_command')('persisted'); source.start('journal_approval')('failed'); replacement.flush()
    assert.deepEqual(frames[1].payload.series.map((item: any) => [item.operation, item.result]), [['journal_approval', 'failed'], ['journal_command', 'persisted']])
    for (const item of frames[1].payload.series) assert.equal(item.sum_micros, 1000)
  } finally { replacement.close() }
  assert.equal(nativePair('journal_command', 'ok'), false)
  assert.equal(nativePair('journal_approval', 'unavailable'), false)
})

test('real SQLite transactions report commit, rollback and BEGIN failure without changing durable state', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-observations-'))
  const path = join(root, 'state', 'commands.sqlite'), runtime = randomUUID(), epoch = randomUUID()
  let ticks = 0
  const observations = new NativeObservations(() => ticks++)
  const journal = await PersistentCommandJournal.open(path, runtime, { observations })
  const approvals = journal.approvals(epoch)
  const samples: { operation: string; result: string; micros: number }[] = []
  const dispose = observations.listen((operation, result, micros) => samples.push({ operation, result, micros }), true)
  t.after(async () => { dispose(); journal.close(); await rm(root, { recursive: true, force: true }) })
  assert.equal(ticks, 0, 'initialization must not cache offline observations')
  const owner = { userId: randomUUID(), deviceId: randomUUID() }
  const command = parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: epoch, session_id: randomUUID(), payload: { mode: 'queue', text: 'PRIVATE_JOURNAL_METRIC' } })
  assert.equal(journal.admit(command, owner).inserted, true)
  assert.equal(journal.admit(command, owner).inserted, false)
  assert.throws(() => journal.admit({ ...command, payload: { ...command.payload, text: 'different' } } as typeof command, owner), /command.request_conflict/)
  assert.equal(journal.lookup(command, owner)!.state, 'host_accepted')
  const database = journalDatabase(journal)
  database.exec('PRAGMA busy_timeout=1')
  const blocker = new DatabaseSync(path)
  try {
    blocker.exec('BEGIN IMMEDIATE')
    assert.throws(() => journal.start(command.request_id, owner), /locked/)
    assert.equal(blocker.isTransaction, true)
  } finally { blocker.exec('ROLLBACK'); blocker.close() }
  journal.start(command.request_id, owner)
  journal.complete(command.request_id, owner, 'agent_queued', { PRIVATE_RESULT: true })
  const beforeRetry = samples.length
  journal.complete(command.request_id, owner, 'agent_queued', {})
  assert.equal(samples.length, beforeRetry, 'an early return is not another commit')
  assert.equal(journal.lookup(command, owner)!.state, 'agent_queued')
  assert.throws(() => approvals.get(randomUUID()), /approval.stale/)
  assert.deepEqual(samples.map(({ operation, result }) => [operation, result]), [
    ['journal_command', 'persisted'], ['journal_command', 'persisted'], ['journal_command', 'failed'],
    ['journal_command', 'failed'], ['journal_command', 'persisted'], ['journal_command', 'persisted'], ['journal_approval', 'failed'],
  ])
  assert.ok(samples.every(item => item.micros === 1000))
  assert.equal(JSON.stringify(samples).includes('PRIVATE'), false)
  const broken = observations.listen(() => { throw new Error('PRIVATE_OBSERVER') }, true)
  try {
    assert.equal(journal.admit(command, owner).state, 'agent_queued')
    assert.throws(() => approvals.get(randomUUID()), /approval.stale/)
    assert.equal(database.isTransaction, false)
  } finally { broken() }
})
