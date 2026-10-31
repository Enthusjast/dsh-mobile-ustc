import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { mkdtemp, readFile, rm, access } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { DEFAULT_COMMAND_JOURNAL_MAX_BYTES, MAX_COMMAND_JOURNAL_MAX_BYTES } from '../src/journal-capacity.js'
import { parseCommand, type Command } from '../src/protocol.js'
import { journalDatabase, sqliteFull, TEST_JOURNAL_BYTES } from './journal-capacity-fixture.js'

const owner = { userId: 'capacity-owner', deviceId: 'capacity-device' }
const command = (): Command => parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: randomUUID(),
  session_id: randomUUID(), payload: { mode: 'queue', text: 'PRIVATE_CAPACITY_BODY_' + randomBytes(12_000).toString('hex') } })

test('journal capacity rejects invalid values before creating state', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-capacity-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  for (const value of [0, -1, NaN, Infinity, 1.5, TEST_JOURNAL_BYTES - 1, TEST_JOURNAL_BYTES + 1, MAX_COMMAND_JOURNAL_MAX_BYTES + TEST_JOURNAL_BYTES]) {
    const directory = join(root, randomUUID())
    await assert.rejects(PersistentCommandJournal.open(join(directory, 'commands.sqlite'), randomUUID(), { maxDatabaseBytes: value }), /capacity is invalid or exhausted/)
    await assert.rejects(access(directory), { code: 'ENOENT' })
  }
})

test('command and approval handles share the page budget, reapplied on reopen without evicting history', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-journal-capacity-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const path = join(root, 'commands.sqlite'), runtime = randomUUID()
  let journal = await PersistentCommandJournal.open(path, runtime, { maxDatabaseBytes: TEST_JOURNAL_BYTES })
  try {
    const database = journalDatabase(journal)
    const pageSize = Number(database.prepare('PRAGMA page_size').get()?.page_size)
    assert.equal(database.prepare('PRAGMA max_page_count').get()?.max_page_count, TEST_JOURNAL_BYTES / pageSize)
    const approvals = journal.approvals(randomUUID())
    assert.equal((approvals as unknown as { database: unknown }).database, database)
    const stored: Command[] = []
    let failed: Command | undefined
    for (let index = 0; index < 100; index++) {
      const next = command()
      try { journal.admit(next, owner); stored.push(next) }
      catch (error) { assert.equal(sqliteFull(error), true); failed = next; break }
    }
    assert.ok(failed && stored.length > 0 && stored.length < 100)
    assert.equal(journal.lookup(failed, owner), undefined)
    assert.equal(journal.lookup(stored[0]!, owner)?.state, 'host_accepted')
    const pages = Number(database.prepare('PRAGMA page_count').get()?.page_count)
    assert.ok(pages * pageSize <= TEST_JOURNAL_BYTES)
    journal.close()
    journal = await PersistentCommandJournal.open(path, runtime, { maxDatabaseBytes: TEST_JOURNAL_BYTES })
    assert.equal(journalDatabase(journal).prepare('PRAGMA max_page_count').get()?.max_page_count, TEST_JOURNAL_BYTES / pageSize)
    assert.equal(journal.lookup(stored[0]!, owner)?.state, 'host_accepted')
    journal.close()
    journal = await PersistentCommandJournal.open(path, runtime, { maxDatabaseBytes: 2 * TEST_JOURNAL_BYTES })
    journal.admit(failed, owner)
    for (let index = 0; index < 10; index++) journal.admit(command(), owner)
    journal.close()
    const before = await readFile(path)
    await assert.rejects(PersistentCommandJournal.open(path, runtime, { maxDatabaseBytes: TEST_JOURNAL_BYTES }), /capacity is invalid or exhausted/)
    assert.deepEqual(await readFile(path), before, 'a smaller budget rewrote the existing journal')
    journal = await PersistentCommandJournal.open(path, runtime)
    assert.equal(journalDatabase(journal).prepare('PRAGMA max_page_count').get()?.max_page_count, DEFAULT_COMMAND_JOURNAL_MAX_BYTES / pageSize)
    assert.equal(journal.lookup(stored[0]!, owner)?.state, 'host_accepted')
    assert.equal(journal.lookup(failed, owner)?.state, 'host_accepted')
  } finally { journal.close() }
})
