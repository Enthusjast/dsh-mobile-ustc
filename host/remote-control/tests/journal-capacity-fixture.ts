import type { DatabaseSync } from 'node:sqlite'
import type { PersistentCommandJournal } from '../src/command-journal.js'

export const TEST_JOURNAL_BYTES = 1024 * 1024

/** Only a fixture may access the private connection; no production fault hook. */
export function journalDatabase(journal: PersistentCommandJournal): DatabaseSync {
  return (journal as unknown as { database: DatabaseSync }).database
}

export function sqliteFull(error: unknown): boolean {
  return error instanceof Error && 'errcode' in error && Number(error.errcode) % 256 === 13
}

/** Allocation invokes the real pager limit and SQLite auto-rollback. */
export function injectJournalFull(journal: PersistentCommandJournal, table: 'commands' | 'approval_records', event: 'INSERT' | 'UPDATE', condition: string): () => void {
  const database = journalDatabase(journal)
  database.exec(`CREATE TABLE fixture_full_padding(data BLOB);
    CREATE TRIGGER fixture_force_full BEFORE ${event} ON ${table} WHEN ${condition}
    BEGIN INSERT INTO fixture_full_padding(data) VALUES(zeroblob(${2 * TEST_JOURNAL_BYTES})); END;`)
  return () => database.exec('DROP TRIGGER fixture_force_full; DROP TABLE fixture_full_padding;')
}
