import type { DatabaseSync } from 'node:sqlite'

const MIB = 1024 * 1024
export const DEFAULT_COMMAND_JOURNAL_MAX_BYTES = 1024 * MIB
export const MIN_COMMAND_JOURNAL_MAX_BYTES = MIB
export const MAX_COMMAND_JOURNAL_MAX_BYTES = 8 * 1024 * MIB

const invalid = () => new Error('command journal database capacity is invalid or exhausted')

/** Logical SQLite main-database capacity; WAL/filesystem quotas are separate. */
export function journalCapacityBytes(value: number | undefined): number {
  const bytes = value ?? DEFAULT_COMMAND_JOURNAL_MAX_BYTES
  if (!Number.isSafeInteger(bytes) || bytes < MIN_COMMAND_JOURNAL_MAX_BYTES || bytes > MAX_COMMAND_JOURNAL_MAX_BYTES || bytes % MIB !== 0) throw invalid()
  return bytes
}

export function configureJournalCapacity(database: DatabaseSync, maxBytes: number): void {
  const bytes = journalCapacityBytes(maxBytes)
  const pageSize = database.prepare('PRAGMA page_size').get()?.page_size
  const count = database.prepare('PRAGMA page_count').get()?.page_count
  if (typeof pageSize !== 'number' || !Number.isSafeInteger(pageSize) || pageSize <= 0 ||
      typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) throw invalid()
  const pages = bytes / pageSize
  if (!Number.isSafeInteger(pages) || count > pages) throw invalid()
  // Reapply on every connection, including reopen. Do not truncate, evict
  // tombstones or generate a replacement database to meet a smaller budget.
  if (database.prepare(`PRAGMA max_page_count = ${pages}`).get()?.max_page_count !== pages) throw invalid()
}
