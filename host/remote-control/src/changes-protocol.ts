import { z } from 'zod'
export const CHANGES_CAPABILITY = 'session.changes.v1'
const uuid = z.uuid()
const digest = z.string().regex(/^[0-9a-f]{64}$/)
const cursor = uuid
const path = z.strictObject({ bytes_base64: z.string().max(16_384).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/), display: z.string().max(16_384) })
const kind = z.enum(['text', 'binary', 'symlink', 'gitlink'])
export const changesRequest = z.strictObject({ sync_id: uuid, limit: z.int().min(1).max(20), cursor: cursor.optional() })
export const changesPatchRequest = z.strictObject({ sync_id: uuid, snapshot_id: uuid, file_id: uuid, cursor: cursor.optional() })
export const changesFileSchema = z.strictObject({ file_id: uuid, status: z.enum(['added', 'modified', 'deleted', 'renamed', 'type_changed']),
  old_path: path.nullable(), new_path: path.nullable(), old_mode: z.string().regex(/^[0-7]{6}$/), new_mode: z.string().regex(/^[0-7]{6}$/),
  kind, patch_bytes: z.int().min(0).max(1024 * 1024), complete: z.boolean(), copyable: z.boolean() })
export const changesPageSchema = z.strictObject({ v: z.literal(1), sync_id: uuid, snapshot_id: uuid,
  source: z.literal('configured_workspace_git'), base: z.strictObject({ kind: z.literal('git_head'), oid: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/) }),
  version: digest, manifest_sha256: digest, expires_at: z.string().datetime({ offset: true }),
  scope: z.literal('tracked_head_to_index_worktree'), excluded: z.tuple([z.literal('untracked'), z.literal('ignored'), z.literal('submodule_contents')]),
  complete: z.literal(true), truncated: z.literal(false), files: z.array(changesFileSchema).max(20), next_cursor: cursor.nullable(),
})
const line = z.strictObject({ kind: z.enum(['context', 'add', 'delete', 'no_final_newline']), bytes_base64: z.string().max(22_000), text: z.string().max(16_384).nullable(), old_line: z.int().min(0).max(Number.MAX_SAFE_INTEGER).nullable(), new_line: z.int().min(0).max(Number.MAX_SAFE_INTEGER).nullable() })
export const changesPatchSchema = z.strictObject({ v: z.literal(1), sync_id: uuid, snapshot_id: uuid, file_id: uuid, version: digest, kind,
  complete: z.boolean(), copyable: z.boolean(), partial: z.boolean(), patch_base64: z.string().max(22_000), patch_utf8: z.string().max(16_384).nullable(),
  hunks: z.array(z.strictObject({ old_start: z.int().min(0), old_count: z.int().min(0), new_start: z.int().min(0), new_count: z.int().min(0), lines: z.array(line).max(20_000) })).max(20_000), next_cursor: cursor.nullable(),
}).refine(page => !page.copyable || page.complete && !page.partial && page.next_cursor === null && page.patch_utf8 !== null && page.kind !== 'binary')
