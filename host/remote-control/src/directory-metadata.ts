import { z } from 'zod'
import type { SessionProjectionHints } from '@deepseek-ai/dsh-api-session-controller/types'

export const DIRECTORY_METADATA_CAPABILITY = 'session.metadata.v1'
const forbidden = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u
export const directoryName = z.string().min(1).max(256).refine(value =>
  value.trim().length > 0 && Buffer.byteLength(value, 'utf8') <= 1024 && !forbidden.test(value) && !/[\ud800-\udfff]/u.test(value))
export const directoryMetadataSchema = z.strictObject({
  v: z.literal(1), title: directoryName.nullable(), workspace_title: directoryName.nullable(),
  title_source: z.enum(['cached', 'sequenced']).nullable(),
  title_as_of_seq: z.number().int().min(-1).max(Number.MAX_SAFE_INTEGER).nullable(),
}).refine(value => (value.title === null) === (value.title_source === null) &&
  (value.title_source === null) === (value.title_as_of_seq === null))
export type DirectoryMetadata = z.infer<typeof directoryMetadataSchema>

/** No paths, configuration labels, first-message text or display-title fallbacks. */
export function nativeDirectoryMetadata(projections: SessionProjectionHints | undefined, workspaceTitle?: unknown): DirectoryMetadata {
  const title = directoryName.safeParse(projections?.values.title)
  const workspace = directoryName.safeParse(workspaceTitle)
  const validCut = projections !== undefined && Number.isSafeInteger(projections.asOfSeq) && projections.asOfSeq >= -1
  return { v: 1, title: title.success && validCut ? title.data : null,
    workspace_title: workspace.success ? workspace.data : null,
    title_source: title.success && validCut ? projections!.kind : null,
    title_as_of_seq: title.success && validCut ? projections!.asOfSeq : null }
}

/** Seeded ordinary forks remain independent roots; true subagents never do. */
export function ordinaryDirectorySession(header: { origin?: string; parentSession?: unknown; isSeeded?: boolean }): boolean {
  return header.origin !== 'subagent' && (header.parentSession === undefined || header.isSeeded === true)
}
