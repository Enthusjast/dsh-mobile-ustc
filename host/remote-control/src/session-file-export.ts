import type { Context } from '@deepseek-ai/cordis'
import { AttachmentId, type FileAttachmentRef, type ImageAttachmentRef, type ImageMediaType } from '@deepseek-ai/dsh-attachment'
import type { SessionWireEvent } from '@deepseek-ai/dsh-api-session-controller/types'
import { basename, dirname } from 'node:path'
import { fileManifest, type FileManifest } from './file-admission.js'
import { PinnedExportSource } from './file-export-source.js'
import { isHumanInput } from './projection.js'
import { ProbeError } from './protocol.js'

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

/** Resolve only a persisted, visible native reference supplied by the current Session controller. */
export async function sessionAttachmentSource(ctx: Context, event: SessionWireEvent, index: number, signal: AbortSignal, current: () => void): Promise<PinnedExportSource> {
  const data = object(event.data)
  const message = event.type === 'user/message' && isHumanInput(data.source) ? data
    : event.type === 'assistant/message' || event.type === 'tool/result' ? object(data.message) : {}
  const content = message.content
  if (!Array.isArray(content) || !Number.isSafeInteger(index) || index < 0 || index >= content.length) throw new ProbeError('file.export_unavailable')
  const block = object(content[index]), ref = object(block.attachment)
  if (typeof ref.attachmentId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(ref.attachmentId)) throw new ProbeError('file.export_unavailable')
  let name = ref.name
  let path: string | undefined
  const media = new Map<string, string>([['image/png', 'png'], ['image/jpeg', 'jpg'], ['image/webp', 'webp'], ['image/gif', 'gif']])
  if (block.type === 'image' && typeof ref.mediaType === 'string' && media.has(ref.mediaType)) {
    if (!Number.isSafeInteger(ref.width) || (ref.width as number) <= 0 || !Number.isSafeInteger(ref.height) || (ref.height as number) <= 0) throw new ProbeError('file.export_unavailable')
    if (!fileManifest.shape.name.safeParse(name).success) name = `image.${media.get(ref.mediaType)!}`
  }
  const parsed = fileManifest.safeParse({ name, size_bytes: ref.bytes, sha256: ref.attachmentId.slice(7) })
  if (!parsed.success) throw new ProbeError('file.export_unavailable')
  const manifest: FileManifest = parsed.data
  const identity = { attachmentId: AttachmentId(ref.attachmentId), name: manifest.name, bytes: manifest.size_bytes }
  if (block.type === 'file') path = ctx.attachments.fileHostPath(identity satisfies FileAttachmentRef)
  else if (block.type === 'image' && typeof ref.mediaType === 'string' && media.has(ref.mediaType)) path = ctx.attachments.imageHostPath({
    ...identity, mediaType: ref.mediaType as ImageMediaType, width: ref.width as number, height: ref.height as number,
  } satisfies ImageAttachmentRef)
  else throw new ProbeError('file.export_unavailable')
  if (path === undefined) throw new ProbeError('file.export_unsupported')
  signal.throwIfAborted(); current()
  return PinnedExportSource.open({ root: dirname(path), parts: [basename(path)], attachment: manifest }, signal, current)
}
