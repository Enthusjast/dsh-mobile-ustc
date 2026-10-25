import { createHash, randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { SessionId } from '@deepseek-ai/dsh-session'
import type { FileUploadReceiptId, FileUploadValue } from '@deepseek-ai/dsh-client-file-upload'
import { z } from 'zod'
import { ProbeError } from './protocol.js'

export const MAX_UPLOAD_FILE_BYTES = 200_000_000
export const MAX_FILE_CHUNK_BYTES = 64 * 1024

/** Transfer metadata describes bytes from quarantine, never a host filesystem path. */
export const fileManifest = z.strictObject({
  name: z.string().min(1).max(512).regex(/^[^\\/\p{Cc}\p{Cs}]+$/u).refine(name => Buffer.byteLength(name) <= 512 && name.trim().length > 0
    && name !== '.' && name !== '..' && !/[\\/\p{Cc}\p{Cs}]/u.test(name)),
  size_bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
})
export type FileManifest = z.infer<typeof fileManifest>

/** Retire only the receipt found under this exact live native Session. */
export function releaseNativeFile(ctx: Context, id: SessionId, receiptId: FileUploadReceiptId): boolean {
  const agent = ctx.agents.get(id)
  if (!agent || !ctx.fileUploads.resolve(agent, receiptId)) return false
  const bindingId = `remote-file-release:${randomUUID()}`
  const binding = ctx.fileUploads.bindPrompt(agent, [receiptId], bindingId)
  try {
    binding.commit()
    ctx.fileUploads.retirePrompt(agent, bindingId)
  } finally { binding[Symbol.dispose]() }
  return true
}

/** The native service has no file-size admission limit, so bound and hash its stream before minting a receipt. */
export async function admitNativeFile(ctx: Context, id: SessionId, input: FileManifest,
  source: AsyncIterable<Uint8Array>, signal: AbortSignal, ensureCurrent: () => void): Promise<FileUploadValue> {
  const parsed = fileManifest.safeParse(input)
  if (!parsed.success) throw new ProbeError('file.invalid')
  const manifest = parsed.data
  if (manifest.size_bytes > MAX_UPLOAD_FILE_BYTES) throw new ProbeError('file.too_large')
  if (signal.aborted) throw new ProbeError('file.cancelled')
  ensureCurrent()
  let validationFailure: ProbeError | undefined
  const fail = (code: string): never => { validationFailure = new ProbeError(code); throw validationFailure }
  const check = () => {
    try { ensureCurrent() }
    catch (error) { if (error instanceof ProbeError) validationFailure = error; throw error }
  }
  const verified = async function* () {
    const hash = createHash('sha256')
    let bytes = 0
    for await (const chunk of source) {
      signal.throwIfAborted()
      check()
      if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0 || chunk.byteLength > MAX_FILE_CHUNK_BYTES) fail('file.chunk_invalid')
      bytes += chunk.byteLength
      if (bytes > manifest.size_bytes) fail('file.integrity_mismatch')
      // A producer can reuse its input buffer after yield. Hash and store one
      // bounded private copy so those two observations cannot diverge.
      const copy = Buffer.from(chunk)
      hash.update(copy)
      yield copy
    }
    signal.throwIfAborted()
    check()
    if (bytes !== manifest.size_bytes || hash.digest('hex') !== manifest.sha256) fail('file.integrity_mismatch')
  }
  let uploaded: FileUploadValue | undefined
  try {
    uploaded = await ctx.fileUploads.uploadStream({ sessionId: id, data: verified(), name: manifest.name, signal })
    signal.throwIfAborted()
    ensureCurrent()
    const agent = ctx.agents.get(id)
    if (!agent || !ctx.fileUploads.resolve(agent, uploaded.receiptId)) throw new ProbeError('file.staging_required')
    if (String(uploaded.file.attachmentId) !== `sha256:${manifest.sha256}` || uploaded.file.bytes !== manifest.size_bytes) fail('file.integrity_mismatch')
    return uploaded
  } catch (error) {
    if (uploaded) {
      try { releaseNativeFile(ctx, id, uploaded.receiptId) } catch { /* An unpublished receipt never becomes remote authority. */ }
    }
    if (signal.aborted) throw new ProbeError('file.cancelled')
    if (validationFailure) throw validationFailure
    if (error instanceof ProbeError) throw error
    throw new ProbeError('file.admission_failed')
  }
}
