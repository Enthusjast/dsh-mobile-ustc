import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { SessionId } from '@deepseek-ai/dsh-session'
import type { FileUploadReceiptId } from '@deepseek-ai/dsh-client-file-upload'
import type { ImageMediaType } from '@deepseek-ai/dsh-attachment'
import type { PromptContentPart } from '@deepseek-ai/dsh-api-session-controller/types'
import type { FileManifest } from './file-admission.js'
import { MAX_IMAGE_BYTES, MAX_IMAGE_DIMENSION, MAX_IMAGE_PIXELS } from './image-protocol.js'
import { ProbeError } from './protocol.js'

interface RasterHeader { mediaType: ImageMediaType; width: number; height: number }
const invalid = (): never => { throw new ProbeError('image.invalid') }
function bounded(mediaType: ImageMediaType, width: number, height: number): RasterHeader {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 ||
    width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION || width * height > MAX_IMAGE_PIXELS) throw new ProbeError('image.too_large')
  return { mediaType, width, height }
}

/** Pre-decode admission only. A real native full decode is mandatory after these fixed allocation bounds. */
export function rasterHeader(bytes: Uint8Array): RasterHeader {
  const data = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (data.length < 10 || data.length > MAX_IMAGE_BYTES) invalid()
  if (data.length >= 33 && data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    if (data.readUInt32BE(8) !== 13 || data.toString('ascii', 12, 16) !== 'IHDR' ||
      ![1, 2, 4, 8, 16].includes(data[24]!) || ![0, 2, 3, 4, 6].includes(data[25]!) || data[26] !== 0 || data[27] !== 0 || data[28]! > 1) invalid()
    return bounded('image/png', data.readUInt32BE(16), data.readUInt32BE(20))
  }
  if (['GIF87a', 'GIF89a'].includes(data.toString('ascii', 0, 6))) return bounded('image/gif', data.readUInt16LE(6), data.readUInt16LE(8))
  if (data[0] === 0xff && data[1] === 0xd8) {
    let at = 2
    while (at < data.length) {
      if (data[at++] !== 0xff) invalid()
      while (at < data.length && data[at] === 0xff) at++
      if (at >= data.length) invalid()
      const marker = data[at++]!
      if (marker === 0xd9 || marker === 0xda) invalid()
      if (marker === 0x01 || marker >= 0xd0 && marker <= 0xd7) continue
      if (at + 2 > data.length) invalid()
      const length = data.readUInt16BE(at)
      if (length < 2 || at + length > data.length) invalid()
      if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
        if (length < 8 || ![8, 12, 16].includes(data[at + 2]!) || data[at + 7]! < 1 || data[at + 7]! > 4 || length !== 8 + 3 * data[at + 7]!) invalid()
        return bounded('image/jpeg', data.readUInt16BE(at + 5), data.readUInt16BE(at + 3))
      }
      at += length
    }
    invalid()
  }
  if (data.length >= 20 && data.toString('ascii', 0, 4) === 'RIFF' && data.toString('ascii', 8, 12) === 'WEBP') {
    if (data.readUInt32LE(4) + 8 !== data.length) invalid()
    let at = 12
    while (at + 8 <= data.length) {
      const kind = data.toString('ascii', at, at + 4), size = data.readUInt32LE(at + 4), start = at + 8
      if (size > data.length - start) invalid()
      if (kind === 'VP8X') {
        if (size !== 10) invalid()
        return bounded('image/webp', data.readUIntLE(start + 4, 3) + 1, data.readUIntLE(start + 7, 3) + 1)
      }
      if (kind === 'VP8 ') {
        if (size < 10 || data[start]! & 1 || data[start + 3] !== 0x9d || data[start + 4] !== 1 || data[start + 5] !== 0x2a) invalid()
        return bounded('image/webp', data.readUInt16LE(start + 6) & 0x3fff, data.readUInt16LE(start + 8) & 0x3fff)
      }
      if (kind === 'VP8L') {
        if (size < 5 || data[start] !== 0x2f) invalid()
        const bits = data.readUInt32LE(start + 1)
        return bounded('image/webp', (bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1)
      }
      at = start + size + (size & 1)
    }
  }
  return invalid()
}

// One full raster admission per native Context. Fixed pixel limits also bound 16-bit RGBA raw decode to 256 MB.
const decoding = new WeakSet<object>()
export async function resolveNativeImage(ctx: Context, id: SessionId, receiptId: FileUploadReceiptId, manifest: FileManifest,
  signal: AbortSignal, current: () => void): Promise<Extract<PromptContentPart, { type: 'image' }>> {
  if (manifest.size_bytes < 1 || manifest.size_bytes > MAX_IMAGE_BYTES) throw new ProbeError('image.too_large')
  signal.throwIfAborted(); current()
  const agent = ctx.agents.get(id)
  const staged = agent && ctx.fileUploads.resolve(agent, receiptId)
  if (!agent || !staged || staged.bytes !== manifest.size_bytes || String(staged.attachmentId) !== `sha256:${manifest.sha256}`) throw new ProbeError('file.staging_required')
  if (decoding.has(ctx)) throw new ProbeError('image.busy')
  decoding.add(ctx)
  const bytes = Buffer.alloc(manifest.size_bytes)
  const check = () => {
    signal.throwIfAborted(); current()
    if (ctx.agents.get(id) !== agent || ctx.fileUploads.resolve(agent, receiptId) !== staged) throw new ProbeError('file.staging_required')
  }
  try {
    let count = 0
    const hash = createHash('sha256')
    for await (const chunk of ctx.attachments.readFileStream(staged, signal)) {
      check()
      if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0 || chunk.byteLength > 64 * 1024 || chunk.byteLength > bytes.length - count) throw new ProbeError('file.integrity_mismatch')
      bytes.set(chunk, count); hash.update(chunk); count += chunk.byteLength
    }
    check()
    if (count !== bytes.length || hash.digest('hex') !== manifest.sha256) throw new ProbeError('file.integrity_mismatch')
    const header = rasterHeader(bytes)
    // Native validation performs complete frame-zero raster decode, checks MIME, applies orientation and bounded normalization.
    await ctx.attachments.validateImage({ data: bytes, mediaType: header.mediaType, name: manifest.name })
    check()
    return { type: 'image', mediaType: header.mediaType, data: bytes.toString('base64'), name: manifest.name }
  } catch (error) {
    signal.throwIfAborted()
    if (error instanceof ProbeError) throw error
    throw new ProbeError('image.invalid')
  } finally { bytes.fill(0); decoding.delete(ctx) }
}

/** Only the native structured pre-admission image rejection is definitely safe to settle as rejected. */
export function imagePromptError(error: unknown): ProbeError | undefined {
  if (!error || typeof error !== 'object' || !('isDSHRemoteError' in error) || error.isDSHRemoteError !== true ||
    !('code' in error) || error.code !== 'session/attachment-invalid') return undefined
  const details = 'details' in error && error.details && typeof error.details === 'object' ? error.details : undefined
  return new ProbeError(details && 'reason' in details && details.reason === 'MODEL_DOES_NOT_SUPPORT_IMAGES' ? 'image.model_unsupported' : 'image.invalid')
}
