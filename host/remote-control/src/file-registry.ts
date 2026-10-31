import type { SessionId } from '@deepseek-ai/dsh-session'
import type { FileUploadValue } from '@deepseek-ai/dsh-client-file-upload'
import type { DshClient, DshPromptPart } from './dsh-client.js'
import type { FileOffer } from './file-protocol.js'
import { ProbeError } from './protocol.js'

interface StagedFile { file: FileOffer; session: string; native: SessionId; upload: FileUploadValue; signal: AbortSignal; valid: () => boolean; confirmed: boolean }

/** Native receipts stay in this process and are fenced by the exact socket lifetime. */
export class NativeFileRegistry {
  private readonly entries = new Map<string, StagedFile>()
  constructor(readonly client: DshClient, readonly epoch: string) {}

  async stage(session: string, file: FileOffer, source: AsyncIterable<Uint8Array>, signal: AbortSignal, valid: () => boolean): Promise<string> {
    if (this.entries.size >= 32 && !this.entries.has(file.file_id)) throw new ProbeError('file.staging_limit')
    signal.throwIfAborted()
    if (!valid()) throw new ProbeError('file.stale')
    const native = await this.client.resolve(session, signal)
    const upload = await this.client.uploadFile(session, { name: file.name, size_bytes: file.size_bytes, sha256: file.sha256 }, source, signal)
    if (signal.aborted || !valid()) { this.client.releaseFile(native, upload.receiptId); throw new ProbeError('file.stale') }
    this.drop(file.file_id)
    this.entries.set(file.file_id, { file: { ...file, download_token: '' }, session, native, upload, signal, valid, confirmed: false })
    return upload.file.name
  }
  confirm(fileId: string): void { const staged = this.entries.get(fileId); if (staged) staged.confirmed = true }

  available(fileId: string): boolean {
    const staged = this.entries.get(fileId)
    return staged !== undefined && staged.confirmed && !staged.signal.aborted && staged.valid() && this.client.fileStaged(staged.native, staged.upload.receiptId)
  }

  resolve(fileId: string, session: string, owner: { userId: string; deviceId: string }): DshPromptPart {
    const staged = this.entries.get(fileId)
    if (staged && (staged.signal.aborted || !staged.valid() || !this.client.fileStaged(staged.native, staged.upload.receiptId))) this.drop(fileId)
    if (!staged || !this.entries.has(fileId) || !staged.confirmed || staged.session !== session || staged.file.user_id !== owner.userId || staged.file.device_id !== owner.deviceId) throw new ProbeError('file.staging_required')
    return { type: 'file', receiptId: staged.upload.receiptId }
  }
  async resolveImage(fileId: string, session: string, owner: { userId: string; deviceId: string }, signal: AbortSignal): Promise<DshPromptPart> {
    this.resolve(fileId, session, owner) // The ordinary scanner/native-ready/ownership gate is never bypassed.
    const staged = this.entries.get(fileId)!
    const current = () => {
      signal.throwIfAborted()
      if (this.entries.get(fileId) !== staged || !this.available(fileId) || staged.file.user_id !== owner.userId || staged.file.device_id !== owner.deviceId) throw new ProbeError('file.staging_required')
    }
    const image = await this.client.resolveImageFile(staged.native, staged.upload.receiptId,
      { name: staged.file.name, size_bytes: staged.file.size_bytes, sha256: staged.file.sha256 }, AbortSignal.any([signal, staged.signal]), current)
    current()
    return image
  }
  drop(fileId: string): void {
    const staged = this.entries.get(fileId)
    this.entries.delete(fileId)
    if (staged) { try { this.client.releaseFile(staged.native, staged.upload.receiptId) } catch { /* Closing authority does not rely on cleanup success. */ } }
  }
  close(): void { for (const id of this.entries.keys()) this.drop(id) }
}
