import { randomUUID } from 'node:crypto'
import type { HostHandshakeSigner } from './relay-client.js'
import { FileFrame, fileReadProof, type FileOffer } from './file-protocol.js'
import type { NativeFileRegistry } from './file-registry.js'

export interface FileTransportBinding {
  installationId: string; connectionId: string; origin: string; signer: HostHandshakeSigner
  signal: AbortSignal; send(frame: unknown): Promise<void>; fail(): void
}
export interface HostFilePeer { handle(value: unknown): Promise<boolean>; close(): void }
interface Transfer { offer: FileOffer; session: string; abort: AbortController; until: number; expires: number; stage: 'queued' | 'reading' | 'reporting' | 'staged' }
interface Pending { type: string; ids: string[]; until: number; file?: string; session?: string }

export class RelayFiles {
  private readonly transfers = new Map<string, Transfer>()
  private readonly timer: NodeJS.Timeout
  private reading = 0
  private closed = false
  private readonly pending = new Map<string, Pending>()
  private renewal: string | undefined
  private lastRenewal = 0
  private readonly onAbort = () => this.close()

  constructor(private readonly registry: NativeFileRegistry, private readonly binding: FileTransportBinding) {
    binding.signal.throwIfAborted()
    this.timer = setInterval(() => this.tick(), 250); this.timer.unref()
    binding.signal.addEventListener('abort', this.onAbort, { once: true })
  }
  async handle(value: unknown): Promise<boolean> {
    if (value === null || typeof value !== 'object' || !('type' in value) || typeof value.type !== 'string') return false
    if (value.type === 'error' && 'request_id' in value && typeof value.request_id === 'string') {
      const pending = this.pending.get(value.request_id)
      if (!pending) return false
      this.settle(value.request_id)
      if (pending.type !== 'file.release') for (const id of pending.ids) { const transfer = this.transfers.get(id); if (transfer) this.end(id, transfer) }
      return true
    }
    if (!value.type.startsWith('file.')) return false
    if (this.closed) return true
    const frame = FileFrame.parse(value)
    if (frame.runtime_id !== this.registry.client.runtimeId || frame.runtime_epoch !== this.registry.epoch) throw new Error('file handoff runtime mismatch')
    if (frame.type === 'file.offer') {
      if (this.transfers.has(frame.payload.handoff_id)) return true
      for (const [id, previous] of this.transfers) if (previous.offer.file_id === frame.payload.file_id) this.end(id, previous)
      if (this.transfers.size >= 32) throw new Error('file transfer queue limit')
      const transfer: Transfer = { offer: frame.payload, session: frame.session_id, abort: new AbortController(), until: Date.parse(frame.payload.lease_until), expires: Date.parse(frame.payload.expires_at), stage: 'queued' }
      if (!this.valid(transfer)) return true
      this.transfers.set(frame.payload.handoff_id, transfer)
      this.pump()
    } else if (frame.type === 'file.renewed') {
      const pending = this.pending.get(frame.request_id)
      if (!pending || pending.type !== 'file.renew') throw new Error('unexpected file renewal')
      const seen = new Set<string>()
      for (const lease of frame.payload.leases) {
        if (seen.has(lease.handoff_id) || !pending.ids.includes(lease.handoff_id)) throw new Error('unexpected file lease')
        seen.add(lease.handoff_id)
        const transfer = this.transfers.get(lease.handoff_id)
        if (transfer) {
          if (Date.parse(lease.expires_at) !== transfer.expires || Date.parse(lease.lease_until) > transfer.expires) throw new Error('file expiry changed')
          transfer.until = Date.parse(lease.lease_until)
        }
      }
      this.settle(frame.request_id)
      for (const id of pending.ids) if (!seen.has(id)) { const transfer = this.transfers.get(id); if (transfer) this.end(id, transfer) }
      this.pump()
    } else if (frame.type === 'file.staged.ack' || frame.type === 'file.release.ack') {
      const pending = this.pending.get(frame.request_id)
      if (!pending || `${pending.type}.ack` !== frame.type || pending.ids[0] !== frame.payload.handoff_id
        || pending.file !== frame.payload.file_id || pending.session !== frame.session_id) throw new Error('unexpected file acknowledgement')
      const transfer = this.transfers.get(frame.payload.handoff_id)
      if (transfer && (transfer.session !== frame.session_id || transfer.offer.file_id !== frame.payload.file_id)) throw new Error('file acknowledgement route changed')
      this.settle(frame.request_id)
      if (frame.type === 'file.staged.ack' && transfer) {
        if (transfer.stage !== 'reporting' || !this.valid(transfer)) { this.end(frame.payload.handoff_id, transfer); return true }
        transfer.stage = 'staged'
        this.registry.confirm(transfer.offer.file_id)
      }
    } else throw new Error('unsupported file frame direction')
    return true
  }
  private valid(transfer: Transfer): boolean { return !this.closed && !this.binding.signal.aborted && !transfer.abort.signal.aborted && Date.now() < transfer.until - 100 && Date.now() < transfer.expires - 100 }
  private async send(type: string, transfer: Transfer | undefined, payload: unknown): Promise<void> {
    if (this.pending.size >= 96) throw new Error('file acknowledgement queue limit')
    const request = randomUUID()
    const ids = transfer ? [transfer.offer.handoff_id] : (payload as { handoff_ids: string[] }).handoff_ids
    this.pending.set(request, { type, ids, until: Date.now() + 2500, ...(transfer ? { file: transfer.offer.file_id, session: transfer.session } : {}) })
    if (type === 'file.renew') this.renewal = request
    try {
      await this.binding.send({ v: 1, type, request_id: request, runtime_id: this.registry.client.runtimeId, runtime_epoch: this.registry.epoch,
        ...(transfer ? { session_id: transfer.session } : {}), payload })
    } catch (error) { this.settle(request); throw error }
  }
  private settle(request: string): void { this.pending.delete(request); if (this.renewal === request) this.renewal = undefined }
  private tick(): void {
    if (this.closed) return
    for (const [request, pending] of this.pending) if (Date.now() >= pending.until) {
      this.settle(request)
      if (pending.type !== 'file.release') for (const id of pending.ids) { const transfer = this.transfers.get(id); if (transfer) this.end(id, transfer) }
    }
    for (const [id, transfer] of this.transfers) if (!this.valid(transfer) || (transfer.stage === 'staged' && !this.registry.available(transfer.offer.file_id))) this.end(id, transfer)
    if (this.transfers.size && !this.renewal && Date.now() - this.lastRenewal >= 1000) {
      this.lastRenewal = Date.now()
      void this.send('file.renew', undefined, { handoff_ids: [...this.transfers.keys()] }).catch(() => this.binding.fail())
    }
    this.pump()
  }
  private pump(): void {
    for (const transfer of this.transfers.values()) {
      if (this.reading >= 2) break
      if (transfer.stage !== 'queued' || !this.valid(transfer)) continue
      transfer.stage = 'reading'; this.reading++
      void this.receive(transfer).catch(() => this.end(transfer.offer.handoff_id, transfer)).finally(() => { this.reading--; this.pump() })
    }
  }
  private async receive(transfer: Transfer): Promise<void> {
    const signal = AbortSignal.any([transfer.abort.signal, this.binding.signal])
    const uri = new URL(`/v1/host-files/${transfer.offer.handoff_id}/content`, this.binding.origin).href
    const proof = await fileReadProof(this.binding.signer, { installationId: this.binding.installationId, runtimeId: this.registry.client.runtimeId,
      epoch: this.registry.epoch, connectionId: this.binding.connectionId, handoffId: transfer.offer.handoff_id, fileId: transfer.offer.file_id, token: transfer.offer.download_token, uri })
    signal.throwIfAborted()
    const response = await fetch(uri, { method: 'GET', headers: { authorization: `DSH-File ${transfer.offer.download_token}`, 'x-dsh-file-proof': proof, 'accept-encoding': 'identity' },
      signal, redirect: 'error', credentials: 'omit', cache: 'no-store' })
    transfer.offer = { ...transfer.offer, download_token: '' }
    if (response.status !== 200 || !response.body || response.headers.get('content-type')?.split(';')[0] !== 'application/octet-stream'
      || response.headers.get('content-length') !== String(transfer.offer.size_bytes)
      || ![null, 'identity'].includes(response.headers.get('content-encoding'))) { await response.body?.cancel(); throw new Error('file download refused') }
    const reader = response.body.getReader()
    const chunks = async function* () {
      try { for (;;) { const next = await reader.read(); if (next.done) return
        for (let at = 0; at < next.value.byteLength; at += 65536) yield next.value.subarray(at, at + 65536)
      } } finally { await reader.cancel().catch(() => {}); reader.releaseLock() }
    }
    const name = await this.registry.stage(transfer.session, transfer.offer, chunks(), signal, () => this.valid(transfer))
    if (!this.valid(transfer)) throw new Error('file authority expired')
    transfer.stage = 'reporting'
    await this.send('file.staged', transfer, { handoff_id: transfer.offer.handoff_id, file_id: transfer.offer.file_id, name, size_bytes: transfer.offer.size_bytes, sha256: transfer.offer.sha256 })
    transfer.offer = { ...transfer.offer, download_token: '' }
  }
  private end(id: string, transfer: Transfer): void {
    if (!this.transfers.delete(id)) return
    transfer.abort.abort(); this.registry.drop(transfer.offer.file_id)
    if (!this.closed && !this.binding.signal.aborted) void this.send('file.release', transfer, { handoff_id: id, file_id: transfer.offer.file_id }).catch(() => this.binding.fail())
  }
  close(): void {
    if (this.closed) return
    this.closed = true; clearInterval(this.timer); this.binding.signal.removeEventListener('abort', this.onAbort)
    for (const [id, transfer] of this.transfers) this.end(id, transfer)
    this.pending.clear()
  }
}
