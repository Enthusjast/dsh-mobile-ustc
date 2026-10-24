import { setTimeout as delay } from 'node:timers/promises'
import { randomUUID } from 'node:crypto'
import { ApprovalWireFrame, encodeApprovalContextFrames, type ApprovalResultFrame, type ApprovalWireStatus } from './approval-protocol.js'
import { ApprovalJournalError } from './approval-journal.js'
import { approvalBinding, type ApprovalContext } from './approval-contract.js'
import type { NativeApprovalSession, SignedApprovals } from './signed-approvals.js'

export interface ApprovalTransportBinding {
  installationId: string
  connectionId: string
  signal: AbortSignal
  send(frame: unknown): Promise<void>
  publishCatalog(nativeSessionId: string, signal: AbortSignal): Promise<void>
  fail(): void
}
export interface HostApprovalPeer { handle(value: unknown): Promise<boolean>; close(): void }
export type HostApprovalPeerFactory = (binding: ApprovalTransportBinding) => HostApprovalPeer
interface Registration { context: ApprovalContext; resolve(): void; reject(error: Error): void }

function acknowledgedFact(report: ApprovalResultFrame, status: ApprovalWireStatus): boolean {
  const fact = report.payload
  if (fact.decision_payload_sha256 && status.decision_payload_sha256 !== fact.decision_payload_sha256) return false
  if (fact.state === 'settled') return status.host_state === 'settled' && status.execution_outcome === fact.execution_outcome
  if (status.host_state === 'settled') return ['approved', 'consumed', 'outcome_unknown'].includes(fact.state)
  if (fact.state === 'approved') return ['approved', 'consumed', 'outcome_unknown'].includes(status.host_state ?? '') || status.state === 'outcome_unknown'
  if (fact.state === 'consumed') return status.host_state === 'consumed' || status.host_state === 'outcome_unknown'
  return status.host_state === fact.state
}

async function cancelled<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  let abort!: () => void
  const interrupted = new Promise<never>((_resolve, reject) => { abort = () => reject(new Error('approval connection closed')); signal.addEventListener('abort', abort, { once: true }) })
  try { return await Promise.race([work, interrupted]) } finally { signal.removeEventListener('abort', abort) }
}

/** One negotiated connection: finite writes, registration waits and durable fact delivery. */
export class RelayApprovals implements HostApprovalPeer {
  private readonly lifetime = new AbortController()
  private readonly session: NativeApprovalSession
  private readonly registrations = new Map<string, Registration>()
  private readonly reports = new Map<string, { frame: ApprovalResultFrame; sent: number }>()
  private readonly timer: NodeJS.Timeout
  private readonly unwatch: () => void
  private readonly onAbort = () => this.close()
  private tail: Promise<void> = Promise.resolve()
  private queued = 0
  private bytes = 0
  private lastWrite = 0
  private closed = false
  private flushing = false
  private dirty = false

  constructor(private readonly owner: SignedApprovals, private readonly binding: ApprovalTransportBinding) {
    binding.signal.throwIfAborted()
    owner.journal.retryReports()
    this.session = owner.attach({ ...owner.identity, installation_id: binding.installationId, connection_id: binding.connectionId }, (context, signal) => this.publish(context, signal))
    this.unwatch = owner.watchReports(() => this.flush())
    this.timer = setInterval(() => this.flush(), 250); this.timer.unref()
    binding.signal.addEventListener('abort', this.onAbort, { once: true })
    this.flush()
  }

  private send(frame: unknown): Promise<void> {
    const size = Buffer.byteLength(JSON.stringify(frame))
    if (this.closed || size > 64 * 1024 || this.queued >= 32 || this.bytes + size > 512 * 1024) return Promise.reject(new Error('approval write queue unavailable'))
    this.queued++; this.bytes += size
    const write = this.tail.catch(() => {}).then(async () => {
      const wait = Math.max(0, this.lastWrite + 75 - Date.now())
      if (wait) await delay(wait, undefined, { signal: this.lifetime.signal })
      this.lifetime.signal.throwIfAborted()
      this.lastWrite = Date.now()
      await cancelled(this.binding.send(frame), this.lifetime.signal)
    })
    this.tail = write
    return write.finally(() => { this.queued--; this.bytes -= size })
  }

  private async publish(context: ApprovalContext, signal: AbortSignal): Promise<void> {
    const lifetime = AbortSignal.any([this.lifetime.signal, signal])
    lifetime.throwIfAborted()
    await cancelled(this.binding.publishCatalog(context.dsh_session_id, lifetime), lifetime)
    lifetime.throwIfAborted()
    if (this.registrations.size >= 64) throw new Error('approval registration limit')
    const id = randomUUID()
    let timer!: NodeJS.Timeout
    const acknowledged = new Promise<void>((resolve, reject) => {
      const abort = () => entry.reject(new Error('approval registration cancelled'))
      const cleanup = () => { clearTimeout(timer); lifetime.removeEventListener('abort', abort); this.registrations.delete(id) }
      const entry: Registration = { context, resolve: () => { cleanup(); resolve() }, reject: error => { cleanup(); reject(error) } }
      this.registrations.set(id, entry)
      lifetime.addEventListener('abort', abort, { once: true })
      timer = setTimeout(() => entry.reject(new Error('approval registration timed out')), 5000); timer.unref()
      if (lifetime.aborted) abort()
    })
    void acknowledged.catch(() => {})
    try { for (const frame of encodeApprovalContextFrames('approval.request', id, context)) await this.send(frame); await acknowledged }
    finally { this.registrations.get(id)?.reject(new Error('approval publication ended')) }
  }

  async handle(value: unknown): Promise<boolean> {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
    const candidate = value as Record<string, unknown>
    if (candidate.type === 'error' && typeof candidate.request_id === 'string') {
      const pending = this.registrations.get(candidate.request_id), report = this.reports.get(candidate.request_id)
      if (!pending && !report) return false
      const code = String((candidate.payload as { code?: unknown } | undefined)?.code ?? 'internal')
      pending?.reject(new Error('approval registration refused'))
      this.reports.delete(candidate.request_id)
      if (code === 'internal' || code === 'runtime.changed') throw new Error('approval authority unavailable')
      return true
    }
    if (typeof candidate.type !== 'string' || !candidate.type.startsWith('approval.')) return false
    if (this.closed) throw new Error('approval connection closed')
    const frame = ApprovalWireFrame.parse(value)
    if (frame.runtime_id !== this.owner.runtimeId) throw new Error('approval runtime mismatch')
    if (frame.type === 'approval.registered') {
      const pending = this.registrations.get(frame.request_id)
      if (!pending) return true
      const context = pending.context, status = frame.payload.status
      if (frame.runtime_epoch !== context.runtime_epoch || frame.session_id !== context.session_id || status.approval_id !== context.approval_id) throw new Error('approval registration route mismatch')
      this.owner.journal.confirmRegistration(status); pending.resolve(); this.flush(); return true
    }
    if (frame.type === 'approval.result.ack') {
      const pending = this.reports.get(frame.request_id)
      if (!pending) return true
      const report = pending.frame, status = frame.payload.status
      if (frame.runtime_epoch !== report.runtime_epoch || frame.session_id !== report.session_id || frame.payload_sha256 !== report.payload_sha256 ||
        status.approval_id !== report.payload.approval_id || status.runtime_id !== report.runtime_id || status.runtime_epoch !== report.runtime_epoch || status.session_id !== report.session_id ||
        status.execution_id !== report.payload.execution_id || status.binding_sha256 !== report.payload.binding_sha256 || !acknowledgedFact(report,status)) throw new Error('approval result acknowledgement mismatch')
      this.owner.journal.acknowledgeReport(report.payload.approval_id, report.payload_sha256)
      this.reports.delete(frame.request_id); this.flush(); return true
    }
    if (frame.type !== 'approval.details.get' && frame.type !== 'approval.decision') throw new Error('unsupported approval frame direction')
    if (frame.runtime_epoch !== this.owner.epoch) throw new Error('approval epoch mismatch')
    if (frame.type === 'approval.details.get') {
      try {
        const context = this.session.details(frame.payload.approval_id)
        if (context.session_id !== frame.session_id) throw new Error('approval session mismatch')
        for (const reply of encodeApprovalContextFrames('approval.details', frame.request_id, context)) await this.send(reply)
      } catch (error) {
        if (error instanceof ApprovalJournalError && error.code === 'approval.storage_unavailable') throw error
        await this.send({ ...frame, type: 'approval.error', payload: { approval_id: frame.payload.approval_id, code: 'approval.stale' } })
      }
    } else {
      try {
        const context = this.owner.journal.get(frame.payload.approval_id).context
        if (context.session_id !== frame.session_id || context.runtime_epoch !== frame.runtime_epoch || approvalBinding(context).context.runtime_id !== frame.runtime_id) throw new Error('approval decision route mismatch')
        await this.session.decide(frame.payload.approval_id, frame.payload.decision_jws, frame.payload.authorization_jws)
      } catch (error) {
        if (error instanceof ApprovalJournalError && error.code === 'approval.storage_unavailable') throw error
        await this.send({ ...frame, type: 'approval.error', payload: { approval_id: frame.payload.approval_id, code: 'approval.stale' } })
      }
    }
    this.flush()
    return true
  }

  private flush(): void {
    if (this.closed) return
    this.dirty = true
    if (this.flushing) return
    this.flushing = true
    void (async () => {
      try {
        while (this.dirty && !this.closed) {
          this.dirty = false
          const now = Date.now()
          for (const [id, pending] of this.reports) if (now - pending.sent >= 5000) this.reports.delete(id)
          if (this.reports.size >= 64) break
          const frames = this.owner.journal.takeReports(Math.min(4, 64 - this.reports.size), 5000)
          for (const frame of frames) {
            if (this.closed) break
            this.reports.set(frame.request_id, { frame, sent: Date.now() })
            await this.send(frame)
          }
          if (frames.length === 4) this.dirty = true
        }
      } catch { this.close(); this.binding.fail() }
      finally { this.flushing = false; if (this.dirty && !this.closed) this.flush() }
    })()
  }

  close(): void {
    if (this.closed) return
    this.closed = true; clearInterval(this.timer); this.unwatch(); this.lifetime.abort(); this.session.close()
    this.binding.signal.removeEventListener('abort', this.onAbort)
    for (const pending of this.registrations.values()) pending.reject(new Error('approval connection closed'))
    this.registrations.clear(); this.reports.clear()
  }
}
