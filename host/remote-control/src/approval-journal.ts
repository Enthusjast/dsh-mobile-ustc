import { createHash, randomUUID } from 'node:crypto'
import type { DatabaseSync } from 'node:sqlite'
import { ApprovalDecision, approvalBinding, approvalDecisionCurrent, type ApprovalContext } from './approval-contract.js'
import { verifyApprovalDecision, type RegisteredApprovalKey } from './approval-signature.js'
import { authorizedApproval, type ApprovalAuthorization, type ApprovalAuthorizer, type ApprovalGuardAuthorizer } from './approval-authorization.js'
import { canonicalObject, parseSigningObject } from './canonical.js'
import { encryptJournalBytes, decryptJournalBytes, type Ciphertext } from './journal-crypto.js'
import { ApprovalWireStatus, makeApprovalResultFrame, type ApprovalResultFrame } from './approval-protocol.js'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const DIGEST = /^[0-9a-f]{64}$/
const STATES = new Set(['pending', 'approved', 'denied', 'consumed', 'settled', 'expired', 'cancelled', 'invalidated', 'outcome_unknown'] as const)
export type ApprovalState = 'pending' | 'approved' | 'denied' | 'consumed' | 'settled' | 'expired' | 'cancelled' | 'invalidated' | 'outcome_unknown'
export type ApprovalOutcome = 'succeeded' | 'failed' | 'cancelled'
export class ApprovalJournalError extends Error { constructor(readonly code: string) { super(code) } }
const failure = (code: string) => new ApprovalJournalError(code)
type Row = {
  runtime_id: string; runtime_epoch: string; boot_id: string; approval_id: string; execution_id: string; session_id: string;
  binding_sha256: string; nonce_sha256: string; state: ApprovalState; expires_at: number;
  context_nonce: Uint8Array; context_ciphertext: Uint8Array; context_tag: Uint8Array;
  decision_nonce: Uint8Array | null; decision_ciphertext: Uint8Array | null; decision_tag: Uint8Array | null;
  decision_sha256: string | null; decided_at: number | null; decision_expires_at: number | null; outcome: ApprovalOutcome | null;
  remote_registered: number; report_pending: number; report_due_at: number;
}
type DecisionData = { compact: string; claims: ApprovalDecision; payload_sha256: string; key_jkt: string; authorization: ApprovalAuthorization }
export interface ApprovalStatus {
  approval_id: string; execution_id: string; runtime_epoch: string; session_id: string; binding_sha256: string;
  state: ApprovalState; expires_at: string; decision_sha256?: string; decision_expires_at?: string; outcome?: ApprovalOutcome;
}

/** Schema migration shares the command journal's already verified key/path and WAL/FULL policy. */
export function migrateApprovalJournal(database: DatabaseSync): void {
  database.exec('BEGIN IMMEDIATE')
  try {
    const version = database.prepare('PRAGMA user_version').get()?.user_version
    if (version === 1) database.exec(`
      CREATE TABLE approval_runs (
        runtime_id TEXT PRIMARY KEY, runtime_epoch TEXT NOT NULL, boot_id TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1))
      ) STRICT;
      CREATE TABLE approval_records (
        runtime_id TEXT NOT NULL, runtime_epoch TEXT NOT NULL, boot_id TEXT NOT NULL,
        approval_id TEXT NOT NULL, execution_id TEXT NOT NULL, session_id TEXT NOT NULL,
        binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64), nonce_sha256 TEXT NOT NULL CHECK(length(nonce_sha256)=64),
        state TEXT NOT NULL CHECK(state IN ('pending','approved','denied','consumed','settled','expired','cancelled','invalidated','outcome_unknown')),
        expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        context_nonce BLOB NOT NULL CHECK(length(context_nonce)=12), context_ciphertext BLOB NOT NULL, context_tag BLOB NOT NULL CHECK(length(context_tag)=16),
        decision_nonce BLOB, decision_ciphertext BLOB, decision_tag BLOB, decision_sha256 TEXT, decided_at INTEGER, decision_expires_at INTEGER,
        outcome TEXT CHECK(outcome IN ('succeeded','failed','cancelled')),
        PRIMARY KEY(runtime_id,approval_id), UNIQUE(runtime_id,execution_id), UNIQUE(runtime_id,nonce_sha256),
        CHECK((decision_nonce IS NULL AND decision_ciphertext IS NULL AND decision_tag IS NULL AND decision_sha256 IS NULL AND decided_at IS NULL AND decision_expires_at IS NULL) OR
          (decision_nonce IS NOT NULL AND length(decision_nonce)=12 AND decision_ciphertext IS NOT NULL AND decision_tag IS NOT NULL AND length(decision_tag)=16
           AND decision_sha256 IS NOT NULL AND length(decision_sha256)=64 AND decided_at IS NOT NULL AND decision_expires_at IS NOT NULL AND decision_expires_at>decided_at)),
        CHECK(state NOT IN ('approved','denied','consumed','settled','outcome_unknown') OR decision_sha256 IS NOT NULL),
        CHECK(state!='pending' OR decision_sha256 IS NULL), CHECK((state='settled')=(outcome IS NOT NULL))
      ) STRICT;
      CREATE INDEX approval_records_state ON approval_records(runtime_id,boot_id,state);
      PRAGMA user_version=2;
    `)
    else if (version !== 2 && version !== 3) throw failure('approval.schema_unsupported')
    if (version !== 3) database.exec(`
      ALTER TABLE approval_records ADD COLUMN remote_registered INTEGER NOT NULL DEFAULT 0 CHECK(remote_registered IN (0,1));
      ALTER TABLE approval_records ADD COLUMN report_pending INTEGER NOT NULL DEFAULT 0 CHECK(report_pending IN (0,1));
      ALTER TABLE approval_records ADD COLUMN report_due_at INTEGER NOT NULL DEFAULT 0 CHECK(report_due_at>=0);
      UPDATE approval_records SET remote_registered=1,report_pending=1 WHERE decision_sha256 IS NOT NULL;
      CREATE INDEX approval_records_reports ON approval_records(runtime_id,remote_registered,report_pending,report_due_at,updated_at);
      PRAGMA user_version=3;
    `)
    database.exec('COMMIT')
  } catch (error) { try { database.exec('ROLLBACK') } catch {} throw error }
}

/** Durable one-use state. It neither restores callbacks nor supplies a default authority. */
export class PersistentApprovalJournal {
  private readonly bootId = randomUUID()
  private closed = false
  private poisoned = false
  private lastClock = -Infinity
  private readonly operations = new Set<AbortController>()
  private constructor(private readonly database: DatabaseSync, private readonly key: Buffer, readonly runtimeId: string, readonly epoch: string, private readonly now: () => number) {}

  static attach(database: DatabaseSync, key: Buffer, runtimeId: string, epoch: string, now: () => number = Date.now): PersistentApprovalJournal {
    if (!UUID.test(runtimeId) || !UUID.test(epoch) || key.length !== 32 || database.prepare('PRAGMA journal_mode').get()?.journal_mode !== 'wal' || database.prepare('PRAGMA synchronous').get()?.synchronous !== 2) throw failure('approval.storage_unavailable')
    const journal = new PersistentApprovalJournal(database, key, runtimeId, epoch, now)
    journal.transaction(() => {
      const time = journal.clock()
      database.prepare(`UPDATE approval_records SET state=CASE WHEN state='consumed' THEN 'outcome_unknown' ELSE 'invalidated' END, updated_at=?,report_pending=remote_registered,report_due_at=0
        WHERE runtime_id=? AND state IN ('pending','approved','consumed')`).run(time, runtimeId)
      database.prepare(`INSERT INTO approval_runs(runtime_id,runtime_epoch,boot_id,active) VALUES(?,?,?,1)
        ON CONFLICT(runtime_id) DO UPDATE SET runtime_epoch=excluded.runtime_epoch,boot_id=excluded.boot_id,active=1`).run(runtimeId, epoch, journal.bootId)
    })
    return journal
  }

  register(value: unknown): ApprovalStatus {
    const binding = approvalBinding(value), context = binding.context
    if (context.runtime_id !== this.runtimeId || context.runtime_epoch !== this.epoch) throw failure('approval.stale')
    return this.transaction(() => {
      this.assertOwner()
      const now = this.clock()
      if (Date.parse(context.created_at) > now || Date.parse(context.expires_at) <= now) throw failure('approval.stale')
      const existing = this.find(context.approval_id)
      if (existing) {
        this.context(existing)
        if (existing.binding_sha256 !== binding.sha256) throw failure('approval.conflict')
        this.expire(existing, now)
        return this.status(existing)
      }
      if (this.database.prepare('SELECT approval_id FROM approval_records WHERE runtime_id=? AND (execution_id=? OR nonce_sha256=?)').get(this.runtimeId, context.execution_id, this.nonceHash(context.nonce))) throw failure('approval.conflict')
      const count = this.database.prepare(`SELECT COUNT(*) total, SUM(state IN ('pending','approved','consumed')) active FROM approval_records WHERE runtime_id=?`).get(this.runtimeId)
      if (typeof count?.total !== 'number' || count.total >= 100_000 || Number(count.active ?? 0) >= 64) throw failure('rate.limited')
      const metadata = { runtime_id:this.runtimeId, runtime_epoch:this.epoch, boot_id:this.bootId, approval_id:context.approval_id, execution_id:context.execution_id, binding_sha256:binding.sha256 }
      const encrypted = encryptJournalBytes(this.key, this.aad(metadata, 'context'), binding.canonical)
      this.database.prepare(`INSERT INTO approval_records(runtime_id,runtime_epoch,boot_id,approval_id,execution_id,session_id,binding_sha256,nonce_sha256,state,expires_at,created_at,updated_at,context_nonce,context_ciphertext,context_tag)
        VALUES(?,?,?,?,?,?,?,?,'pending',?,?,?,?,?,?)`).run(this.runtimeId, this.epoch, this.bootId, context.approval_id, context.execution_id, context.session_id, binding.sha256, this.nonceHash(context.nonce), Date.parse(context.expires_at), now, now, encrypted.nonce, encrypted.ciphertext, encrypted.tag)
      return this.status(this.required(context.approval_id))
    })
  }

  get(approvalId: string): { status: ApprovalStatus; context: ApprovalContext } {
    return this.transaction(() => {
      this.assertOwner()
      const row = this.required(approvalId), context = this.context(row)
      if (row.decision_sha256) this.decision(row,context)
      this.expire(row, this.clock())
      return { status:this.status(row), context }
    })
  }

  async decide(approvalId: string, compact: string, key: RegisteredApprovalKey, authorize: ApprovalAuthorizer): Promise<ApprovalStatus> {
    this.assertActive()
    if (this.operations.size >= 64) throw failure('rate.limited')
    const operation = new AbortController()
    this.operations.add(operation)
    const timeout = setTimeout(() => operation.abort(), 1500)
    let aborted!: () => void
    const cancelled = new Promise<never>((_resolve,reject) => {
      aborted = () => reject(operation.signal.reason instanceof ApprovalJournalError ? operation.signal.reason : failure('approval.authorization_unavailable'))
      operation.signal.addEventListener('abort',aborted,{once:true})
    })
    try { return await Promise.race([this.decidePending(approvalId,compact,key,authorize,operation.signal),cancelled]) }
    finally { clearTimeout(timeout); operation.signal.removeEventListener('abort',aborted); this.operations.delete(operation); operation.abort() }
  }

  private async decidePending(approvalId: string, compact: string, key: RegisteredApprovalKey, authorize: ApprovalAuthorizer, signal: AbortSignal): Promise<ApprovalStatus> {
    const initial = this.get(approvalId)
    const signingKey = structuredClone(key)
    const verified = await verifyApprovalDecision(compact, signingKey, initial.context, this.clock())
    if (signal.aborted) throw failure('approval.authorization_unavailable')
    let evidence: unknown
    try { evidence = await authorize(structuredClone(initial.context), structuredClone(verified.claims), signal) }
    catch { throw failure('approval.authorization_unavailable') }
    if (signal.aborted) throw failure('approval.authorization_unavailable')
    const result = this.transaction(() => {
      this.assertOwner()
      const row = this.required(approvalId), context = this.context(row), now = this.clock()
      if (!this.owned(row) || row.binding_sha256 !== initial.status.binding_sha256) throw failure('approval.stale')
      this.expire(row, now)
      if (!approvalDecisionCurrent(context, verified.claims, now)) return { error:failure('approval.stale') }
      const authorization = authorizedApproval(evidence, context, verified.claims, signingKey.approval_key_jkt, now)
      if (!authorization) throw failure('approval.authorization_unavailable')
      if (row.decision_sha256) {
        const previous = this.decision(row, context)
        if (row.decision_sha256 !== verified.payload_sha256) throw failure('approval.conflict')
        if (previous.authorization.grant_version !== authorization.grant_version || !['approved','denied','consumed','settled'].includes(row.state)) throw failure('approval.stale')
        return { status:this.status(row) }
      }
      if (row.state !== 'pending') return { error:failure('approval.stale') }
      const record: DecisionData = { compact, claims:verified.claims, payload_sha256:verified.payload_sha256, key_jkt:signingKey.approval_key_jkt, authorization }
      const encrypted = encryptJournalBytes(this.key, this.aad(row, 'decision'), canonicalObject(record))
      const state = verified.claims.decision === 'allow_once' ? 'approved' : 'denied'
      const updated = this.database.prepare(`UPDATE approval_records SET state=?,decision_nonce=?,decision_ciphertext=?,decision_tag=?,decision_sha256=?,decided_at=?,decision_expires_at=?,updated_at=?,remote_registered=1,report_pending=1,report_due_at=0
        WHERE runtime_id=? AND approval_id=? AND boot_id=? AND state='pending'`).run(state, encrypted.nonce, encrypted.ciphertext, encrypted.tag, verified.payload_sha256, now, Date.parse(verified.claims.expires_at), now, this.runtimeId, approvalId, this.bootId)
      if (updated.changes !== 1) throw failure('approval.stale')
      const committed = this.required(approvalId)
      if (committed.state !== state || committed.decision_sha256 !== verified.payload_sha256 || committed.remote_registered !== 1 || committed.report_pending !== 1) throw failure('approval.stale')
      return { status:this.status(committed) }
    })
    if (result.error) throw result.error
    return result.status!
  }

  /** Synchronous final-guard operation: permission is returned only after COMMIT succeeds. */
  consume(approvalId: string, actualContext: unknown, authorize: ApprovalGuardAuthorizer): ApprovalStatus {
    const actual = approvalBinding(actualContext)
    const result = this.transaction(() => {
      this.assertOwner()
      const row = this.required(approvalId), context = this.context(row), now = this.clock()
      this.expire(row, now)
      if (!this.owned(row) || row.state !== 'approved') return { error:failure('approval.stale') }
      const decision = this.decision(row, context)
      let evidence: unknown
      try { evidence = authorize(structuredClone(context), structuredClone(decision.claims)) } catch { evidence = undefined }
      const checked = this.clock()
      this.expire(row, checked)
      if (row.state !== 'approved') return { error:failure('approval.stale') }
      const lease = authorizedApproval(evidence, context, decision.claims, decision.key_jkt, checked)
      if (actual.sha256 !== row.binding_sha256 || decision.claims.decision !== 'allow_once' || Date.parse(decision.claims.expires_at) <= checked || !lease || lease.grant_version !== decision.authorization.grant_version) {
        this.setState(row, 'invalidated', checked)
        return { error:failure('approval.authorization_unavailable') }
      }
      this.setState(row, 'consumed', checked)
      return { status:this.status(row), validUntil:Math.min(Date.parse(lease.expires_at),Date.parse(decision.claims.expires_at),row.expires_at) }
    })
    if (result.error) throw result.error
    if (this.clock() >= result.validUntil!) {
      this.invalidate(approvalId)
      throw failure('approval.authorization_unavailable')
    }
    return result.status!
  }

  settle(approvalId: string, outcome: ApprovalOutcome): ApprovalStatus {
    if (!['succeeded','failed','cancelled'].includes(outcome)) throw failure('approval.invalid_outcome')
    return this.transaction(() => {
      this.assertOwner()
      const row = this.required(approvalId)
      if (!this.owned(row)) throw failure('approval.stale')
      this.context(row)
      if (row.state === 'settled') { if (row.outcome !== outcome) throw failure('approval.conflict'); return this.status(row) }
      if (row.state !== 'consumed') throw failure('approval.stale')
      const updated = this.database.prepare(`UPDATE approval_records SET state='settled',outcome=?,updated_at=?,report_pending=remote_registered,report_due_at=0 WHERE runtime_id=? AND approval_id=? AND boot_id=? AND state='consumed'`).run(outcome, this.clock(), this.runtimeId, approvalId, this.bootId)
      if (updated.changes !== 1 || this.required(approvalId).state !== 'settled') throw failure('approval.stale')
      return this.status(this.required(approvalId))
    })
  }

  invalidate(approvalId: string, reason: 'cancelled' | 'invalidated' = 'invalidated'): ApprovalStatus {
    if (reason !== 'cancelled' && reason !== 'invalidated') throw failure('approval.invalid_state')
    return this.transaction(() => {
      this.assertOwner()
      const row = this.required(approvalId)
      if (!this.owned(row)) throw failure('approval.stale')
      if (row.state === 'pending' || row.state === 'approved' || row.state === 'consumed') this.setState(row, row.state === 'consumed' ? 'outcome_unknown' : reason, this.clock())
      return this.status(row)
    })
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    for (const operation of this.operations) operation.abort(failure('approval.storage_unavailable'))
    this.transaction(() => {
      this.database.prepare(`UPDATE approval_records SET state=CASE WHEN state='consumed' THEN 'outcome_unknown' ELSE 'invalidated' END,updated_at=?,report_pending=remote_registered,report_due_at=0
        WHERE runtime_id=? AND boot_id=? AND state IN ('pending','approved','consumed')`).run(this.clock(), this.runtimeId, this.bootId)
      this.database.prepare('UPDATE approval_runs SET active=0 WHERE runtime_id=? AND boot_id=?').run(this.runtimeId, this.bootId)
    }, true)
  }

  /** Registration acknowledgement is a metadata fact, never approval authority. */
  confirmRegistration(value: unknown): void {
    const status = ApprovalWireStatus.parse(value)
    this.transaction(() => {
      this.assertOwner()
      const row = this.required(status.approval_id)
      this.context(row)
      if (status.runtime_id !== this.runtimeId || status.runtime_epoch !== row.runtime_epoch || status.session_id !== row.session_id ||
        status.execution_id !== row.execution_id || status.binding_sha256 !== row.binding_sha256 || Date.parse(status.expires_at) !== row.expires_at ||
        (row.decision_sha256 && status.decision_payload_sha256 && row.decision_sha256 !== status.decision_payload_sha256)) throw failure('approval.conflict')
      if (row.remote_registered === 1) return
      const updated = this.database.prepare(`UPDATE approval_records SET remote_registered=1,report_pending=CASE WHEN state='pending' THEN report_pending ELSE 1 END,report_due_at=0
        WHERE runtime_id=? AND approval_id=? AND remote_registered=0`).run(this.runtimeId,row.approval_id)
      if (updated.changes !== 1 || this.required(row.approval_id).remote_registered !== 1) throw failure('approval.stale')
    })
  }

  /** Reserve bounded metadata reports; retries use the same content-derived ID. */
  takeReports(limit = 16, retryAfterMs = 5000): ApprovalResultFrame[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 64 || !Number.isSafeInteger(retryAfterMs) || retryAfterMs < 100 || retryAfterMs > 60_000) throw failure('approval.invalid_report')
    return this.transaction(() => {
      this.assertOwner()
      const now = this.clock()
      const rows = this.database.prepare(`SELECT * FROM approval_records WHERE runtime_id=? AND remote_registered=1 AND report_pending=1 AND state!='pending' AND report_due_at<=?
        ORDER BY report_due_at,updated_at,approval_id LIMIT ?`).all(this.runtimeId,now,limit) as Row[]
      return rows.map(row => {
        const context = this.context(row)
        if (row.decision_sha256) this.decision(row,context)
        this.expire(row,now)
        const report = this.report(row)
        const updated = this.database.prepare(`UPDATE approval_records SET report_due_at=? WHERE runtime_id=? AND approval_id=? AND report_pending=1 AND state=?`).run(now+retryAfterMs,this.runtimeId,row.approval_id,row.state)
        if (updated.changes !== 1) throw failure('approval.stale')
        return report
      })
    })
  }

  acknowledgeReport(approvalId: string, payloadSHA256: string): boolean {
    if (!DIGEST.test(payloadSHA256)) throw failure('approval.invalid_report')
    return this.transaction(() => {
      this.assertOwner()
      const row = this.required(approvalId)
      const context = this.context(row)
      if (row.decision_sha256) this.decision(row,context)
      if (row.state === 'pending' || !row.remote_registered || this.report(row).payload_sha256 !== payloadSHA256) return false
      if (!row.report_pending) return true
      const updated = this.database.prepare(`UPDATE approval_records SET report_pending=0,report_due_at=0 WHERE runtime_id=? AND approval_id=? AND state=? AND report_pending=1`).run(this.runtimeId,approvalId,row.state)
      return updated.changes === 1 && this.required(approvalId).report_pending === 0
    })
  }

  /** A new connection may retry receipts immediately, without reviving execution. */
  retryReports(): void {
    this.transaction(() => { this.assertOwner(); this.database.prepare('UPDATE approval_records SET report_due_at=0 WHERE runtime_id=? AND report_pending=1').run(this.runtimeId) })
  }

  private clock(): number {
    const now = this.now()
    if (!Number.isSafeInteger(now) || now < this.lastClock) throw failure('approval.clock_unavailable')
    this.lastClock = now
    return now
  }
  private assertOwner(): void {
    this.assertActive()
    const owner = this.database.prepare('SELECT runtime_epoch,boot_id,active FROM approval_runs WHERE runtime_id=?').get(this.runtimeId)
    if (owner?.runtime_epoch !== this.epoch || owner.boot_id !== this.bootId || owner.active !== 1) throw failure('approval.stale')
  }
  private assertActive(): void { if (this.closed || this.poisoned || !this.database.isOpen) throw failure('approval.storage_unavailable') }
  private owned(row: Row): boolean { return row.boot_id === this.bootId && row.runtime_epoch === this.epoch }
  private find(id: string): Row | undefined {
    if (!UUID.test(id)) throw failure('approval.stale')
    return this.database.prepare('SELECT * FROM approval_records WHERE runtime_id=? AND approval_id=?').get(this.runtimeId, id) as Row | undefined
  }
  private required(id: string): Row { const row = this.find(id); if (!row) throw failure('approval.stale'); return row }
  private nonceHash(nonce: string): string { return createHash('sha256').update(Buffer.from(nonce, 'base64url')).digest('hex') }
  private aad(row: Pick<Row,'runtime_id'|'runtime_epoch'|'boot_id'|'approval_id'|'execution_id'|'binding_sha256'>, kind: string): Uint8Array {
    return Buffer.from(`dsh-approval-journal/v1\0${row.runtime_id}\0${row.runtime_epoch}\0${row.boot_id}\0${row.approval_id}\0${row.execution_id}\0${row.binding_sha256}\0${kind}`)
  }
  private ciphertext(row: Row, kind: 'context' | 'decision'): Ciphertext {
    const nonce = row[`${kind}_nonce`], ciphertext = row[`${kind}_ciphertext`], tag = row[`${kind}_tag`]
    if (!nonce || !ciphertext || !tag) throw failure('journal.integrity_failed')
    return { nonce:Buffer.from(nonce), ciphertext:Buffer.from(ciphertext), tag:Buffer.from(tag) }
  }
  private context(row: Row): ApprovalContext {
    const clear = decryptJournalBytes(this.key, this.aad(row, 'context'), this.ciphertext(row, 'context'))
    try {
      const raw = parseSigningObject(clear), binding = approvalBinding(raw)
      if (binding.sha256 !== row.binding_sha256 || binding.context.runtime_id !== row.runtime_id || binding.context.runtime_epoch !== row.runtime_epoch || binding.context.approval_id !== row.approval_id || binding.context.execution_id !== row.execution_id ||
        binding.context.session_id !== row.session_id || this.nonceHash(binding.context.nonce) !== row.nonce_sha256 || Date.parse(binding.context.expires_at) !== row.expires_at) throw failure('journal.integrity_failed')
      return raw as ApprovalContext
    } finally { clear.fill(0) }
  }
  private decision(row: Row, context: ApprovalContext): DecisionData {
    const clear = decryptJournalBytes(this.key, this.aad(row, 'decision'), this.ciphertext(row, 'decision'))
    try {
      const data = parseSigningObject(clear) as unknown as DecisionData
      const claims = ApprovalDecision.parse(data.claims), canonical = canonicalObject(claims)
      const hash = createHash('sha256').update(canonical).digest('hex')
      if (!DIGEST.test(data.payload_sha256) || hash !== row.decision_sha256 || hash !== data.payload_sha256 || claims.binding_sha256 !== row.binding_sha256 || claims.approval_id !== context.approval_id ||
        Date.parse(claims.expires_at) !== row.decision_expires_at || (row.state==='denied' ? claims.decision!=='reject' : claims.decision!=='allow_once') ||
        !authorizedApproval(data.authorization, context, claims, data.key_jkt, row.decided_at!)) throw failure('journal.integrity_failed')
      return data
    } finally { clear.fill(0) }
  }
  private expire(row: Row, now: number): void {
    const deadline=row.state==='approved'?Math.min(row.expires_at,row.decision_expires_at??row.expires_at):row.expires_at
    if ((row.state === 'pending' || row.state === 'approved') && deadline <= now) this.setState(row, 'expired', now)
  }
  private setState(row: Row, state: ApprovalState, now: number): void {
    const updated = this.database.prepare('UPDATE approval_records SET state=?,updated_at=?,report_pending=remote_registered,report_due_at=0 WHERE runtime_id=? AND approval_id=? AND boot_id=? AND state=?').run(state, now, this.runtimeId, row.approval_id, row.boot_id, row.state)
    if (updated.changes !== 1 || this.required(row.approval_id).state !== state) throw failure('approval.stale')
    row.state = state
  }
  private report(row: Row): ApprovalResultFrame {
    if (row.state === 'pending') throw failure('approval.invalid_report')
    return makeApprovalResultFrame({ type:'approval.result',runtime_id:this.runtimeId,runtime_epoch:row.runtime_epoch,session_id:row.session_id,
      payload:{approval_id:row.approval_id,execution_id:row.execution_id,binding_sha256:row.binding_sha256,state:row.state,
        ...(row.decision_sha256?{decision_payload_sha256:row.decision_sha256}:{}),...(row.outcome?{execution_outcome:row.outcome}:{})} })
  }
  private status(row: Row): ApprovalStatus {
    if (!STATES.has(row.state) || !DIGEST.test(row.binding_sha256)) throw failure('journal.integrity_failed')
    return { approval_id:row.approval_id, execution_id:row.execution_id, runtime_epoch:row.runtime_epoch, session_id:row.session_id, binding_sha256:row.binding_sha256,
      state:row.state, expires_at:new Date(row.expires_at).toISOString(), ...(row.decision_sha256 ? { decision_sha256:row.decision_sha256 } : {}),
      ...(row.decision_expires_at!==null?{decision_expires_at:new Date(row.decision_expires_at).toISOString()}:{}), ...(row.outcome ? { outcome:row.outcome } : {}) }
  }
  private transaction<T>(operation: () => T, closing = false): T {
    if ((!closing && (this.closed || this.poisoned)) || !this.database.isOpen) throw failure('approval.storage_unavailable')
    let began = false
    try {
      this.database.exec('BEGIN IMMEDIATE'); began = true
      const value = operation()
      this.database.exec('COMMIT')
      return value
    } catch (error) {
      if (began) { try { this.database.exec('ROLLBACK') } catch {} }
      if (error instanceof ApprovalJournalError) throw error
      this.poisoned = true
      for (const operation of this.operations) operation.abort(failure('approval.storage_unavailable'))
      throw failure('approval.storage_unavailable')
    }
  }
}
