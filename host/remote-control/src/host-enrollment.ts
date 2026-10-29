import { randomBytes, randomUUID } from 'node:crypto'
import { inspect } from 'node:util'
import { z } from 'zod'
import { parseSigningObject } from './canonical.js'
import { enrollmentAbortable, enrollmentError, HostEnrollmentError, HostEnrollmentTransport, type HostEnrollmentTransportOptions } from './host-enrollment-transport.js'
import { guards } from './host-process-guards.js'

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const secret = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value)
const ref = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/)
const wellFormed = (value: string) => Buffer.from(value, 'utf8').toString('utf8') === value
const version = z.string().refine(value => value === value.trim() && wellFormed(value) && Buffer.byteLength(value) <= 128 && !/\p{Cc}/u.test(value))
const inputSchema = z.strictObject({
  organizationId: uuid, hostId: uuid.optional(), alias: z.string().refine(value => value === value.trim() && wellFormed(value) && Array.from(value).length >= 1 && Array.from(value).length <= 160 && !/\p{Cc}/u.test(value)),
  profileRef: ref, dshVersion: version.default(''), applicationVersion: version.default(''), pluginVersion: version.default(''),
  protocolVersion: z.number().int().min(1).max(32), workspaceRefs: z.array(ref).max(64).refine(values => new Set(values).size === values.length),
})
const recoverySchema = z.strictObject({ version: z.literal(1), binding: z.string().regex(/^[0-9a-f]{64}$/), requestId: uuid,
  code: secret, preparedAt: z.number().int().safe().nonnegative(), input: inputSchema })
const workspace = z.strictObject({ reference: ref, workspace_id: uuid })
const state = z.enum(['pending', 'user_confirmed', 'approved', 'denied', 'expired', 'cancelled'])
const created = z.strictObject({ ok: z.literal(true), data: z.strictObject({ enrollment_id: uuid, request_id: uuid, host_id: uuid,
  installation_id: uuid, runtime_id: uuid, profile_ref: ref, state, expires_at: z.string().datetime({ offset: true }),
  workspaces: z.array(workspace).max(64) }) })
const record = z.strictObject({ enrollment_id: uuid, request_id: uuid, organization_id: uuid, organization_name: z.string().max(2048),
  host_id: uuid, host_alias: z.string().max(2048), installation_id: uuid, installation_key_jkt: secret, runtime_id: uuid,
  profile_ref: ref, dsh_version: version.optional(), application_version: version.optional(), plugin_version: version.optional(),
  protocol_version: z.number().int().min(1).max(32), state, expires_at: z.string().datetime({ offset: true }),
  host_confirmed: z.boolean(), user_confirmed: z.boolean(), user_confirmed_by_me: z.boolean(), workspaces: z.array(workspace).max(64) })
const review = z.strictObject({ ok: z.literal(true), data: z.strictObject({ enrollment: record,
  confirmed_user: z.strictObject({ user_id: uuid, issuer: z.string().min(1).max(2048), subject: z.string().min(1).max(2048), eligible: z.boolean() }).nullable() }) })
const confirmation = z.strictObject({ ok: z.literal(true), data: z.strictObject({ enrollment_id: uuid, host_id: uuid, runtime_id: uuid,
  state: z.enum(['pending', 'user_confirmed', 'approved']), expires_at: z.string().datetime({ offset: true }), host_confirmed: z.boolean(), user_confirmed: z.boolean() }) })
export const hostEnrollmentBindingRecord = z.strictObject({ version: z.literal(1), purpose: z.literal('dsh-host-enrollment-binding-v1'),
  binding: z.string().regex(/^[0-9a-f]{64}$/), request_id: uuid, enrollment_id: uuid, organization_id: uuid,
  host_id: uuid, installation_id: uuid, installation_key_jkt: secret, runtime_id: uuid,
  profile_ref: ref, expires_at: z.string().datetime({ offset: true }), workspaces: z.array(workspace).max(64) })

export interface HostEnrollmentRequest {
  organizationId: string
  hostId?: string
  alias: string
  profileRef: string
  dshVersion?: string
  applicationVersion?: string
  pluginVersion?: string
  protocolVersion: number
  workspaceRefs: string[]
}
export type HostEnrollmentOptions = HostEnrollmentTransportOptions
export type HostEnrollmentReview = z.infer<typeof review>['data']
export type HostEnrollmentApprovalReview = {
  readonly enrollment: Readonly<Omit<HostEnrollmentReview['enrollment'], 'workspaces'>> & {
    readonly workspaces: readonly Readonly<HostEnrollmentReview['enrollment']['workspaces'][number]>[]
  }
  readonly confirmed_user: Readonly<NonNullable<HostEnrollmentReview['confirmed_user']>> | null
}
export type HostEnrollmentConfirmation = z.infer<typeof confirmation>['data']
export interface HostEnrollmentBinding {
  readonly organizationId: string
  readonly hostId: string
  readonly installationId: string
  readonly installationKeyThumbprint: string
  readonly runtimeId: string
  readonly profileRef: string
  readonly workspaces: readonly Readonly<{ reference: string; workspaceId: string }>[]
}
export type HostEnrollmentBindingRecord = z.infer<typeof hostEnrollmentBindingRecord>
type IntentState = z.infer<typeof recoverySchema>
type ReceiptData = z.infer<typeof created>['data']
export type HostEnrollmentDetails = Readonly<Omit<ReceiptData, 'workspaces'>> & { readonly workspaces: readonly Readonly<ReceiptData['workspaces'][number]>[] }
const attemptStates = new WeakMap<HostEnrollmentIntent, IntentState>()
const attemptLifetimes = new WeakMap<HostEnrollmentIntent, AbortController>()
const attemptOwners = new WeakMap<HostEnrollmentIntent, AbortSignal>()
const receiptStates = new WeakMap<HostEnrollmentReceipt, { attempt: HostEnrollmentIntent; data: ReceiptData }>()
const activeApprovals = guards.enrollmentApprovals
const clientBindings = new WeakMap<HostEnrollmentClient, string>()
const clientTransports = new WeakMap<HostEnrollmentClient, HostEnrollmentTransport>()

/** @internal A recovery store binds its encryption to this exact account and installation. */
export function enrollmentRecoveryBinding(client: HostEnrollmentClient): string {
  const binding = clientBindings.get(client)
  if (!binding) throw enrollmentError('invalid_config')
  if (client.signal.aborted) throw enrollmentError('cancelled')
  return binding
}

/** @internal Capture only metadata from an attempt and a verified create receipt. */
export function captureEnrollmentBinding(client: HostEnrollmentClient, attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt): HostEnrollmentBindingRecord {
  const binding = enrollmentRecoveryBinding(client), transport = clientTransports.get(client)
  const value = currentAttempt(attempt, binding), saved = receiptStates.get(receipt)
  if (!transport || !saved || saved.attempt !== attempt) throw enrollmentError('invalid_config')
  return hostEnrollmentBindingRecord.parse({ version: 1, purpose: 'dsh-host-enrollment-binding-v1', binding,
    request_id: value.requestId, enrollment_id: saved.data.enrollment_id, organization_id: value.input.organizationId,
    host_id: saved.data.host_id, installation_id: saved.data.installation_id, installation_key_jkt: transport.thumbprint,
    runtime_id: saved.data.runtime_id, profile_ref: value.input.profileRef, expires_at: saved.data.expires_at,
    workspaces: [...saved.data.workspaces].sort((a, b) => a.reference < b.reference ? -1 : a.reference > b.reference ? 1 : 0) })
}

/** @internal Recheck persisted metadata against the live host-only review route. */
export async function verifyEnrollmentBinding(client: HostEnrollmentClient, source: HostEnrollmentBindingRecord, signal: AbortSignal): Promise<HostEnrollmentBinding> {
  const binding = enrollmentRecoveryBinding(client), transport = clientTransports.get(client)
  if (!transport) throw enrollmentError('invalid_config')
  let expected: HostEnrollmentBindingRecord
  try { expected = hostEnrollmentBindingRecord.parse(source) } catch { throw enrollmentError('invalid_config') }
  if (expected.binding !== binding || expected.installation_key_jkt !== transport.thumbprint || new Set(expected.workspaces.map(item => item.reference)).size !== expected.workspaces.length ||
      !sameReferences([...expected.workspaces.map(item => item.reference)].sort(), expected.workspaces)) throw enrollmentError('identity_changed')
  let result: HostEnrollmentReview
  try { result = review.parse(await transport.request('GET', `/v1/enrollments/${expected.enrollment_id}/host-review`, undefined, 200, signal)).data }
  catch (cause) { if (cause instanceof HostEnrollmentError) throw cause; throw enrollmentError('response_invalid') }
  if (enrollmentRecoveryBinding(client) !== binding) throw enrollmentError('cancelled')
  const row = result.enrollment
  if (row.enrollment_id !== expected.enrollment_id || row.request_id !== expected.request_id || row.organization_id !== expected.organization_id ||
      row.host_id !== expected.host_id || row.installation_id !== expected.installation_id ||
      row.installation_key_jkt !== expected.installation_key_jkt || row.runtime_id !== expected.runtime_id || row.profile_ref !== expected.profile_ref ||
      Date.parse(row.expires_at) !== Date.parse(expected.expires_at) || !sameWorkspaces(row.workspaces, expected.workspaces) ||
      row.user_confirmed !== (result.confirmed_user !== null)) throw enrollmentError('identity_changed')
  if (row.state !== 'approved' || !row.host_confirmed || !row.user_confirmed || !result.confirmed_user) throw enrollmentError('review_required')
  return Object.freeze({ organizationId: expected.organization_id, hostId: expected.host_id, installationId: expected.installation_id,
    installationKeyThumbprint: expected.installation_key_jkt, runtimeId: expected.runtime_id, profileRef: expected.profile_ref,
    workspaces: Object.freeze(expected.workspaces.map(item => Object.freeze({ reference: item.reference, workspaceId: item.workspace_id }))) })
}

function currentAttempt(attempt: HostEnrollmentIntent, binding: string): IntentState {
  const value = attemptStates.get(attempt)
  const now = Date.now()
  if (!value || value.binding !== binding || !Number.isFinite(now) || now < value.preparedAt || now - value.preparedAt > 10 * 60_000) throw enrollmentError('invalid_config')
  if (attemptOwners.get(attempt)?.aborted !== false) throw enrollmentError('cancelled')
  return value
}

function frozenReceipt(data: ReceiptData): HostEnrollmentDetails {
  return Object.freeze({ ...data, workspaces: Object.freeze(data.workspaces.map(item => Object.freeze({ ...item }))) })
}

/** Export the short-lived pairing code only to the intended local UI or to
 * caller-managed protected recovery storage. Ordinary formatting is redacted. */
export interface HostEnrollmentIntent {
  readonly requestId: string
  readonly code: string
  exportRecovery(): Buffer
  destroy(): void
}

class EnrollmentIntent implements HostEnrollmentIntent {
  constructor(value: IntentState, owner: AbortSignal) {
    if (!(owner instanceof AbortSignal)) throw enrollmentError('invalid_config')
    attemptStates.set(this, value); attemptLifetimes.set(this, new AbortController()); attemptOwners.set(this, owner); Object.freeze(this)
  }
  get requestId(): string { const value = attemptStates.get(this); if (!value) throw enrollmentError('invalid_config'); return value.requestId }
  get code(): string { const value = attemptStates.get(this); if (!value) throw enrollmentError('invalid_config'); return currentAttempt(this, value.binding).code }
  exportRecovery(): Buffer { const value = attemptStates.get(this); if (!value) throw enrollmentError('invalid_config'); return Buffer.from(JSON.stringify(currentAttempt(this, value.binding)), 'utf8') }
  destroy(): void { attemptLifetimes.get(this)?.abort(); attemptLifetimes.delete(this); attemptOwners.delete(this); attemptStates.delete(this) }
  toString(): string { return 'HostEnrollmentIntent' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
}

export interface HostEnrollmentReceipt { readonly details: HostEnrollmentDetails }

class EnrollmentReceipt implements HostEnrollmentReceipt {
  readonly details: HostEnrollmentDetails
  constructor(attempt: HostEnrollmentIntent, data: ReceiptData) {
    this.details = frozenReceipt(data)
    receiptStates.set(this, { attempt, data }); Object.freeze(this)
  }
}

/** Host enrollment is scoped to one verified resource identity and installation
 * key. Local confirmation is supplied by the host UI; no phone or SSO UI is provided. */
export class HostEnrollmentClient {
  readonly signal: AbortSignal
  #transport: HostEnrollmentTransport

  constructor(options: HostEnrollmentOptions) {
    this.#transport = new HostEnrollmentTransport(options)
    this.signal = this.#transport.signal
    clientBindings.set(this, this.#transport.binding)
    clientTransports.set(this, this.#transport)
    Object.freeze(this)
  }
  toString(): string { return 'HostEnrollmentClient' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
  close(): void { this.#transport.close() }

  prepare(input: HostEnrollmentRequest): HostEnrollmentIntent {
    this.#transport.current(this.signal)
    try {
      const normalized = inputSchema.parse(input)
      normalized.workspaceRefs.sort()
      return new EnrollmentIntent({ version: 1, binding: this.#transport.binding, requestId: randomUUID(),
        code: randomBytes(32).toString('base64url'), preparedAt: Date.now(), input: normalized }, this.signal)
    } catch { throw enrollmentError('invalid_config') }
  }

  restore(recovery: Uint8Array): HostEnrollmentIntent {
    this.#transport.current(this.signal)
    if (!(recovery instanceof Uint8Array) || recovery.length === 0 || recovery.length > 16 * 1024) throw enrollmentError('invalid_config')
    const copy = Buffer.from(recovery)
    try {
      const value = recoverySchema.parse(parseSigningObject(copy))
      if (value.input.workspaceRefs.some((item, index, items) => index > 0 && items[index - 1]! >= item)) throw enrollmentError('invalid_config')
      const attempt = new EnrollmentIntent(value, this.signal)
      currentAttempt(attempt, this.#transport.binding)
      return attempt
    } catch { throw enrollmentError('invalid_config') }
    finally { copy.fill(0) }
  }

  async create(attempt: HostEnrollmentIntent, signal: AbortSignal): Promise<HostEnrollmentReceipt> {
    const value = currentAttempt(attempt, this.#transport.binding), input = value.input
    const lifetime = attemptSignal(attempt, signal)
    const body = { request_id: value.requestId, organization_id: input.organizationId, ...(input.hostId ? { host_id: input.hostId } : {}),
      alias: input.alias, profile_ref: input.profileRef, dsh_version: input.dshVersion, application_version: input.applicationVersion,
      plugin_version: input.pluginVersion, protocol_version: input.protocolVersion, installation_public_jwk: this.#transport.publicJwk,
      code: value.code, workspace_refs: input.workspaceRefs }
    let response: ReceiptData
    try { response = created.parse(await this.#transport.request('POST', '/v1/enrollments', body, 201, lifetime)).data }
    catch (cause) { if (cause instanceof HostEnrollmentError) throw cause; throw enrollmentError('outcome_unknown') }
    try { currentAttempt(attempt, this.#transport.binding) } catch { throw enrollmentError('outcome_unknown') }
    if (response.request_id !== value.requestId || response.profile_ref !== input.profileRef || input.hostId && response.host_id !== input.hostId ||
        !sameReferences(input.workspaceRefs, response.workspaces)) throw enrollmentError('outcome_unknown')
    const expires = Date.parse(response.expires_at)
    if (!Number.isFinite(expires) || expires > Date.now() + 330_000) throw enrollmentError('outcome_unknown')
    return new EnrollmentReceipt(attempt, response)
  }

  async review(attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt, signal: AbortSignal): Promise<HostEnrollmentReview> {
    const value = currentAttempt(attempt, this.#transport.binding), saved = receiptStates.get(receipt)
    if (!saved || saved.attempt !== attempt) throw enrollmentError('invalid_config')
    const lifetime = attemptSignal(attempt, signal)
    let result: HostEnrollmentReview
    try { result = review.parse(await this.#transport.request('GET', `/v1/enrollments/${saved.data.enrollment_id}/host-review`, undefined, 200, lifetime)).data }
    catch (cause) { if (cause instanceof HostEnrollmentError) throw cause; throw enrollmentError('response_invalid') }
    currentAttempt(attempt, this.#transport.binding)
    const row = result.enrollment, input = value.input, expected = saved.data
    if (row.enrollment_id !== expected.enrollment_id || row.request_id !== value.requestId || row.organization_id !== input.organizationId ||
        row.host_id !== expected.host_id || row.host_alias !== input.alias || row.installation_id !== expected.installation_id ||
        row.installation_key_jkt !== this.#transport.thumbprint || row.runtime_id !== expected.runtime_id || row.profile_ref !== input.profileRef ||
        (row.dsh_version ?? '') !== input.dshVersion || (row.application_version ?? '') !== input.applicationVersion ||
        (row.plugin_version ?? '') !== input.pluginVersion || row.protocol_version !== input.protocolVersion ||
        Date.parse(row.expires_at) !== Date.parse(expected.expires_at) || !sameWorkspaces(row.workspaces, expected.workspaces) ||
        row.user_confirmed !== (result.confirmed_user !== null)) throw enrollmentError('identity_changed')
    return result
  }

  async confirm(attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt,
    approve: (review: HostEnrollmentApprovalReview, signal: AbortSignal) => boolean | Promise<boolean>, signal: AbortSignal): Promise<HostEnrollmentConfirmation> {
    if (typeof approve !== 'function' || !(signal instanceof AbortSignal)) throw enrollmentError('invalid_config')
    const attemptState = currentAttempt(attempt, this.#transport.binding)
    if (receiptStates.get(receipt)?.attempt !== attempt) throw enrollmentError('invalid_config')
    const approvalKey = `${attemptState.binding}:${attemptState.requestId}`
    if (activeApprovals.has(approvalKey)) throw enrollmentError('busy')
    activeApprovals.add(approvalKey)
    try {
      const first = await this.review(attempt, receipt, signal)
      const user = requireReview(first)
      const remaining = Date.parse(first.enrollment.expires_at) - Date.now()
      if (remaining <= 0) throw enrollmentError('review_required')
      const consentSignal = AbortSignal.any([attemptSignal(attempt, signal), this.signal, AbortSignal.timeout(Math.min(remaining, 120_000))])
      this.#transport.current(consentSignal)
      const visible = freezeReview(first)
      const accepted = await enrollmentAbortable(Promise.resolve().then(() => { this.#transport.current(consentSignal); return approve(visible, consentSignal) }), consentSignal)
      this.#transport.current(consentSignal)
      if (accepted !== true) throw enrollmentError('declined')
      const current = await this.review(attempt, receipt, consentSignal)
      const currentUser = requireReview(current)
      if (currentUser.user_id !== user.user_id || currentUser.issuer !== user.issuer || currentUser.subject !== user.subject ||
          current.enrollment.organization_name !== first.enrollment.organization_name ||
          current.enrollment.user_confirmed_by_me !== first.enrollment.user_confirmed_by_me) throw enrollmentError('identity_changed')
      const value = currentAttempt(attempt, this.#transport.binding), saved = receiptStates.get(receipt)!
      let result: HostEnrollmentConfirmation
      try { result = confirmation.parse(await this.#transport.request('POST', `/v1/enrollments/${saved.data.enrollment_id}/host-confirm`,
        { code: value.code, confirmed_user_id: currentUser.user_id }, 200, consentSignal)).data }
      catch (cause) { if (cause instanceof HostEnrollmentError) throw cause; throw enrollmentError('outcome_unknown') }
      try { this.#transport.current(consentSignal); currentAttempt(attempt, this.#transport.binding) } catch { throw enrollmentError('outcome_unknown') }
      if (result.enrollment_id !== saved.data.enrollment_id || result.host_id !== saved.data.host_id || result.runtime_id !== saved.data.runtime_id ||
          result.state !== 'approved' || !result.user_confirmed || !result.host_confirmed || Date.parse(result.expires_at) !== Date.parse(saved.data.expires_at)) throw enrollmentError('outcome_unknown')
      return result
    } finally { activeApprovals.delete(approvalKey) }
  }
}

function attemptSignal(attempt: HostEnrollmentIntent, caller: AbortSignal): AbortSignal {
  const lifetime = attemptLifetimes.get(attempt)
  if (!(caller instanceof AbortSignal) || !lifetime) throw enrollmentError('invalid_config')
  return AbortSignal.any([caller, lifetime.signal])
}

function sameReferences(refs: string[], workspaces: ReceiptData['workspaces']): boolean {
  return refs.length === workspaces.length && new Set(workspaces.map(item => item.workspace_id)).size === workspaces.length &&
    [...workspaces.map(item => item.reference)].sort().every((item, index) => item === refs[index])
}
function sameWorkspaces(actual: ReceiptData['workspaces'], expected: ReceiptData['workspaces']): boolean {
  if (actual.length !== expected.length || new Set(actual.map(item => item.reference)).size !== actual.length || new Set(actual.map(item => item.workspace_id)).size !== actual.length) return false
  const map = new Map(expected.map(item => [item.reference, item.workspace_id]))
  return actual.every(item => map.get(item.reference) === item.workspace_id)
}
function requireReview(value: HostEnrollmentReview): NonNullable<HostEnrollmentReview['confirmed_user']> {
  if (value.enrollment.state !== 'user_confirmed' || value.enrollment.host_confirmed || !value.enrollment.user_confirmed ||
      !value.confirmed_user?.eligible || Date.parse(value.enrollment.expires_at) <= Date.now()) throw enrollmentError('review_required')
  return value.confirmed_user
}
function freezeReview(value: HostEnrollmentReview): HostEnrollmentApprovalReview {
  const enrollment = Object.freeze({ ...value.enrollment, workspaces: Object.freeze(value.enrollment.workspaces.map(item => Object.freeze({ ...item }))) })
  return Object.freeze({ enrollment, confirmed_user: value.confirmed_user && Object.freeze({ ...value.confirmed_user }) })
}
