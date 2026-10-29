import { randomInt } from 'node:crypto'
import { closeSync, constants, fstatSync, openSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { setTimeout as delay } from 'node:timers/promises'
import { ReadStream, WriteStream, isatty } from 'node:tty'
import { z } from 'zod'
import { captureEnrollmentBinding, type HostEnrollmentApprovalReview, type HostEnrollmentBinding, type HostEnrollmentClient, type HostEnrollmentIntent, type HostEnrollmentReceipt } from './host-enrollment.js'
import type { HostEnrollmentBindingStore } from './host-enrollment-binding.js'
import type { HostEnrollmentRecoveryStore } from './host-enrollment-recovery.js'

type Code = 'unavailable' | 'cancelled' | 'expired' | 'busy' | 'recovery_required'
export class HostLocalEnrollmentError extends Error {
  readonly code: `host.local_enrollment.${Code}`
  constructor(code: `host.local_enrollment.${Code}`) {
    const allowed: Code[] = ['unavailable', 'cancelled', 'expired', 'busy', 'recovery_required']
    const safe = allowed.some(value => code === `host.local_enrollment.${value}`) ? code : 'host.local_enrollment.unavailable'
    super(safe); this.code = safe; this.name = 'HostLocalEnrollmentError'
  }
}
const failure = (code: Code = 'unavailable') => new HostLocalEnrollmentError(`host.local_enrollment.${code}`)
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const ref = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/)
const fingerprint = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value)
const text = z.string().min(1).max(2048)
const visibleReview = z.object({
  enrollment: z.object({ organization_id: uuid, organization_name: text, host_id: uuid, host_alias: text, installation_id: uuid,
    installation_key_jkt: fingerprint, runtime_id: uuid, profile_ref: ref, state: z.literal('user_confirmed'),
    expires_at: z.string().datetime({ offset: true }), host_confirmed: z.literal(false), user_confirmed: z.literal(true),
    workspaces: z.array(z.strictObject({ reference: ref, workspace_id: uuid })).max(64) }).passthrough(),
  confirmed_user: z.strictObject({ user_id: uuid, issuer: text, subject: text, eligible: z.literal(true) }),
}).strict()

const guardKey = Symbol.for('ustc.dsh.host-local-enrollment-terminal.v1')
const globalState = globalThis as unknown as Record<symbol, unknown>
const existing = globalState[guardKey]
if (existing !== undefined && !(existing instanceof Set)) throw new Error('host local terminal guard unavailable')
const terminalGuard = (existing ?? new Set<string>()) as Set<string>
if (existing === undefined) Object.defineProperty(globalThis, guardKey, { value: terminalGuard, enumerable: false, writable: false, configurable: false })

type Terminal = { input: ReadStream; output: WriteStream }

function openTerminal(): Terminal {
  if (process.platform !== 'linux') throw failure()
  let inputFd = -1, outputFd = -1
  let input: ReadStream | undefined, output: WriteStream | undefined
  try {
    inputFd = openSync('/dev/tty', constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOCTTY)
    outputFd = openSync('/dev/tty', constants.O_WRONLY | constants.O_NONBLOCK | constants.O_NOCTTY)
    if (!isatty(inputFd) || !isatty(outputFd) || !fstatSync(inputFd).isCharacterDevice() || !fstatSync(outputFd).isCharacterDevice()) throw failure()
    input = new ReadStream(inputFd)
    inputFd = -1
    output = new WriteStream(outputFd)
    outputFd = -1
    input.on('error', () => {}); output.on('error', () => {})
    return { input, output }
  } catch {
    input?.destroy(); output?.destroy()
    if (inputFd >= 0) try { closeSync(inputFd) } catch { /* Already closed. */ }
    if (outputFd >= 0) try { closeSync(outputFd) } catch { /* Already closed. */ }
    throw failure()
  }
}

function current(signal: AbortSignal): void { if (signal.aborted) throw failure('cancelled') }

async function withTerminal<T>(signal: AbortSignal, action: (terminal: Terminal) => Promise<T>): Promise<T> {
  if (!(signal instanceof AbortSignal)) throw failure()
  current(signal)
  if (terminalGuard.has('controlling-terminal')) throw failure('busy')
  terminalGuard.add('controlling-terminal')
  let terminal: Terminal | undefined
  try {
    terminal = openTerminal()
    current(signal)
    return await action(terminal)
  } catch (cause) {
    if (cause instanceof HostLocalEnrollmentError) throw new HostLocalEnrollmentError(cause.code)
    if (signal.aborted) throw failure('cancelled')
    throw failure()
  } finally {
    terminal?.input.destroy(); terminal?.output.destroy()
    terminalGuard.delete('controlling-terminal')
  }
}

// Untrusted server strings are rendered as unambiguous printable ASCII. This
// prevents terminal escape sequences, bidirectional controls and line injection.
function literal(value: string): string {
  let result = '"'
  for (const character of value) {
    const point = character.codePointAt(0)!
    if (point >= 0x20 && point <= 0x7e && character !== '"' && character !== '\\') result += character
    else if (character === '"' || character === '\\') result += `\\${character}`
    else result += `\\u{${point.toString(16).toUpperCase()}}`
  }
  return `${result}"`
}

async function writeTerminal(output: WriteStream, value: string, signal: AbortSignal): Promise<void> {
  if (Buffer.byteLength(value) > 32 * 1024) throw failure()
  current(signal)
  await new Promise<void>((resolveResult, rejectResult) => {
    let settled = false
    const finish = (error?: HostLocalEnrollmentError) => {
      if (settled) return
      settled = true; signal.removeEventListener('abort', abort); output.removeListener('error', bad)
      if (error) rejectResult(error); else resolveResult()
    }
    const abort = () => finish(failure('cancelled'))
    const bad = () => finish(failure())
    signal.addEventListener('abort', abort, { once: true }); output.once('error', bad)
    output.write(value, error => finish(error ? failure() : undefined))
    if (signal.aborted) abort()
  })
}

async function readDecision(input: ReadStream, expected: string, signal: AbortSignal): Promise<boolean> {
  current(signal)
  return await new Promise<boolean>((resolveResult, rejectResult) => {
    let settled = false, bytes = 0
    const reader = createInterface({ input, terminal: false, crlfDelay: Infinity })
    const finish = (decision: boolean, error?: HostLocalEnrollmentError) => {
      if (settled) return
      settled = true; signal.removeEventListener('abort', abort); input.removeListener('data', count); input.removeListener('error', bad)
      reader.removeListener('line', line); reader.removeListener('close', closed); reader.close()
      if (error) rejectResult(error); else resolveResult(decision)
    }
    const abort = () => finish(false, failure('cancelled'))
    const bad = () => finish(false, failure())
    const closed = () => finish(false, failure())
    const line = (value: string) => finish(value === expected)
    const count = (chunk: string | Buffer) => { bytes += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.length; if (bytes > 128) finish(false) }
    input.prependListener('data', count); input.once('error', bad)
    reader.once('line', line); reader.once('close', closed)
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) abort()
  })
}

/** Show the short-lived code only on this process's controlling terminal. */
export async function presentHostEnrollmentOnTerminal(client: HostEnrollmentClient, attempt: HostEnrollmentIntent, receipt: HostEnrollmentReceipt, signal: AbortSignal): Promise<void> {
  if (!(signal instanceof AbortSignal)) throw failure()
  const record = captureEnrollmentBinding(client, attempt, receipt)
  if (!['pending', 'user_confirmed'].includes(receipt.details.state) || Date.parse(receipt.details.expires_at) <= Date.now()) throw failure('expired')
  const pairingCode = attempt.code
  const lifetime = AbortSignal.any([signal, client.signal, AbortSignal.timeout(5_000)])
  const text = [
    '\nDSH 远控绑定申请（仅在可信本机终端展示）',
    `组织 ID: ${record.organization_id}`, `主机 ID: ${record.host_id}`, `安装实例 ID: ${record.installation_id}`,
    `运行实例 ID: ${record.runtime_id}`, `Profile: ${literal(record.profile_ref)}`, `安装公钥指纹: ${record.installation_key_jkt}`,
    `登记 ID: ${record.enrollment_id}`, `配对码: ${pairingCode}`, `有效期至: ${record.expires_at}`,
    '请在手机上核对主机与指纹并确认；本机随后仍需单独核对用户。', '',
  ].join('\n')
  await withTerminal(lifetime, async terminal => { await writeTerminal(terminal.output, text, lifetime) })
}

/** Ask for an unpredictable exact response after displaying the verified review. */
export async function approveHostEnrollmentOnTerminal(source: HostEnrollmentApprovalReview, signal: AbortSignal): Promise<boolean> {
  if (!(signal instanceof AbortSignal)) throw failure()
  let review: z.infer<typeof visibleReview>
  try { review = visibleReview.parse(source) } catch { throw failure() }
  if (Date.parse(review.enrollment.expires_at) <= Date.now()) throw failure('expired')
  const challenge = randomInt(100_000, 1_000_000).toString()
  const user = review.confirmed_user, row = review.enrollment
  const text = [
    '\nDSH 远控绑定：请核对以下信息',
    `组织: ${literal(row.organization_name)} (${row.organization_id})`, `主机: ${literal(row.host_alias)} (${row.host_id})`,
    `安装实例: ${row.installation_id}`, `安装公钥指纹: ${row.installation_key_jkt}`,
    `运行实例: ${row.runtime_id}`, `Profile: ${literal(row.profile_ref)}`,
    `确认用户 ID: ${user.user_id}`, `用户 issuer: ${literal(user.issuer)}`, `用户 subject: ${literal(user.subject)}`,
    ...row.workspaces.map(item => `工作区: ${literal(item.reference)} (${item.workspace_id})`),
    `有效期至: ${row.expires_at}`,
    '请通过可信组织目录核对用户身份；非 ASCII 和控制字符以转义形式显示。',
    `仅在明确同意绑定时输入 APPROVE ${challenge} 并按回车；其他输入均拒绝。`, '',
  ].join('\n')
  return await withTerminal(signal, async terminal => {
    await writeTerminal(terminal.output, text, signal)
    return await readDecision(terminal.input, `APPROVE ${challenge}`, signal)
  })
}

export interface HostLocalEnrollmentOptions {
  client: HostEnrollmentClient
  recovery: HostEnrollmentRecoveryStore
  binding: HostEnrollmentBindingStore
  attempt: HostEnrollmentIntent
  receipt: HostEnrollmentReceipt
  signal: AbortSignal
}

/** Present pairing on the controlling terminal, wait for the phone and require
 * explicit local confirmation. No approval or new attempt is replayed automatically. */
export async function runHostEnrollmentOnTerminal(options: HostLocalEnrollmentOptions): Promise<HostEnrollmentBinding> {
  if (!options || !(options.signal instanceof AbortSignal) || !options.client || !options.recovery || !options.binding) throw failure()
  const { client, recovery, binding, attempt, receipt, signal } = options
  const expected = captureEnrollmentBinding(client, attempt, receipt)
  const reconcile = async (lifetime: AbortSignal) => {
    const result = await binding.open(lifetime)
    if (!result || result.requestId !== expected.request_id || result.enrollmentId !== expected.enrollment_id ||
        result.organizationId !== expected.organization_id || result.hostId !== expected.host_id ||
        result.installationId !== expected.installation_id || result.installationKeyThumbprint !== expected.installation_key_jkt ||
        result.runtimeId !== expected.runtime_id || result.profileRef !== expected.profile_ref || result.workspaces.length !== expected.workspaces.length ||
        result.workspaces.some(item => !expected.workspaces.some(saved => saved.reference === item.reference && saved.workspace_id === item.workspaceId))) throw failure('recovery_required')
    return result
  }
  if (receipt.details.state === 'approved') {
    return await reconcile(signal)
  }
  const remaining = Date.parse(receipt.details.expires_at) - Date.now()
  if (remaining <= 0 || !['pending', 'user_confirmed'].includes(receipt.details.state)) throw failure('expired')
  const deadline = AbortSignal.timeout(Math.min(remaining, 300_000))
  const lifetime = AbortSignal.any([signal, client.signal, deadline])
  await recovery.save(attempt, lifetime)
  await presentHostEnrollmentOnTerminal(client, attempt, receipt, lifetime)
  for (;;) {
    if (deadline.aborted) throw failure('expired')
    current(lifetime)
    const review = await client.review(attempt, receipt, lifetime)
    if (review.enrollment.state === 'approved') {
      return await reconcile(lifetime)
    }
    if (review.enrollment.state === 'user_confirmed' && review.confirmed_user?.eligible) {
      return await binding.confirm(recovery, attempt, receipt, approveHostEnrollmentOnTerminal, lifetime)
    }
    if (!['pending', 'user_confirmed'].includes(review.enrollment.state)) throw failure('expired')
    try { await delay(Math.min(5_000, Math.max(1, Date.parse(receipt.details.expires_at) - Date.now())), undefined, { signal: lifetime }) }
    catch { if (deadline.aborted) throw failure('expired'); if (lifetime.aborted) throw failure('cancelled'); throw failure() }
  }
}
