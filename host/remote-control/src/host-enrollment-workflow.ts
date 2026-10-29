import { inspect } from 'node:util'
import { HostEnrollmentError } from './host-enrollment-transport.js'
import { runHostEnrollmentOnTerminal } from './host-local-enrollment.js'
import type { HostEnrollmentBinding, HostEnrollmentClient, HostEnrollmentIntent, HostEnrollmentRequest } from './host-enrollment.js'
import type { HostEnrollmentBindingStore } from './host-enrollment-binding.js'
import type { HostEnrollmentRecoveryStore } from './host-enrollment-recovery.js'

type Code = 'invalid_config' | 'cancelled' | 'busy' | 'existing' | 'recovery_required'
export class HostTerminalEnrollmentWorkflowError extends Error {
  readonly code: `host.terminal_enrollment.${Code}`
  constructor(code: `host.terminal_enrollment.${Code}`) {
    const allowed: Code[] = ['invalid_config', 'cancelled', 'busy', 'existing', 'recovery_required']
    const safe = allowed.some(value => code === `host.terminal_enrollment.${value}`) ? code : 'host.terminal_enrollment.invalid_config'
    super(safe); this.code = safe; this.name = 'HostTerminalEnrollmentWorkflowError'
  }
}
const failure = (code: Code) => new HostTerminalEnrollmentWorkflowError(`host.terminal_enrollment.${code}`)

export interface HostTerminalEnrollmentWorkflowOptions {
  client: HostEnrollmentClient
  recovery: HostEnrollmentRecoveryStore
  binding: HostEnrollmentBindingStore
}

/** Explicit Linux terminal enrollment and recovery. Dependencies remain owned by the caller. */
export class HostTerminalEnrollmentWorkflow {
  readonly signal: AbortSignal
  #closed = new AbortController()
  #client: HostEnrollmentClient
  #recovery: HostEnrollmentRecoveryStore
  #binding: HostEnrollmentBindingStore
  #busy = false

  constructor(options: HostTerminalEnrollmentWorkflowOptions) {
    if (!options || !(options.client?.signal instanceof AbortSignal) || !(options.recovery?.signal instanceof AbortSignal) ||
        !(options.binding?.signal instanceof AbortSignal) || typeof options.client.prepare !== 'function' ||
        typeof options.client.review !== 'function' || typeof options.recovery.load !== 'function' ||
        typeof options.recovery.create !== 'function' || typeof options.recovery.save !== 'function' ||
        typeof options.recovery.confirm !== 'function' || typeof options.recovery.removeApproved !== 'function' ||
        typeof options.binding.open !== 'function' || typeof options.binding.reserve !== 'function' || typeof options.binding.confirm !== 'function') throw failure('invalid_config')
    this.#client = options.client; this.#recovery = options.recovery; this.#binding = options.binding
    this.signal = AbortSignal.any([this.#closed.signal, options.client.signal, options.recovery.signal, options.binding.signal])
    Object.freeze(this)
  }

  toString(): string { return 'HostTerminalEnrollmentWorkflow' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
  close(): void { this.#closed.abort() }

  #current(signal: AbortSignal): void { if (signal.aborted || this.signal.aborted) throw failure('cancelled') }

  async #run<T>(caller: AbortSignal, action: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (!(caller instanceof AbortSignal)) throw failure('invalid_config')
    this.#current(caller)
    if (this.#busy) throw failure('busy')
    this.#busy = true
    const lifetime = AbortSignal.any([caller, this.signal])
    try { return await action(lifetime) }
    finally { this.#busy = false }
  }

  async #existing(signal: AbortSignal): Promise<{ binding: HostEnrollmentBinding | undefined; pending: boolean }> {
    try {
      const binding = await this.#binding.open(signal)
      this.#current(signal)
      return { binding, pending: false }
    } catch (cause) {
      if (cause instanceof HostEnrollmentError && cause.code === 'host.enrollment.review_required') {
        this.#current(signal)
        return { binding: undefined, pending: true }
      }
      throw cause
    }
  }

  async #continue(attempt: HostEnrollmentIntent, signal: AbortSignal): Promise<HostEnrollmentBinding> {
    this.#current(signal)
    const receipt = await this.#recovery.create(attempt, signal)
    this.#current(signal)
    if (receipt.details.state === 'pending' || receipt.details.state === 'user_confirmed') {
      // Refuse a conflicting pointer before displaying the pairing code.
      await this.#binding.reserve(attempt, receipt, signal)
      this.#current(signal)
    }
    return await runHostEnrollmentOnTerminal({ client: this.#client, recovery: this.#recovery, binding: this.#binding, attempt, receipt, signal })
  }

  /** Reopen an approved binding or explicitly resume its original protected attempt.
   * Undefined means no local records, not proof that no server request exists. */
  async resume(signal: AbortSignal): Promise<HostEnrollmentBinding | undefined> {
    return await this.#run(signal, async lifetime => {
      const existing = await this.#existing(lifetime)
      if (existing.binding) return existing.binding
      const attempt = await this.#recovery.load(lifetime)
      try {
        this.#current(lifetime)
        if (!attempt) {
          if (existing.pending) throw failure('recovery_required')
          return undefined
        }
        return await this.#continue(attempt, lifetime)
      } finally { attempt?.destroy() }
    })
  }

  /** Start only after the caller has independently reconciled any older request. */
  async start(request: HostEnrollmentRequest, signal: AbortSignal): Promise<HostEnrollmentBinding> {
    return await this.#run(signal, async lifetime => {
      const existing = await this.#existing(lifetime)
      if (existing.binding || existing.pending) throw failure('existing')
      const saved = await this.#recovery.load(lifetime)
      try { if (saved) throw failure('existing') }
      finally { saved?.destroy() }
      this.#current(lifetime)
      const attempt = this.#client.prepare(request)
      try { return await this.#continue(attempt, lifetime) }
      finally { attempt.destroy() }
    })
  }

  /** Explicitly remove only recovery data matched to a freshly approved binding. */
  async cleanup(signal: AbortSignal): Promise<boolean> {
    return await this.#run(signal, async lifetime => await this.#recovery.removeApproved(this.#binding, lifetime))
  }
}
