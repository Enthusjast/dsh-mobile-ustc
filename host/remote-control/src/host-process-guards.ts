/** Shared across duplicate copies of this package loaded in one JS realm. */
interface HostProcessGuards {
  readonly enrollmentApprovals: Set<string>
  readonly recoveryPaths: Map<string, symbol>
}

const key = Symbol.for('ustc.dsh.host-process-guards.v1')
const globalState = globalThis as unknown as Record<symbol, unknown>
const existing = globalState[key]
let guards: HostProcessGuards
if (existing === undefined) {
  guards = Object.freeze({ enrollmentApprovals: new Set<string>(), recoveryPaths: new Map<string, symbol>() })
  Object.defineProperty(globalThis, key, { value: guards, enumerable: false, configurable: false, writable: false })
} else {
  const value = existing as Partial<HostProcessGuards>
  if (!value || !(value.enrollmentApprovals instanceof Set) || !(value.recoveryPaths instanceof Map)) throw new Error('host process guards unavailable')
  guards = value as HostProcessGuards
}

export { guards }
