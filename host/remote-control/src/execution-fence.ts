import { randomUUID } from 'node:crypto'
import type { ToolDefinition, ToolExecution, ToolRunContext } from '@deepseek-ai/dsh-tools'

const unavailable = () => new Error('approval: native execution authority unavailable')
type Execution = Readonly<ToolExecution>
type BodyCheck = (args: unknown, execution: ToolRunContext) => void
type BodySlot = BodyCheck | 'blocked' | 'spent'
const definitions = new WeakMap<ToolDefinition, DefinitionExecutionFence>()

/**
 * Public-definition adapter for the pinned DSH body boundary. It preserves the
 * registry's own lookup/scoping instead of registering a shadow capability.
 * Weak execution keys retain negative fences for delayed/retried calls without
 * retaining disposed plugin owners or granting a second invocation.
 */
export class DefinitionExecutionFence {
  readonly version = randomUUID()
  private readonly slots = new WeakMap<object, BodySlot>()
  readonly execute: ToolDefinition['execute']

  constructor(readonly definition: ToolDefinition) {
    const property = Object.getOwnPropertyDescriptor(definition, 'execute')
    if (!property || !('value' in property) || typeof property.value !== 'function' || !property.writable) throw unavailable()
    const original = property.value as ToolDefinition['execute'], slots = this.slots
    this.execute = function (args, execution) {
      const check = slots.get(execution)
      if (check === 'blocked' || check === 'spent') throw unavailable()
      if (check) {
        // Spend the in-memory body entry before the durable check. A failed
        // check must not permit an around-wrapper to retry this same execution.
        slots.set(execution, 'spent')
        check(args, execution)
      }
      return Reflect.apply(original, this, [args, execution])
    }
    Object.defineProperty(definition, 'execute', { ...property, value: this.execute })
  }

  arm(execution: Execution, check: BodyCheck): void {
    if (this.slots.has(execution) || this.definition.execute !== this.execute) throw unavailable()
    this.slots.set(execution, check)
  }

  block(execution: Execution): void { this.slots.set(execution, 'blocked') }
}

export function fenceToolDefinition(definition: ToolDefinition): DefinitionExecutionFence {
  let fence = definitions.get(definition)
  if (!fence || definition.execute !== fence.execute) {
    fence = new DefinitionExecutionFence(definition)
    definitions.set(definition, fence)
  }
  return fence
}

export interface ExecutionSignalFence {
  /** Called only after durable consumption, immediately before the real body. */
  enterBody(): void
  /** Closes an unstarted call even if a wrapper replaces its signal. */
  cancel(): void
  /** Release owner callbacks; keep only a weak negative fence on old calls. */
  release(): void
}

/**
 * DSH 0.2.1-rc.2 reads and fuses exec.signal immediately before resolving the
 * body. Validate there as well as at tools.guard, so async wrappers cannot move
 * a stale permit to a later dispatch or swap to an unadapted definition.
 */
export function fenceExecutionSignal(execution: Execution, validate: () => boolean): ExecutionSignalFence {
  const property = Object.getOwnPropertyDescriptor(execution, 'signal')
  if (!property || !('value' in property) || !property.configurable || !property.writable) throw unavailable()
  const caller = property.value as AbortSignal
  const controller = new AbortController()
  let current = AbortSignal.any([caller, controller.signal])
  let check: (() => boolean) | undefined = validate
  let checking = false, entered = false
  const fail = () => controller.abort(unavailable())
  const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')!.get!
  Object.defineProperty(execution, 'signal', {
    enumerable: property.enumerable ?? false, configurable: false,
    get() {
      if (check && !checking) {
        checking = true
        try { if (!check()) fail() } catch { fail() }
        finally { checking = false }
      }
      return current
    },
    set(value: AbortSignal) {
      if (Object.isFrozen(execution)) throw unavailable()
      try { Reflect.apply(aborted, value, []) } catch { fail(); throw unavailable() }
      current = AbortSignal.any([caller, controller.signal, value])
    },
  })
  return {
    enterBody() { if (controller.signal.aborted || entered) throw unavailable(); entered = true; check = undefined },
    cancel() { if (!entered) fail(); check = undefined },
    release() { if (!entered) fail(); check = undefined },
  }
}
