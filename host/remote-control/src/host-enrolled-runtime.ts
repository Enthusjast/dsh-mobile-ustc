import { isAbsolute, resolve } from 'node:path'
import { enrollmentRecoveryBinding, requireEnrollmentBindingOwner, type HostEnrollmentClient } from './host-enrollment.js'
import type { HostEnrollmentBindingStore } from './host-enrollment-binding.js'
import { hostRestCredentialOwner, type HostRestCredentialProvider } from './host-credentials.js'
import type { Workspace } from './dsh-client.js'
import type { SignedApprovalOptions } from './signed-approvals.js'

type Code = 'invalid_config' | 'identity_changed' | 'unavailable' | 'cancelled'
export class HostEnrolledRuntimeError extends Error {
  readonly code: `host.enrolled_runtime.${Code}`
  constructor(code: `host.enrolled_runtime.${Code}`) {
    const allowed: Code[] = ['invalid_config', 'identity_changed', 'unavailable', 'cancelled']
    const safe = allowed.some(value => code === `host.enrolled_runtime.${value}`) ? code : 'host.enrolled_runtime.unavailable'
    super(safe); this.code = safe; this.name = 'HostEnrolledRuntimeError'
  }
}
const failure = (code: Code) => new HostEnrolledRuntimeError(`host.enrolled_runtime.${code}`)

export interface HostEnrolledRuntimeOptions {
  /** The same resource account and installation used by the binding store. */
  client: HostEnrollmentClient
  binding: HostEnrollmentBindingStore
  credentials: HostRestCredentialProvider
  /** A trusted profile identifier supplied by the host distribution. */
  profileRef: string
}

/** @internal Verify the active binding before opening the journal or a local endpoint. */
export async function verifyEnrolledHostRuntime(options: HostEnrolledRuntimeOptions,
  runtime: { runtimeId: string; workspaces: readonly Workspace[]; requireProtectedJournalKey: boolean },
  signed: Pick<SignedApprovalOptions, 'hostId' | 'installationId'>, signal: AbortSignal): Promise<void> {
  if (!(signal instanceof AbortSignal) || !options || !(options.client?.signal instanceof AbortSignal) ||
      !(options.binding?.signal instanceof AbortSignal) || !(options.credentials?.signal instanceof AbortSignal) ||
      typeof options.binding.open !== 'function' || typeof options.profileRef !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.profileRef) || !runtime || !signed ||
      !runtime.requireProtectedJournalKey || !Array.isArray(runtime.workspaces) || runtime.workspaces.length === 0) throw failure('invalid_config')
  const lifetime = AbortSignal.any([signal, options.client.signal, options.binding.signal, options.credentials.signal])
  if (lifetime.aborted) throw failure('cancelled')
  let owner: ReturnType<typeof hostRestCredentialOwner>, expected: string
  try { owner = hostRestCredentialOwner(options.credentials); expected = enrollmentRecoveryBinding(options.client) }
  catch { if (lifetime.aborted) throw failure('cancelled'); throw failure('invalid_config') }
  if (owner.binding !== expected) throw failure('identity_changed')
  let binding: Awaited<ReturnType<HostEnrollmentBindingStore['open']>>
  try { binding = await options.binding.open(lifetime) }
  catch { if (lifetime.aborted) throw failure('cancelled'); throw failure('unavailable') }
  if (lifetime.aborted) throw failure('cancelled')
  if (!binding) throw failure('unavailable')
  try { requireEnrollmentBindingOwner(options.client, binding) }
  catch { if (lifetime.aborted) throw failure('cancelled'); throw failure('identity_changed') }
  if (binding.runtimeId !== runtime.runtimeId || binding.profileRef !== options.profileRef ||
      binding.installationId !== owner.installationId || binding.hostId !== signed.hostId || binding.installationId !== signed.installationId) throw failure('identity_changed')
  const registered = new Map(binding.workspaces.map(item => [item.reference, item.workspaceId]))
  const ids = new Set<string>(), remotes = new Set<string>(), paths = new Set<string>()
  for (const workspace of runtime.workspaces) {
    if (!workspace || typeof workspace.id !== 'string' || typeof workspace.remoteId !== 'string' ||
        typeof workspace.cwd !== 'string' || workspace.cwd.includes('\0') || Buffer.byteLength(workspace.cwd) > 8192 ||
        !isAbsolute(workspace.cwd) || registered.get(workspace.id) !== workspace.remoteId ||
        ids.has(workspace.id) || remotes.has(workspace.remoteId) || paths.has(resolve(workspace.cwd))) throw failure('identity_changed')
    ids.add(workspace.id); remotes.add(workspace.remoteId); paths.add(resolve(workspace.cwd))
  }
}
