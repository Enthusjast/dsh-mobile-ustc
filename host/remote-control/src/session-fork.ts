import { SessionId } from '@deepseek-ai/dsh-session'
import { remoteErrorOf } from '@deepseek-ai/dsh-typert-protocol'
import type { CommandOwner } from './command-journal.js'
import { mobileSessionId, type DshClient } from './dsh-client.js'
import type { ForkPartialResult, ForkPayload, ForkResult } from './fork-protocol.js'
import { ProbeError } from './protocol.js'
import type { SessionMessageActions } from './session-message-actions.js'

/** The caller must durably enter dispatching before invoking this function. There is deliberately no retry loop. */
export async function forkSessionOnce(client: DshClient, messages: SessionMessageActions, sourceSessionId: string,
  payload: ForkPayload, owner: CommandOwner, signal: AbortSignal, note: (partial: ForkPartialResult) => void): Promise<ForkResult> {
  const native = await messages.validateFork(sourceSessionId, payload.workspace_id, payload.anchor, owner, signal)
  signal.throwIfAborted()
  let child: SessionId, attached: 'attached' | 'failed' = 'attached'
  try {
    // Native has no caller request ID. A dispatching/uncertain original must never reach this call again.
    const result = await client.forkNative(native, payload.anchor.native_seq)
    child = result.sessionId
  } catch (cause) {
    const error = remoteErrorOf(cause)
    if (error?.code !== 'session/workspace-attach-failed') throw cause
    const details = error.details as { sessionId?: unknown }
    if (typeof details.sessionId !== 'string' || details.sessionId.length === 0 || Buffer.byteLength(details.sessionId) > 2048 || details.sessionId.includes('\0')) throw cause
    child = SessionId(details.sessionId)
    attached = 'failed'
  }
  const mobile = mobileSessionId(client.runtimeId, child)
  if (mobile === sourceSessionId) throw new ProbeError('command.outcome_unknown')
  let partial: ForkPartialResult = { child_session_id: mobile, fork_outcome: { v: 1, workspace_attachment: attached, checkpoint: 'unknown' } }
  // Persist the created identity before any asynchronous checkpoint/catalog work, including partial attach failure.
  note(partial)
  const checkpoint = await client.checkpoint(child)
  partial = { ...partial, fork_outcome: { ...partial.fork_outcome, checkpoint: checkpoint.state } }
  note(partial)
  if (checkpoint.state !== 'persisted') return { ...partial, checkpoint, command_state: 'outcome_unknown' }
  try {
    // Resolve configured cwd and the new ordinary seeded child through the authoritative catalog again.
    // This is not a grant to open it; Relay/Android must independently revalidate target authority.
    const catalog = await client.sessionCatalog(AbortSignal.timeout(3000), [String(child)])
    const item = catalog.find(entry => entry.session_id === mobile && entry.workspace_id === payload.workspace_id && entry.state !== 'unavailable')
    if (!item || item.last_persisted_seq < checkpoint.through_seq) return { ...partial, checkpoint, command_state: 'outcome_unknown' }
    return { ...partial, checkpoint, catalog_item: item }
  } catch {
    return { ...partial, checkpoint, command_state: 'outcome_unknown' }
  }
}
