import type { DshClient } from './dsh-client.js'
import { mediaEventVersion, visibleMediaReference, type VisibleMediaReference } from './media-protocol.js'
import { sessionImageDescriptor } from './session-file-export.js'
import { projectEvent } from './projection.js'
import { ProbeError } from './protocol.js'

/** Reuse the narrower persisted visible-event export producer, never attachment(session, callerId). */
export async function verifyVisibleMedia(client: DshClient, session: string, input: VisibleMediaReference,
  signal: AbortSignal, current: () => void): Promise<VisibleMediaReference> {
  const reference = visibleMediaReference.parse(input)
  signal.throwIfAborted(); current()
  // This path checks the current configured workspace, stable checkpoint, visible native producer and pinned source digest.
  const source = await client.attachmentExportSource(session, reference.native_seq, reference.part_index, signal, current)
  try {
    const manifest = await source.prepare(signal)
    if (mediaEventVersion(manifest) !== mediaEventVersion(reference.manifest)) throw new ProbeError('file.export_changed')
    signal.throwIfAborted(); current()
    const native = await client.resolve(session, signal)
    const page = await client.page(native, { throughSeq: reference.native_seq, beforeSeq: reference.native_seq + 1, maxMessages: 1 }, signal)
    const event = page.records.find(record => record.event.seq === reference.native_seq)?.event
    if (!event) throw new ProbeError('file.export_unavailable')
    const actual = visibleMediaReference.parse({ v: 1, origin: 'session_attachment', native_seq: event.seq,
      part_index: reference.part_index, event_version_sha256: mediaEventVersion(projectEvent(event)),
      ...sessionImageDescriptor(event, reference.part_index) })
    if (mediaEventVersion(actual) !== mediaEventVersion(reference)) throw new ProbeError('file.export_changed')
    signal.throwIfAborted(); current()
    return actual
  } finally { await source.close() }
}
