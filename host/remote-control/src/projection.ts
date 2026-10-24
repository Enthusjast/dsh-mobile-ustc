import type { SessionWireEvent } from '@deepseek-ai/dsh-api-session-controller/types'

const fields: Record<string, readonly string[]> = {
  'turn/start': ['turn'], 'turn/end': ['turn', 'reason'],
  'step/start': ['turn', 'step'], 'step/end': ['turn', 'step'],
  'tool/call': ['turn', 'step', 'callId', 'name', 'arguments'],
  'approval/asked': ['id', 'toolName', 'callId', 'reason'], 'approval/decided': ['id', 'outcome'],
}

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}
function pick(value: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  return Object.fromEntries(keys.filter(key => value[key] !== undefined).map(key => [key, value[key]]))
}
function content(value: unknown): unknown[] {
  if (!Array.isArray(value)) return []
  return value.flatMap(part => {
    const block = object(part)
    if (block.type === 'text') return [pick(block, ['type', 'text'])]
    if (block.type === 'reasoning') return [pick(block, ['type', 'text'])]
    return []
  })
}

/** Explicit display projection. Unknown/configuration events advance the cursor without exporting data. */
export function projectEvent(event: SessionWireEvent) {
  const data = object(event.data)
  const source = object(data.source)
  const humanInput = source.kind === 'user' || (source.kind === 'user-question-reply' && source.outcome === 'answered'
    && typeof source.callId === 'string' && source.callId.length > 0)
  let projected: Record<string, unknown> = {}
  if (fields[event.type]) projected = pick(data, fields[event.type]!)
  // Native user-role messages also carry producer-injected context. Only the
  // explicit human input and answered native question replies belong in the
  // phone transcript. Other producers advance the cursor without a body.
  if (event.type === 'user/message' && humanInput) projected = { ...pick(data, ['id']), content: content(data.content) }
  if (event.type === 'assistant/message' || event.type === 'tool/result') {
    const message = object(data.message)
    projected = { ...pick(data, ['turn', 'step', 'interrupted']), message: { ...pick(message, ['id', 'callId', 'isError']), content: content(message.content) } }
  }
  if (event.type === 'assistant/attempt') projected = { ...pick(data, ['turn', 'step']), stream: projectStream(data.stream) }
  const visible = Object.keys(projected).length > 0
  return {
    native_seq: event.seq, time: event.time, type: visible ? event.type : 'cursor', data: projected,
    ...(visible && event.surfaceOp !== undefined ? { surface_op: event.surfaceOp } : {}),
    ...(visible && event.sourceEventSeqs !== undefined ? { source_event_seqs: event.sourceEventSeqs } : {}),
  }
}

/** Discard provider replay metadata and extension fields even inside assistant stream records. */
export function projectChunk(value: unknown): Record<string, unknown> {
  const chunk = object(value)
  const allowed: Record<string, readonly string[]> = {
    'block-start': ['type', 'index', 'blockType'], 'text-delta': ['type', 'index', 'text'],
    'reasoning-delta': ['type', 'index', 'text'], 'tool-call-delta': ['type', 'index', 'id', 'name', 'argumentsDelta'],
    'usage': ['type', 'usage'], 'finish': ['type', 'reason'],
  }
  if (chunk.type === 'block-end') {
    const block = object(chunk.block)
    return { ...pick(chunk, ['type', 'index']), block: pick(block, ['type', 'text', 'id', 'name', 'arguments']) }
  }
  return pick(chunk, allowed[String(chunk.type)] ?? ['type'])
}

export function projectStream(value: unknown): unknown[] {
  if (!Array.isArray(value)) return []
  return value.map(item => {
    const record = object(item)
    return record.type === 'chunk' ? { type: 'chunk', time: record.time, chunk: projectChunk(record.chunk) }
      : pick(record, ['type', 'time0', 'index', 'dt', 'texts', 'id', 'name', 'args'])
  })
}
