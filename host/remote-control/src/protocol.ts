import { z } from 'zod'

export const MAX_FRAME_BYTES = 64 * 1024
export const MAX_QUEUE_BYTES = 512 * 1024
const uuid = z.uuid()
const base = { v: z.literal(0), request_id: uuid, runtime_epoch: uuid }
const session = { ...base, session_id: uuid }
const empty = z.strictObject({})
const command = <T extends string, P extends z.ZodType>(type: T, payload: P) =>
  z.strictObject({ ...base, type: z.literal(type), payload })
const sessionCommand = <T extends string, P extends z.ZodType>(type: T, payload: P) =>
  z.strictObject({ ...session, type: z.literal(type), payload })
const textContent = z.strictObject({ type: z.literal('text'), text: z.string().min(1).max(32_768).regex(/\S/) })

/** M0 local probe protocol. It is deliberately separate from mobile protocol v1. */
export const Command = z.discriminatedUnion('type', [
  command('session.list', empty),
  command('model.catalog', empty),
  command('session.create', z.strictObject({ workspace: z.string().min(1).max(128), preset: z.string().min(1).max(128) })),
  sessionCommand('message.submit', z.union([
    z.strictObject({ mode: z.enum(['queue', 'steer']), text: z.string().min(1).max(32_768).regex(/\S/) }),
    z.strictObject({ mode: z.enum(['queue', 'steer']), content: z.array(textContent).min(1).max(16) }),
  ])),
  sessionCommand('session.cancel', empty),
  sessionCommand('session.model.select', z.strictObject({
    provider: z.string().min(1).max(128), model: z.string().min(1).max(128), reasoning_effort: z.string().min(1).max(64).optional(),
  })),
  sessionCommand('session.subscribe', z.strictObject({ max_messages: z.int().min(1).max(100).default(30) })),
  sessionCommand('session.page', z.strictObject({
    sync_id: uuid, through_seq: z.int().min(-1), before_seq: z.int().min(0), max_messages: z.int().min(1).max(100).default(30),
  })),
  command('interaction.list', empty),
  command('interaction.answer', z.strictObject({
    interaction_id: uuid,
    answer: z.union([
      z.strictObject({ decision: z.enum(['allow_once', 'reject']) }),
      z.strictObject({ answers: z.array(z.strictObject({
        id: z.string().min(1).max(128), selected: z.array(z.string().max(4096)).max(32), custom: z.string().max(16_384).optional(),
      })).min(1).max(32) }),
    ]),
  })),
])
export type Command = z.infer<typeof Command>

export class ProbeError extends Error {
  constructor(public readonly code: string) { super(code) }
}

export function parseCommand(value: unknown): Command {
  const parsed = Command.safeParse(value)
  if (!parsed.success) throw new ProbeError('protocol.invalid')
  return parsed.data
}

export interface Frame {
  v: 0
  type: string
  runtime_epoch: string
  request_id?: string
  session_id?: string
  sync_id?: string
  payload: unknown
}

/** Fragment serialized JSON as base64 bytes; Unicode code points may cross fragments. */
export function encodeFrames(frame: Frame): string[] {
  const json = JSON.stringify(frame)
  const bytes = Buffer.from(json)
  if (bytes.length <= MAX_FRAME_BYTES) return [json + '\n']
  if (bytes.length > MAX_QUEUE_BYTES / 2) throw new ProbeError('protocol.snapshot_too_large')
  const size = 40 * 1024
  const count = Math.ceil(bytes.length / size)
  return Array.from({ length: count }, (_, index) => JSON.stringify({
    v: 0, type: 'fragment', runtime_epoch: frame.runtime_epoch,
    request_id: frame.request_id, session_id: frame.session_id, sync_id: frame.sync_id,
    payload: { type: frame.type, index, count, data: bytes.subarray(index * size, (index + 1) * size).toString('base64') },
  }) + '\n')
}
