import { z } from 'zod'

export const QUESTION_REFERENCES_CAPABILITY = 'question.references.v1'
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const time = z.iso.datetime({ offset: true })
const identity = { question_id: uuid, session_id: uuid }
export const questionReference = z.union([
  z.strictObject({ ...identity, kind: z.literal('question'), state: z.literal('pending'), expires_at: time }),
  z.strictObject({ ...identity, kind: z.literal('timed_question'), state: z.literal('pending'), expires_at: time.nullable() }),
  z.strictObject({ ...identity, kind: z.literal('timed_question'), state: z.enum(['continued', 'reply_queued']), expires_at: z.null() }),
])
const envelope = { v: z.literal(1), request_id: uuid, runtime_id: uuid, runtime_epoch: uuid }
export const questionReferencesFrame = z.strictObject({ ...envelope, type: z.literal('question.references'), payload: z.strictObject({
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), items: z.array(questionReference).max(128),
}) })
export const questionReferencesAck = z.strictObject({ ...envelope, type: z.literal('question.references.ack'), payload: z.strictObject({
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), item_count: z.number().int().min(0).max(128),
}) })
export type QuestionReference = z.infer<typeof questionReference>
export interface LocalQuestionReference { nativeSessionId: string; reference: QuestionReference }
export interface QuestionReferenceSource {
  references(): LocalQuestionReference[]
  watchReferences(changed: () => void): () => void
}
