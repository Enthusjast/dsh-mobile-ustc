import { z } from 'zod'

const text = (max: number) => z.string().max(max).refine(value => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value))
export const questionAnswerPayload = z.strictObject({
  question_id: z.uuid(),
  answers: z.array(z.strictObject({
    id: text(128).min(1), selected: z.array(text(4096)).max(32), custom: text(16_384).optional(),
  })).min(1).max(32),
})
export const questionItem = z.strictObject({
  id: text(128).min(1), question: text(16_384).min(1), detail: text(65_536).optional(), header: text(128).optional(),
  options: z.array(z.strictObject({ label: text(4096).min(1), description: text(16_384).optional() })).max(32).optional(),
  multi_select: z.boolean().optional(),
  intent: z.strictObject({ kind: z.literal('plan-review'), approve: text(4096).min(1) }).optional(),
})
export interface BlockingQuestion {
  question_id: string
  expires_at: string
  questions: Array<z.infer<typeof questionItem>>
}
export interface QuestionSnapshot { revision: number; items: BlockingQuestion[] }
export interface QuestionSource {
  snapshot(sessionId: string): QuestionSnapshot
  watch(sessionId: string, changed: () => void): () => void
}
