/** Native user-role context is not necessarily human input. Keep export and display admission identical. */
export function isHumanInput(value: unknown): boolean {
  const source = value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
  return source.kind === 'user' || (source.kind === 'user-question-reply' && source.outcome === 'answered'
    && typeof source.callId === 'string' && source.callId.length > 0)
}
