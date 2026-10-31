import { performance } from 'node:perf_hooks'
import { z } from 'zod'

export const HOST_OBSERVATIONS_CAPABILITY = 'host.observations.v1'
export const HOST_JOURNAL_OBSERVATIONS_CAPABILITY = 'host.journal.observations.v1'
export const nativeOperations = ['checkpoint', 'cold_checkpoint', 'prompt', 'create', 'prompt_reconcile', 'journal_command', 'journal_approval'] as const
export function journalOperation(operation: string): boolean { return operation === 'journal_command' || operation === 'journal_approval' }
export const nativeResults = ['persisted', 'failed', 'unavailable', 'ok', 'error', 'cancelled'] as const
export const nativeBucketMicros = [1000, 5000, 10000, 50000, 100000, 300000, 500000, 1000000, 5000000, 10000000, 30000000, 60000000] as const
const MAX_COUNT = 1_000_000_000
const MAX_SUM = Number.MAX_SAFE_INTEGER
export type NativeOperation = typeof nativeOperations[number]
export type NativeResult = typeof nativeResults[number]
const observationUUID = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)

export function nativePair(operation: string, result: string): boolean {
  if (journalOperation(operation)) return result === 'persisted' || result === 'failed'
  return nativeOperations.includes(operation as NativeOperation) && (operation === 'checkpoint' || operation === 'cold_checkpoint'
    ? ['persisted', 'failed', 'unavailable'].includes(result) : ['ok', 'error', 'cancelled'].includes(result))
}

const seriesSchema = z.strictObject({ operation: z.enum(nativeOperations), result: z.enum(nativeResults),
  count: z.number().int().min(1).max(MAX_COUNT), sum_micros: z.number().int().min(0).max(MAX_SUM),
  buckets: z.array(z.number().int().min(0).max(MAX_COUNT)).length(nativeBucketMicros.length),
}).refine(series => nativePair(series.operation, series.result) && series.buckets.every((value, i) => value <= series.count && (i === 0 || value >= series.buckets[i - 1]!)))
export const hostObservationsPayload = z.strictObject({ connection_id: observationUUID, sequence: z.number().int().min(1).max(MAX_COUNT),
  dropped: z.number().int().min(0).max(MAX_COUNT), series: z.array(seriesSchema).max(19),
}).refine(value => new Set(value.series.map(item => `${item.operation}:${item.result}`)).size === value.series.length)
export const hostObservationsFrame = z.strictObject({ v: z.literal(1), type: z.literal('host.observations'), runtime_id: observationUUID, runtime_epoch: observationUUID, payload: hostObservationsPayload })
export type NativeObservationSeries = z.infer<typeof seriesSchema>

/** One bounded listener for the current authenticated connection. No IDs or errors enter it. */
export class NativeObservations {
  private listener: ((operation: NativeOperation, result: NativeResult, micros: number) => void) | undefined
  private journalEnabled = false
  constructor(private readonly clock: () => number = () => performance.now()) {}
  listen(listener: (operation: NativeOperation, result: NativeResult, micros: number) => void, journalEnabled = false): () => void {
    this.listener = listener
    this.journalEnabled = journalEnabled
    return () => { if (this.listener === listener) this.listener = undefined }
  }
  start(operation: NativeOperation): (result: NativeResult) => void {
    const listener = this.listener
    if (!listener || journalOperation(operation) && !this.journalEnabled) return () => {}
    let started: number
    try { started = this.clock() } catch { return () => {} }
    let finished = false
    return result => {
      if (finished || this.listener !== listener) return
      finished = true
      try { listener(operation, result, Math.round((this.clock() - started) * 1000)) } catch { /* Observation cannot affect execution. */ }
    }
  }
  async measure<T>(operation: NativeOperation, execute: () => Promise<T>, result: (value: T) => NativeResult = () => 'ok', signal?: AbortSignal): Promise<T> {
    const finish = this.start(operation)
    try { const value = await execute(); try { finish(result(value)) } catch {} return value }
    catch (error) { finish(operation === 'checkpoint' || operation === 'cold_checkpoint' ? 'failed' : signal?.aborted ? 'cancelled' : 'error'); throw error }
  }
}

/** Counters restart for each Relay connection; fixed cells aggregate all samples without a per-call queue. */
export class NativeObservationWindow {
  private readonly series = new Map<string, NativeObservationSeries>()
  private dropped = 0
  private sequence = 0
  version = 0
  record(operation: NativeOperation, result: NativeResult, micros: number): void {
    const key = `${operation}:${result}`
    const previous = this.series.get(key)
    if (!nativePair(operation, result) || !Number.isSafeInteger(micros) || micros < 0 || micros > MAX_SUM
      || (previous?.count ?? 0) >= MAX_COUNT || (previous?.sum_micros ?? 0) + micros > MAX_SUM) {
      if (this.dropped < MAX_COUNT) { this.dropped++; this.version++ }
      return
    }
    const cell = previous ?? { operation, result, count: 0, sum_micros: 0, buckets: nativeBucketMicros.map(() => 0) }
    cell.count++; cell.sum_micros += micros
    nativeBucketMicros.forEach((bound, i) => { if (micros <= bound) cell.buckets[i] = cell.buckets[i]! + 1 })
    this.series.set(key, cell); this.version++
  }
  snapshot(connectionId: string): z.infer<typeof hostObservationsPayload> | undefined {
    if (this.version === 0 || this.sequence >= MAX_COUNT) return undefined
    return { connection_id: connectionId, sequence: ++this.sequence, dropped: this.dropped,
      series: [...this.series.values()].sort((a, b) => `${a.operation}:${a.result}`.localeCompare(`${b.operation}:${b.result}`)).map(item => ({ ...item, buckets: [...item.buckets] })) }
  }
}

export function bindNativeObservations(source: NativeObservations, identity: { connectionId: string; runtimeId: string; epoch: string }, send: (frame: z.infer<typeof hostObservationsFrame>) => boolean, journalEnabled = false) {
  const window = new NativeObservationWindow()
  let sentVersion = 0
  let closed = false
  const dispose = source.listen((operation, result, micros) => window.record(operation, result, micros), journalEnabled)
  const flush = () => {
    if (closed || window.version === sentVersion) return
    const version = window.version
    const payload = window.snapshot(identity.connectionId)
    if (!payload) return
    try { if (send({ v: 1, type: 'host.observations', runtime_id: identity.runtimeId, runtime_epoch: identity.epoch, payload })) sentVersion = version } catch { /* Best effort, no business transport closure or retry queue. */ }
  }
  const timer = setInterval(flush, 5000); timer.unref()
  return { flush, close() { closed = true; clearInterval(timer); dispose() } }
}
