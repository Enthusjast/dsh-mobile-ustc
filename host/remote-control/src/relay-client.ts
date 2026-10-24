import { createHash, randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { setTimeout as delay } from 'node:timers/promises'
import { z } from 'zod'
import type { CommandOwner, CommandState } from './command-journal.js'
import type { SessionCatalogChange, SessionCatalogItem } from './dsh-client.js'
import { parseCommand, ProbeError, type Command } from './protocol.js'
import type { CommandStateObserver } from './runtime.js'
import { RelaySessions, type SessionReaderRuntime } from './relay-sessions.js'
import { questionAnswerPayload } from './questions.js'
import { APPROVAL_INVALIDATION_CAPABILITY, SIGNED_APPROVAL_CAPABILITY } from './approval-protocol.js'
import type { HostApprovalPeer, HostApprovalPeerFactory } from './relay-approvals.js'

const MAX_FRAME_BYTES = 64 * 1024
const MAX_BUFFERED_BYTES = 512 * 1024
const PROTOCOL = 'dsh.remote.v1'
const PROOF_TYPE = 'dsh-relay-handshake-proof+jwt'
const AUDIENCE = 'urn:dsh-mobile-ustc:realtime'
const capabilities = ['command.relay.v1', 'connection.heartbeat.v1', 'question.blocking.v1', 'question.timed.v1', 'session.cancel.v1', 'session.catalog.v1', 'session.create.v1', 'session.read.v1'] as const
const requiredCapabilities = ['command.relay.v1', 'connection.heartbeat.v1'] as const
const uuid = z.uuid()
const nonEmptyText = z.string().min(1).max(32_768).regex(/\S/).refine(text => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text))

const challengeSchema = z.strictObject({
  v: z.literal(1),
  type: z.literal('challenge'),
  payload: z.strictObject({
    connection_id: uuid,
    challenge_id: uuid,
    nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    role: z.literal('installation'),
    expires_at: z.string().datetime({ offset: true }),
  }),
})
const helloOkSchema = z.strictObject({
  v: z.literal(1),
  type: z.literal('hello.ok'),
  payload: z.strictObject({
    role: z.literal('host'),
    connection_id: uuid,
    installation_id: uuid,
    runtime_id: uuid,
    runtime_epoch: uuid,
    protocol_version: z.number().int().min(1),
    protocols: z.array(z.number().int()).min(1),
    capabilities: z.array(z.string()),
    server_time: z.string().datetime({ offset: true }),
    heartbeat_seconds: z.number().int().positive(),
    max_frame_bytes: z.number().int().positive(),
    lease_expires_at: z.string().datetime({ offset: true }),
  }),
})
const sessionCatalogAckSchema = z.strictObject({
  v: z.literal(1),
  type: z.literal('session.catalog.ack'),
  request_id: uuid,
  runtime_id: uuid,
  runtime_epoch: uuid,
  payload: z.strictObject({ session_count: z.number().int().min(0).max(20_000), server_time: z.string().datetime({ offset: true }) }),
})
const submitSchema = z.strictObject({
  v: z.literal(1),
  type: z.literal('message.submit'),
  request_id: uuid,
  runtime_id: uuid,
  runtime_epoch: uuid,
  session_id: uuid,
  user_id: uuid,
  device_id: uuid,
  payload_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  payload: z.strictObject({
    mode: z.enum(['queue', 'steer']),
    content: z.array(z.strictObject({ type: z.literal('text'), text: nonEmptyText })).min(1).max(16),
  }),
})
const cancelSchema = submitSchema.extend({ type: z.literal('session.cancel'), payload: z.strictObject({}) })
const questionSchema = submitSchema.extend({ type: z.literal('question.answer'), payload: questionAnswerPayload })
const timedQuestionSchema = submitSchema.extend({ type: z.literal('question.timed.answer'), payload: questionAnswerPayload })
const createSchema = submitSchema.omit({ session_id: true }).extend({
  type: z.literal('session.create'), payload: z.strictObject({ workspace_id: uuid, preset: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/) }),
})
const forwardedCommandSchema = z.discriminatedUnion('type', [submitSchema, cancelSchema, createSchema, questionSchema, timedQuestionSchema])
type ForwardedCommand = z.infer<typeof forwardedCommandSchema>
const catalogItemSchema = z.strictObject({
  session_id: uuid,
  dsh_session_id: z.string().min(1).refine(value => Buffer.byteLength(value) <= 2048 && !value.includes('\0')),
  workspace_id: uuid.nullable(),
  state: z.enum(['available', 'running', 'archived', 'unavailable']),
  last_persisted_seq: z.number().int().min(-1),
})

export interface HostHandshakeSigner {
  /** Sign the JWS signing input with the registered P-256 key and return 64-byte IEEE-P1363 r||s. */
  sign(signingInput: Uint8Array): Promise<Uint8Array> | Uint8Array
}

export interface HostConnectionCredential {
  installationId: string
  credential: string
  signer: HostHandshakeSigner
}

/** The provider owns key storage and may refresh the short-lived REST credential before each connect. */
export interface HostCredentialProvider {
  acquire(signal: AbortSignal): Promise<HostConnectionCredential>
}

export interface HostRelayOptions {
  url: string
  runtime: {
    epoch: string
    client: {
      runtimeId: string
      sessionCatalog(signal: AbortSignal, sessionIds?: readonly string[]): Promise<SessionCatalogItem[]>
      watchSessionCatalog(onChange: (change: SessionCatalogChange) => void): () => void
    }
    dispatch(command: Command, signal: AbortSignal, owner: CommandOwner, observe?: CommandStateObserver): Promise<unknown>
    follow: SessionReaderRuntime['follow']
    claimQuestion?: SessionReaderRuntime['claimQuestion']
  }
  credentials: HostCredentialProvider
  dshVersion: string
  applicationVersion: string
  pluginVersion: string
  approvals?: HostApprovalPeerFactory
}

interface RelaySocket {
  readyState: number
  bufferedAmount: number
  send(data: string, callback: (error?: Error) => void): void
  close(code?: number, reason?: string): void
  terminate(): void
  on(event: string, listener: (...args: any[]) => void): this
  once(event: string, listener: (...args: any[]) => void): this
  off(event: string, listener: (...args: any[]) => void): this
}

const WebSocketClient = createRequire(import.meta.url)('ws') as new (
  url: string,
  protocols: string[],
  options: Record<string, unknown>,
) => RelaySocket

class IncomingFrames {
  private readonly frames: Buffer[] = []
  private waiter: { resolve(frame: Buffer): void; reject(error: Error): void; timer: NodeJS.Timeout } | undefined
  private ended: Error | undefined
  private readonly onMessage = (data: unknown, binary: boolean) => {
    if (binary) return this.end(new Error('Relay sent a binary frame'))
    let frame: Buffer
    try { frame = rawData(data) } catch (error) { return this.end(asError(error)) }
    if (frame.length > MAX_FRAME_BYTES) return this.end(new Error('Relay frame exceeded the size limit'))
    if (this.waiter) {
      const waiter = this.waiter
      this.waiter = undefined
      clearTimeout(waiter.timer)
      waiter.resolve(frame)
    } else {
      this.frames.push(frame)
      if (this.frames.length > 32) this.end(new Error('Relay frame queue exceeded the limit'))
    }
  }
  private readonly onClose = () => this.end(new Error('Relay connection closed'))
  private readonly onError = (error: unknown) => this.end(asError(error))

  constructor(private readonly socket: RelaySocket, private readonly signal: AbortSignal) {
    socket.on('message', this.onMessage)
    socket.on('close', this.onClose)
    socket.on('error', this.onError)
    signal.addEventListener('abort', this.onClose, { once: true })
  }

  next(timeoutMs: number): Promise<Buffer> {
    const buffered = this.frames.shift()
    if (buffered) return Promise.resolve(buffered)
    if (this.ended) return Promise.reject(this.ended)
    return new Promise((resolve, reject) => {
      if (this.waiter) return reject(new Error('Concurrent Relay frame reads are not supported'))
      const timer = setTimeout(() => {
        this.waiter = undefined
        reject(new Error('Relay frame timed out'))
      }, timeoutMs)
      timer.unref()
      this.waiter = { resolve, reject, timer }
    })
  }

  close(): void {
    this.socket.off('message', this.onMessage)
    this.socket.off('close', this.onClose)
    this.socket.off('error', this.onError)
    this.signal.removeEventListener('abort', this.onClose)
    this.end(new Error('Relay frame reader closed'))
  }

  private end(error: Error): void {
    if (this.ended) return
    this.ended = error
    if (this.waiter) {
      clearTimeout(this.waiter.timer)
      this.waiter.reject(error)
      this.waiter = undefined
    }
  }
}

function rawData(data: unknown): Buffer {
  if (Buffer.isBuffer(data)) return data
  if (data instanceof ArrayBuffer) return Buffer.from(data)
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  if (Array.isArray(data) && data.every(Buffer.isBuffer)) return Buffer.concat(data)
  throw new Error('Relay returned an unsupported frame type')
}

function asError(error: unknown): Error { return error instanceof Error ? error : new Error('Relay transport failed') }

function parseFrame(data: Buffer): unknown {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)) }
  catch { throw new ProbeError('protocol.invalid') }
}

function sendFrame(socket: RelaySocket, value: unknown): Promise<void> {
  const encoded = JSON.stringify(value)
  if (Buffer.byteLength(encoded) > MAX_FRAME_BYTES || socket.readyState !== 1 || socket.bufferedAmount + Buffer.byteLength(encoded) > MAX_BUFFERED_BYTES) {
    return Promise.reject(new ProbeError('protocol.resync_required'))
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.terminate(); reject(new ProbeError('protocol.resync_required')) }, 5000)
    timer.unref()
    socket.send(encoded, error => { clearTimeout(timer); if (error) reject(error); else resolve() })
  })
}

function splitSessionCatalog(mode: 'snapshot' | 'delta', runtimeId: string, runtimeEpoch: string, snapshotId: string, items: SessionCatalogItem[]): SessionCatalogItem[][] {
  if (items.length > 20_000) throw new ProbeError('rate.limited')
  const chunks: SessionCatalogItem[][] = []
  let current: SessionCatalogItem[] = []
  for (const item of items) {
    if (!catalogItemSchema.safeParse(item).success) throw new ProbeError('protocol.invalid')
    const candidate = [...current, item]
    const probe = {
      v: 1, type: 'session.catalog', request_id: snapshotId, runtime_id: runtimeId, runtime_epoch: runtimeEpoch,
      payload: { mode, index: chunks.length, complete: false, items: candidate },
    }
    if (candidate.length > 256 || Buffer.byteLength(JSON.stringify(probe)) > MAX_FRAME_BYTES - 1024) {
      if (current.length === 0) throw new ProbeError('protocol.frame_too_large')
      chunks.push(current)
      current = [item]
    } else current = candidate
  }
  if (current.length > 0 || chunks.length === 0) chunks.push(current)
  return chunks
}

function endpoint(value: string): string {
  const url = new URL(value)
  if (url.username || url.password || url.search || url.hash) throw new Error('Relay URL cannot contain credentials, query, or fragment')
  if (url.protocol === 'https:') url.protocol = 'wss:'
  else if (url.protocol === 'http:') url.protocol = 'ws:'
  if (url.protocol !== 'wss:' && url.protocol !== 'ws:') throw new Error('Relay URL must use HTTPS or WSS')
  if (url.protocol === 'ws:' && !isLoopback(url.hostname)) throw new Error('Plain WebSocket is only allowed for loopback development')
  if (url.pathname === '/' || url.pathname === '') url.pathname = '/v1/realtime'
  if (url.pathname !== '/v1/realtime') throw new Error('Relay URL path must be /v1/realtime')
  return url.toString()
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(hostname)
}

function validateCredential(value: HostConnectionCredential): void {
  if (!uuid.safeParse(value.installationId).success || !/^[A-Za-z0-9_-]{43}$/.test(value.credential)
    || typeof value.signer?.sign !== 'function') throw new ProbeError('auth.proof_invalid')
}

function jcs(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(jcs)
  if (value === null || typeof value !== 'object') return value
  const record = value as Record<string, unknown>
  return Object.fromEntries(Object.keys(record).sort().map(key => [key, jcs(record[key])]))
}

function forwardedDigest(sessionId: string, payload: z.infer<typeof submitSchema>['payload']): string {
  const canonical = JSON.stringify(jcs({ type: 'message.submit', session_id: sessionId, payload }))
  return createHash('sha256').update(canonical).digest('hex')
}

/** Build and validate the Relay host hello; exported so golden tests can pin the Go/Node digest. */
export function hostHelloDigest(parts: readonly string[]): string {
  const hash = createHash('sha256')
  hash.update(Buffer.from('dsh-mobile-ustc/relay-hello/v1\0'))
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8')
    const size = Buffer.alloc(4)
    size.writeUInt32BE(bytes.length)
    hash.update(size).update(bytes)
  }
  return hash.digest('base64url')
}

function encodeJwsPart(value: unknown): string { return Buffer.from(JSON.stringify(value)).toString('base64url') }

async function proofForHello(
  credential: HostConnectionCredential,
  challenge: z.infer<typeof challengeSchema>['payload'],
  runtimeId: string,
  runtimeEpoch: string,
  versions: Pick<HostRelayOptions, 'dshVersion' | 'applicationVersion' | 'pluginVersion'>,
  offered: readonly string[] = capabilities,
): Promise<string> {
  const helloDigest = hostHelloDigest([
    'host', runtimeId, runtimeEpoch, versions.dshVersion, versions.applicationVersion,
    versions.pluginVersion, '1', [...offered].sort().join('\n'),
  ])
  const header = encodeJwsPart({ typ: PROOF_TYPE, alg: 'ES256' })
  const payload = encodeJwsPart({
    iss: credential.installationId,
    aud: AUDIENCE,
    challenge_id: challenge.challenge_id,
    connection_id: challenge.connection_id,
    nonce: challenge.nonce,
    runtime_id: runtimeId,
    runtime_epoch: runtimeEpoch,
    hello_sha256: helloDigest,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
  })
  const signingInput = `${header}.${payload}`
  const signature = await credential.signer.sign(Buffer.from(signingInput, 'utf8'))
  if (signature.byteLength !== 64) throw new ProbeError('auth.proof_invalid')
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`
}

function parseForwarded(data: unknown, runtimeId: string, runtimeEpoch: string): ForwardedCommand {
  const parsed = forwardedCommandSchema.safeParse(data)
  if (!parsed.success || parsed.data.runtime_id !== runtimeId || parsed.data.runtime_epoch !== runtimeEpoch
    || (parsed.data.type === 'session.cancel'
      ? relayCancelDigest(parsed.data.session_id, parsed.data.runtime_epoch)
      : parsed.data.type === 'question.answer'
        ? relayQuestionDigest(parsed.data.session_id, parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'question.timed.answer'
        ? relayTimedQuestionDigest(parsed.data.session_id, parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'session.create'
        ? relayCreateDigest(parsed.data.runtime_epoch, parsed.data.payload)
        : forwardedDigest(parsed.data.session_id, parsed.data.payload)) !== parsed.data.payload_sha256) {
    throw new ProbeError('protocol.invalid')
  }
  return parsed.data
}

function makeCommand(frame: ForwardedCommand): Command {
  return parseCommand({
    v: 0,
    type: frame.type,
    request_id: frame.request_id,
    runtime_epoch: frame.runtime_epoch,
    ...('session_id' in frame ? { session_id: frame.session_id } : {}),
    payload: frame.payload,
  })
}

async function waitForOpen(socket: RelaySocket, signal: AbortSignal): Promise<void> {
  if (socket.readyState === 1) return
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error('Relay connection timed out')), 15_000)
    timeout.unref()
    const opened = () => finish()
    const closed = () => finish(new Error('Relay closed during handshake'))
    const errored = (error: unknown) => finish(asError(error))
    const aborted = () => finish(new Error('Relay connection aborted'))
    const finish = (error?: Error) => {
      clearTimeout(timeout)
      socket.off('open', opened)
      socket.off('close', closed)
      socket.off('error', errored)
      signal.removeEventListener('abort', aborted)
      if (error) reject(error)
      else resolve()
    }
    socket.once('open', opened)
    socket.once('close', closed)
    socket.once('error', errored)
    signal.addEventListener('abort', aborted, { once: true })
    if (signal.aborted) aborted()
  })
}

async function receiveFrame(queue: IncomingFrames, timeoutMs: number): Promise<unknown> {
  return parseFrame(await queue.next(timeoutMs))
}

async function connectOnce(options: HostRelayOptions, url: string, credential: HostConnectionCredential, signal: AbortSignal): Promise<void> {
  validateCredential(credential)
  const socket = new WebSocketClient(url, [PROTOCOL], {
    headers: { Authorization: `DSH-Host ${credential.credential}` },
    handshakeTimeout: 15_000,
    maxPayload: MAX_FRAME_BYTES,
    perMessageDeflate: false,
  })
  const connection = new AbortController()
  let stopWatchingCatalog = () => {}
  let catalogRetryTimer: NodeJS.Timeout | undefined
  let sessions: RelaySessions | undefined
  let approvals: HostApprovalPeer | undefined
  const abortConnection = () => {
    connection.abort()
    socket.terminate()
  }
  signal.addEventListener('abort', abortConnection, { once: true })
  const queue = new IncomingFrames(socket, connection.signal)
  try {
    await waitForOpen(socket, connection.signal)
    const challengeEnvelope = challengeSchema.safeParse(await receiveFrame(queue, 15_000))
    if (!challengeEnvelope.success || Date.parse(challengeEnvelope.data.payload.expires_at) <= Date.now()) {
      throw new ProbeError('auth.proof_invalid')
    }
    const challenge = challengeEnvelope.data.payload
    const offered = options.approvals ? [...capabilities, SIGNED_APPROVAL_CAPABILITY, APPROVAL_INVALIDATION_CAPABILITY] : [...capabilities]
    const proof = await proofForHello(credential, challenge, options.runtime.client.runtimeId, options.runtime.epoch, options, offered)
    await sendFrame(socket, {
      v: 1,
      type: 'hello.proof',
      payload: {
        proof,
        runtime_id: options.runtime.client.runtimeId,
        runtime_epoch: options.runtime.epoch,
        dsh_version: options.dshVersion,
        application_version: options.applicationVersion,
        plugin_version: options.pluginVersion,
        protocol_version: 1,
        capabilities: offered,
      },
    })
    const ack = helloOkSchema.safeParse(await receiveFrame(queue, 15_000))
    if (!ack.success || ack.data.payload.connection_id !== challenge.connection_id
      || ack.data.payload.installation_id !== credential.installationId
      || ack.data.payload.runtime_id !== options.runtime.client.runtimeId
      || ack.data.payload.runtime_epoch !== options.runtime.epoch
      || ack.data.payload.protocol_version !== 1 || !ack.data.payload.protocols.includes(1)
      || ack.data.payload.max_frame_bytes > MAX_FRAME_BYTES || Date.parse(ack.data.payload.lease_expires_at) <= Date.now()
      || !requiredCapabilities.every(capability => ack.data.payload.capabilities.includes(capability))) {
      throw new ProbeError('protocol.unsupported')
    }

    if (options.approvals && (![SIGNED_APPROVAL_CAPABILITY,APPROVAL_INVALIDATION_CAPABILITY,'session.catalog.v1'].every(capability=>ack.data.payload.capabilities.includes(capability)))) throw new ProbeError('protocol.unsupported')

    const catalogEnabled = ack.data.payload.capabilities.includes('session.catalog.v1')
    if (ack.data.payload.capabilities.includes('session.read.v1')) sessions = new RelaySessions({
      epoch: options.runtime.epoch, client: options.runtime.client,
      follow: (command, signal) => options.runtime.follow(command, signal),
      dispatch: (command, signal) => options.runtime.dispatch(command, signal, { userId: 'relay-read', deviceId: 'relay-read' }),
      ...(options.runtime.claimQuestion ? { claimQuestion: (sessionId: string, questionId: string, signal: AbortSignal) => options.runtime.claimQuestion!(sessionId, questionId, signal) } : {}),
    }, frame => sendFrame(socket, frame), ack.data.payload.capabilities.includes('question.timed.v1'))
    const pendingCatalogAcks = new Map<string, { count: number; resolve(): void; reject(error: Error): void }>()
    let catalogRefresh: Promise<void> | undefined
    let catalogDirty = false
    let snapshotRequested = true
    const deltaSessionIDs = new Set<string>()
    const catalogBarriers = new Set<{ nativeId: string; resolve(): void; reject(error: Error): void }>()
    const waitForCatalogAck = (snapshotId: string, count: number) => new Promise<void>((resolve, reject) => {
      let timer: NodeJS.Timeout
      const aborted = () => entry.reject(new Error('Relay connection aborted'))
      const cleanup = () => {
        clearTimeout(timer)
        connection.signal.removeEventListener('abort', aborted)
        pendingCatalogAcks.delete(snapshotId)
      }
      const entry = {
        count,
        resolve: () => { cleanup(); resolve() },
        reject: (error: Error) => { cleanup(); reject(error) },
      }
      timer = setTimeout(() => entry.reject(new Error('Relay session catalog acknowledgement timed out')), 15_000)
      timer.unref()
      pendingCatalogAcks.set(snapshotId, entry)
      connection.signal.addEventListener('abort', aborted, { once: true })
      if (connection.signal.aborted) aborted()
    })
    const startCatalogRefresh = () => {
      if (!catalogEnabled || catalogRefresh) return
      catalogRefresh = (async () => {
        while (catalogDirty && !connection.signal.aborted) {
          catalogDirty = false
          const mode = snapshotRequested ? 'snapshot' : 'delta'
          const sessionIDs = mode === 'snapshot' ? undefined : [...deltaSessionIDs]
          snapshotRequested = false
          deltaSessionIDs.clear()
          const items = await options.runtime.client.sessionCatalog(connection.signal, sessionIDs)
          if (mode === 'delta' && items.length === 0) continue
          const snapshotId = randomUUID()
          const chunks = splitSessionCatalog(mode, options.runtime.client.runtimeId, options.runtime.epoch, snapshotId, items)
          const acknowledged = waitForCatalogAck(snapshotId, items.length)
          // A failed write can end this task before it reaches the acknowledgement.
          void acknowledged.catch(() => {})
          try {
            for (let index = 0; index < chunks.length; index++) {
              await sendFrame(socket, {
                v: 1,
                type: 'session.catalog',
                request_id: snapshotId,
                runtime_id: options.runtime.client.runtimeId,
                runtime_epoch: options.runtime.epoch,
                payload: { mode, index, complete: index === chunks.length - 1, items: chunks[index] },
              })
            }
            await acknowledged
            for (const barrier of [...catalogBarriers]) {
              const item = items.find(item => item.dsh_session_id === barrier.nativeId)
              if (item) {
                if (item.state === 'unavailable' || !item.workspace_id) barrier.reject(new ProbeError('access.denied'))
                else barrier.resolve()
              }
            }
          } finally {
            pendingCatalogAcks.get(snapshotId)?.reject(new Error('Relay catalog publication ended'))
          }
          if (catalogRetryTimer) clearTimeout(catalogRetryTimer)
          catalogRetryTimer = undefined
        }
      })().finally(() => {
        catalogRefresh = undefined
        if (catalogDirty && !connection.signal.aborted) startCatalogRefresh()
      })
      void catalogRefresh.catch(scheduleCatalogRetry)
    }
    const scheduleCatalogRetry = () => {
      if (!catalogEnabled || catalogRetryTimer || connection.signal.aborted) return
      catalogRetryTimer = setTimeout(() => {
        catalogRetryTimer = undefined
        requestCatalogRefresh({ kind: 'snapshot' })
      }, 30_000)
      catalogRetryTimer.unref()
    }
    const requestCatalogRefresh = (change: SessionCatalogChange = { kind: 'snapshot' }) => {
      if (change.kind === 'snapshot') {
        snapshotRequested = true
        deltaSessionIDs.clear()
      } else if (!snapshotRequested) {
        for (const sessionId of change.sessionIds) deltaSessionIDs.add(sessionId)
      }
      catalogDirty = true
      startCatalogRefresh()
      catalogRefresh?.catch(scheduleCatalogRetry)
    }
    stopWatchingCatalog = catalogEnabled
      ? options.runtime.client.watchSessionCatalog(requestCatalogRefresh)
      : () => {}
    if (catalogEnabled) requestCatalogRefresh()

    if (options.approvals) approvals = options.approvals({
      installationId: credential.installationId, connectionId: ack.data.payload.connection_id, signal: connection.signal,
      send: frame => sendFrame(socket, frame), fail: abortConnection,
      publishCatalog: (nativeId, signal) => new Promise<void>((resolve, reject) => {
        if (catalogBarriers.size >= 64 || connection.signal.aborted || signal.aborted) { reject(new ProbeError('runtime.offline')); return }
        const lifetime = AbortSignal.any([connection.signal, signal])
        const abort = () => barrier.reject(new ProbeError('runtime.offline'))
        const cleanup = () => { catalogBarriers.delete(barrier); lifetime.removeEventListener('abort', abort) }
        const barrier = { nativeId, resolve: () => { cleanup(); resolve() }, reject: (error: Error) => { cleanup(); reject(error) } }
        catalogBarriers.add(barrier); lifetime.addEventListener('abort', abort, { once: true })
        requestCatalogRefresh({ kind: 'delta', sessionIds: [nativeId] })
      }),
    })

    const handleFrame = async (value: unknown) => {
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        const frame = value as Record<string, unknown>
        if (approvals && await approvals.handle(value)) return
        if (frame.v === 1 && frame.type === 'pong') return
        if (frame.type === 'session.catalog.ack') {
          const parsed = sessionCatalogAckSchema.safeParse(value)
          if (!parsed.success || parsed.data.runtime_id !== options.runtime.client.runtimeId
            || parsed.data.runtime_epoch !== options.runtime.epoch) throw new ProbeError('protocol.invalid')
          const pending = pendingCatalogAcks.get(parsed.data.request_id)
          if (pending && pending.count !== parsed.data.payload.session_count) throw new ProbeError('protocol.invalid')
          pending?.resolve()
          return
        }
        if (frame.type === 'error') {
          const requestId = typeof frame.request_id === 'string' ? frame.request_id : ''
          pendingCatalogAcks.get(requestId)?.reject(new ProbeError(String((frame.payload as { code?: unknown } | undefined)?.code ?? 'internal')))
          return
        }
        if (frame.v === 1 && frame.type === 'server.draining') {
          socket.close(1012, 'server draining')
          return
        }
        if (sessions?.handle(value)) return
        const forwarded = parseForwarded(value, options.runtime.client.runtimeId, options.runtime.epoch)
        if (forwarded.type === 'session.cancel' && !ack.data.payload.capabilities.includes('session.cancel.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'session.create' && !ack.data.payload.capabilities.includes('session.create.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'question.answer' && !ack.data.payload.capabilities.includes('question.blocking.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'question.timed.answer' && !ack.data.payload.capabilities.includes('question.timed.v1')) throw new ProbeError('protocol.unsupported')
        const command = makeCommand(forwarded)
        const owner: CommandOwner = { userId: forwarded.user_id, deviceId: forwarded.device_id }
        let reported: CommandState | undefined
        const observe: CommandStateObserver = async (state: CommandState, result?: unknown) => {
          reported = state
          let item: z.infer<typeof catalogItemSchema> | undefined
          if (forwarded.type === 'session.create' && state === 'settled') {
            const parsed = catalogItemSchema.safeParse((result as { catalog_item?: unknown } | undefined)?.catalog_item)
            if (!parsed.success || parsed.data.workspace_id !== forwarded.payload.workspace_id || (parsed.data.state !== 'available' && parsed.data.state !== 'running')) throw new ProbeError('journal.integrity_failed')
            item = parsed.data
          }
          await sendFrame(socket, {
            v: 1,
            type: 'command.receipt',
            request_id: forwarded.request_id,
            runtime_id: forwarded.runtime_id,
            runtime_epoch: forwarded.runtime_epoch,
            ...('session_id' in forwarded ? { session_id: forwarded.session_id } : item ? { session_id: item.session_id } : {}),
            device_id: forwarded.device_id,
            payload: {
              state, payload_sha256: forwarded.payload_sha256,
              ...(forwarded.type === 'session.create' ? { workspace_id: forwarded.payload.workspace_id } : {}),
              ...(item ? { created_session: item } : {}),
            },
          })
        }
        try { await options.runtime.dispatch(command, connection.signal, owner, observe) }
        catch (error) {
          // A durably rejected/uncertain operation already has a receipt. It
          // must not tear down unrelated subscriptions on the same transport.
          if (reported !== 'rejected' && reported !== 'outcome_unknown') throw error
        }
        return
      }
      throw new ProbeError('protocol.invalid')
    }

    const reader = (async () => {
      while (!connection.signal.aborted) {
        const value = await receiveFrame(queue, 40_000)
        await handleFrame(value)
      }
    })()
    const heartbeat = setInterval(() => {
      void sendFrame(socket, { v: 1, type: 'ping', payload: {} }).catch(() => socket.close(1011, 'send failed'))
    }, ack.data.payload.heartbeat_seconds * 1000)
    heartbeat.unref()
    try { await reader }
    finally { clearInterval(heartbeat) }
  } finally {
    approvals?.close()
    sessions?.close()
    if (catalogRetryTimer) clearTimeout(catalogRetryTimer)
    stopWatchingCatalog()
    signal.removeEventListener('abort', abortConnection)
    connection.abort()
    queue.close()
    if (socket.readyState === 1) socket.close(1000, 'connection ended')
    else if (socket.readyState < 2) socket.terminate()
  }
}

async function run(options: HostRelayOptions, url: string, signal: AbortSignal): Promise<void> {
  let backoffMs = 1_000
  while (!signal.aborted) {
    try {
      const credential = await withAbort(options.credentials.acquire(signal), signal)
      await connectOnce(options, url, credential, signal)
      backoffMs = 1_000
    } catch {
      if (signal.aborted) return
    }
    if (signal.aborted) return
    const spread = Math.floor(Math.random() * Math.max(1, backoffMs / 4))
    try { await delay(backoffMs + spread, undefined, { signal }) }
    catch { return }
    backoffMs = Math.min(backoffMs * 2, 60_000)
  }
}

function withAbort<Value>(promise: Promise<Value>, signal: AbortSignal): Promise<Value> {
  if (signal.aborted) return Promise.reject(new Error('Relay connection aborted'))
  return new Promise((resolve, reject) => {
    const aborted = () => {
      signal.removeEventListener('abort', aborted)
      reject(new Error('Relay connection aborted'))
    }
    signal.addEventListener('abort', aborted, { once: true })
    promise.then(value => {
      signal.removeEventListener('abort', aborted)
      resolve(value)
    }, error => {
      signal.removeEventListener('abort', aborted)
      reject(error)
    })
  })
}

export function startHostRelay(options: HostRelayOptions) {
  const url = endpoint(options.url)
  if ([options.applicationVersion, options.dshVersion, options.pluginVersion].some(value =>
    !value || value !== value.trim() || Buffer.byteLength(value) > 128 || /\p{Cc}/u.test(value))) {
    throw new Error('Relay version metadata must be non-empty, bounded, and contain no control characters')
  }
  if (!uuid.safeParse(options.runtime.client.runtimeId).success || !uuid.safeParse(options.runtime.epoch).success) {
    throw new Error('Relay runtime identity must use UUIDs')
  }
  const controller = new AbortController()
  const task = run(options, url, controller.signal).catch(() => {})
  return {
    async close() {
      controller.abort()
      await task
    },
  }
}

export function relayPayloadDigest(sessionId: string, payload: z.infer<typeof submitSchema>['payload']): string {
  return forwardedDigest(sessionId, payload)
}

export function relayCancelDigest(sessionId: string, runtimeEpoch: string): string {
  return createHash('sha256').update(JSON.stringify(jcs({ type: 'session.cancel', runtime_epoch: runtimeEpoch, session_id: sessionId, payload: {} }))).digest('hex')
}

export function relayCreateDigest(runtimeEpoch: string, payload: z.infer<typeof createSchema>['payload']): string {
  return createHash('sha256').update(JSON.stringify(jcs({ type: 'session.create', runtime_epoch: runtimeEpoch, payload }))).digest('hex')
}

export function relayQuestionDigest(sessionId: string, runtimeEpoch: string, payload: z.infer<typeof questionAnswerPayload>): string {
  return createHash('sha256').update(JSON.stringify(jcs({ type: 'question.answer', runtime_epoch: runtimeEpoch, session_id: sessionId, payload }))).digest('hex')
}

export function relayTimedQuestionDigest(sessionId: string, runtimeEpoch: string, payload: z.infer<typeof questionAnswerPayload>): string {
  return createHash('sha256').update(JSON.stringify(jcs({ type: 'question.timed.answer', runtime_epoch: runtimeEpoch, session_id: sessionId, payload }))).digest('hex')
}
