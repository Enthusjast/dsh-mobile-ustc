import { createHash, randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { setTimeout as delay } from 'node:timers/promises'
import { z } from 'zod'
import type { CommandOwner, CommandState } from './command-journal.js'
import type { DshClient, SessionCatalogChange, SessionCatalogItem } from './dsh-client.js'
import { archivePayload, modelSelectionPayload, parseCommand, ProbeError, type Command } from './protocol.js'
import type { CommandStateObserver } from './runtime.js'
import { RelaySessions, type SessionReaderRuntime } from './relay-sessions.js'
import { questionAnswerPayload } from './questions.js'
import { APPROVAL_INVALIDATION_CAPABILITY, SIGNED_APPROVAL_CAPABILITY } from './approval-protocol.js'
import type { HostApprovalPeer, HostApprovalPeerFactory } from './relay-approvals.js'
import { QUESTION_REFERENCES_CAPABILITY } from './question-reference-protocol.js'
import type { HostQuestionReferences, QuestionReferenceBinding } from './relay-question-references.js'
import { CREATION_OPTIONS_CAPABILITY, creationOptionsSchema, type SessionCreationOptions } from './creation-options.js'
import { FILE_HANDOFF_CAPABILITY, FILE_MESSAGE_CAPABILITY, FILE_RECONCILE_CAPABILITY, fileReference } from './file-protocol.js'
import type { FileTransportBinding, HostFilePeer } from './relay-files.js'
import type { HostExportPeer } from './relay-exports.js'
import { EXPORT_CAPABILITY } from './export-protocol.js'
import { bindNativeObservations, HOST_OBSERVATIONS_CAPABILITY, type NativeObservations } from './native-observations.js'
import { MODEL_CATALOG_CAPABILITY, type ModelPage, type ModelPageBinding, type ModelPageRequest } from './model-catalog.js'
import { HostConnectionLease } from './connection-lease.js'
import { HostReconnectBackoff } from './relay-backoff.js'
import { DIRECTORY_METADATA_CAPABILITY, directoryMetadataSchema } from './directory-metadata.js'
import { IMAGE_MESSAGE_CAPABILITY, SESSION_MEDIA_CAPABILITY, imageReference } from './image-protocol.js'
import { CHANGES_CAPABILITY } from './changes-protocol.js'
import { FORK_CAPABILITY, MESSAGE_ACTIONS_CAPABILITY, forkPayloadSchema, forkOutcomeSchema, relayForkDigest } from './fork-protocol.js'
import { WorkspaceChanges } from './workspace-changes.js'

const MAX_FRAME_BYTES = 64 * 1024
const MAX_BUFFERED_BYTES = 512 * 1024
const PROTOCOL = 'dsh.remote.v1'
const PROOF_TYPE = 'dsh-relay-handshake-proof+jwt'
const AUDIENCE = 'urn:dsh-mobile-ustc:realtime'
const capabilities = ['command.relay.v1', 'connection.heartbeat.v1', 'question.blocking.v1', 'question.timed.v1', 'session.archive.v1', 'session.cancel.v1', 'session.catalog.v1', 'session.create.v1', 'session.model.select.v1', 'session.read.v1'] as const
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
    protocols: z.array(z.number().int().positive()).min(1).max(16).refine(values => new Set(values).size === values.length),
    capabilities: z.array(z.string().min(1).max(128)).max(64).refine(values => new Set(values).size === values.length),
    server_time: z.string().datetime({ offset: true }),
    heartbeat_seconds: z.literal(20),
    max_frame_bytes: z.literal(MAX_FRAME_BYTES),
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
const creationOptionsAckSchema = z.strictObject({
  v: z.literal(1), type: z.literal('session.create.options.ack'), request_id: uuid, runtime_id: uuid, runtime_epoch: uuid,
  payload: z.strictObject({ workspace_count: z.number().int().min(0).max(128), preset_count: z.number().int().min(0).max(128), server_time: z.string().datetime({ offset: true }) }),
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
    content: z.array(z.discriminatedUnion('type', [z.strictObject({ type: z.literal('text'), text: nonEmptyText }), fileReference, imageReference])).min(1).max(16).refine(parts => {
      const ids = parts.filter(part => part.type !== 'text').map(part => part.file_id)
      return new Set(ids).size === ids.length
    }),
  }),
})
const cancelSchema = submitSchema.extend({ type: z.literal('session.cancel'), payload: z.strictObject({}) })
const reconcileSchema = submitSchema.extend({ type: z.literal('message.files.reconcile'),
  payload: submitSchema.shape.payload.refine(payload => payload.content.some(part => part.type !== 'text')) })
const modelSelectionSchema = submitSchema.extend({ type: z.literal('session.model.select'), payload: modelSelectionPayload })
const archiveSchema = submitSchema.extend({ type: z.literal('session.archive'), payload: archivePayload })
const forkSchema = submitSchema.extend({ type: z.literal('session.fork'), payload: forkPayloadSchema })
const questionSchema = submitSchema.extend({ type: z.literal('question.answer'), payload: questionAnswerPayload })
const timedQuestionSchema = submitSchema.extend({ type: z.literal('question.timed.answer'), payload: questionAnswerPayload })
const createSchema = submitSchema.omit({ session_id: true }).extend({
  type: z.literal('session.create'), payload: z.strictObject({ workspace_id: uuid, preset: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/) }),
})
const forwardedCommandSchema = z.discriminatedUnion('type', [submitSchema, reconcileSchema, cancelSchema, archiveSchema, modelSelectionSchema, createSchema, forkSchema, questionSchema, timedQuestionSchema])
type ForwardedCommand = z.infer<typeof forwardedCommandSchema>
const catalogItemSchema = z.strictObject({
  session_id: uuid,
  dsh_session_id: z.string().min(1).refine(value => Buffer.byteLength(value) <= 2048 && !value.includes('\0')),
  workspace_id: uuid.nullable(),
  state: z.enum(['available', 'running', 'archived', 'unavailable']),
  last_persisted_seq: z.number().int().min(-1),
})
const directoryCatalogItemSchema = catalogItemSchema.extend({ metadata: directoryMetadataSchema.optional() })
const receiptCatalogItemSchema = directoryCatalogItemSchema.transform(({ metadata: _metadata, ...item }) => item)

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
  readonly origin?: string
  readonly signal?: AbortSignal
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
      modelPage?(binding: ModelPageBinding, request: ModelPageRequest, signal: AbortSignal): Promise<ModelPage>
      creationOptions?(): SessionCreationOptions
      observations?: NativeObservations
      resolveImageFile?: DshClient['resolveImageFile']
      nativeForkSupported?: () => boolean
      workspaceChangesContext?: NonNullable<SessionReaderRuntime['client']['workspaceChangesContext']>
    }
    dispatch(command: Command, signal: AbortSignal, owner: CommandOwner, observe?: CommandStateObserver): Promise<unknown>
    reconcileFileMessage?(command: Extract<Command, { type: 'message.submit' }>, signal: AbortSignal, owner: CommandOwner, observe?: CommandStateObserver): Promise<unknown>
    follow: SessionReaderRuntime['follow']
    claimQuestion?: SessionReaderRuntime['claimQuestion']
    messageActions?: NonNullable<SessionReaderRuntime['messageActions']>
    changes?: NonNullable<SessionReaderRuntime['changes']>
    mediaCurrent?: (session: string, sync: string) => boolean
  }
  credentials: HostCredentialProvider
  dshVersion: string
  applicationVersion: string
  pluginVersion: string
  approvals?: HostApprovalPeerFactory
  questionReferences?: (binding: QuestionReferenceBinding) => HostQuestionReferences
  files?: (binding: FileTransportBinding) => HostFilePeer
  exports?: (binding: FileTransportBinding) => HostExportPeer
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
  private bytes = 0
  private waiter: { resolve(frame: Buffer): void; reject(error: Error): void; timer: NodeJS.Timeout } | undefined
  private ended: Error | undefined
  private readonly onMessage = (data: unknown, binary: boolean) => {
    if (this.ended) return
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
      if (this.frames.length >= 32 || this.bytes + frame.length > MAX_BUFFERED_BYTES) {
        return this.end(new Error('Relay frame queue exceeded the limit'))
      }
      this.frames.push(frame)
      this.bytes += frame.length
    }
  }
  private readonly onClose = () => this.end(new Error('Relay connection closed'))
  private readonly onError = (error: unknown) => this.end(asError(error))

  constructor(private readonly socket: RelaySocket, private readonly signal: AbortSignal, private readonly failed: () => void) {
    socket.on('message', this.onMessage)
    socket.on('close', this.onClose)
    socket.on('error', this.onError)
    signal.addEventListener('abort', this.onClose, { once: true })
    if (signal.aborted) this.onClose()
  }

  next(timeoutMs: number): Promise<Buffer> {
    if (this.ended) return Promise.reject(this.ended)
    const buffered = this.frames.shift()
    if (buffered) {
      this.bytes -= buffered.length
      return Promise.resolve(buffered)
    }
    return new Promise((resolve, reject) => {
      if (this.waiter) return reject(new Error('Concurrent Relay frame reads are not supported'))
      const timer = setTimeout(() => {
        this.end(new Error('Relay frame timed out'))
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
    this.frames.length = 0
    this.bytes = 0
    if (this.waiter) {
      clearTimeout(this.waiter.timer)
      this.waiter.reject(error)
      this.waiter = undefined
    }
    this.failed()
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

function splitSessionCatalog(mode: 'snapshot' | 'delta', runtimeId: string, runtimeEpoch: string, snapshotId: string, items: SessionCatalogItem[], metadata: boolean): SessionCatalogItem[][] {
  if (items.length > 20_000) throw new ProbeError('rate.limited')
  const chunks: SessionCatalogItem[][] = []
  let current: SessionCatalogItem[] = []
  for (const item of items) {
    if (!(metadata ? directoryCatalogItemSchema : catalogItemSchema).safeParse(item).success) throw new ProbeError('protocol.invalid')
    const candidate = [...current, item]
    const probe = {
      v: 1, type: 'session.catalog', request_id: snapshotId, runtime_id: runtimeId, runtime_epoch: runtimeEpoch,
      payload: { mode, index: chunks.length, complete: false, items: candidate, ...(metadata ? { metadata_version: 1 } : {}) },
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
      : parsed.data.type === 'session.model.select'
        ? relayModelSelectionDigest(parsed.data.session_id, parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'session.archive'
        ? relayArchiveDigest(parsed.data.session_id, parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'question.answer'
        ? relayQuestionDigest(parsed.data.session_id, parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'question.timed.answer'
        ? relayTimedQuestionDigest(parsed.data.session_id, parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'session.create'
        ? relayCreateDigest(parsed.data.runtime_epoch, parsed.data.payload)
      : parsed.data.type === 'session.fork'
        ? relayForkDigest(parsed.data.runtime_epoch, parsed.data.session_id, parsed.data.payload)
        : forwardedDigest(parsed.data.session_id, parsed.data.payload)) !== parsed.data.payload_sha256) {
    throw new ProbeError('protocol.invalid')
  }
  return parsed.data
}

function makeCommand(frame: ForwardedCommand): Command {
  return parseCommand({
    v: 0,
    type: frame.type === 'message.files.reconcile' ? 'message.submit' : frame.type,
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

async function connectOnce(options: HostRelayOptions, url: string, credential: HostConnectionCredential, signal: AbortSignal, connected: () => void): Promise<void> {
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
  let creationOptionsTimer: NodeJS.Timeout | undefined
  let leaseTimer: NodeJS.Timeout | undefined
  let sessions: RelaySessions | undefined
  let approvals: HostApprovalPeer | undefined
  let questionReferences: HostQuestionReferences | undefined
  let files: HostFilePeer | undefined
  let exports: HostExportPeer | undefined
  let observations: ReturnType<typeof bindNativeObservations> | undefined
  const abortConnection = () => {
    connection.abort()
    socket.terminate()
  }
  signal.addEventListener('abort', abortConnection, { once: true })
  const queue = new IncomingFrames(socket, connection.signal, abortConnection)
  if (signal.aborted) abortConnection()
  try {
    await waitForOpen(socket, connection.signal)
    const challengeEnvelope = challengeSchema.safeParse(await receiveFrame(queue, 15_000))
    if (!challengeEnvelope.success || Date.parse(challengeEnvelope.data.payload.expires_at) <= Date.now()) {
      throw new ProbeError('auth.proof_invalid')
    }
    const challenge = challengeEnvelope.data.payload
    let sourceOptions: SessionCreationOptions | undefined
    try {
      if (options.runtime.client.creationOptions) sourceOptions = creationOptionsSchema.parse(options.runtime.client.creationOptions())
    } catch { /* The bounded metadata extension is unavailable; core Relay operations remain independent. */ }
    const offered: string[] = options.approvals ? [...capabilities, SIGNED_APPROVAL_CAPABILITY, APPROVAL_INVALIDATION_CAPABILITY] : [...capabilities]
    offered.push(DIRECTORY_METADATA_CAPABILITY)
    if (options.files && typeof options.runtime.client.resolveImageFile === 'function') offered.push(IMAGE_MESSAGE_CAPABILITY)
    if (options.exports && options.runtime.mediaCurrent) offered.push(SESSION_MEDIA_CAPABILITY)
    if (options.runtime.messageActions) offered.push(MESSAGE_ACTIONS_CAPABILITY)
    if (options.runtime.messageActions && options.runtime.client.nativeForkSupported?.()) offered.push(FORK_CAPABILITY)
    if (options.runtime.changes && options.runtime.client.workspaceChangesContext && await WorkspaceChanges.supported()) offered.push(CHANGES_CAPABILITY)
    if (options.questionReferences) offered.push(QUESTION_REFERENCES_CAPABILITY)
    if (sourceOptions) offered.push(CREATION_OPTIONS_CAPABILITY)
    if (options.files) offered.push(FILE_HANDOFF_CAPABILITY, FILE_MESSAGE_CAPABILITY)
    if (options.files && options.runtime.reconcileFileMessage) offered.push(FILE_RECONCILE_CAPABILITY)
    if(options.exports)offered.push(EXPORT_CAPABILITY)
    if (options.runtime.client.modelPage) offered.push(MODEL_CATALOG_CAPABILITY)
    if (options.runtime.client.observations) offered.push(HOST_OBSERVATIONS_CAPABILITY)
    connection.signal.throwIfAborted()
    const proof = await withAbort(proofForHello(credential, challenge, options.runtime.client.runtimeId, options.runtime.epoch, options, offered), connection.signal)
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
      || !ack.data.payload.capabilities.every(capability => offered.includes(capability))
      || !requiredCapabilities.every(capability => ack.data.payload.capabilities.includes(capability))) {
      throw new ProbeError('protocol.unsupported')
    }

    const lease = new HostConnectionLease(ack.data.payload.server_time, ack.data.payload.lease_expires_at)
    const checkCurrent = () => {
      if (lease.remaining() <= 0) abortConnection()
      connection.signal.throwIfAborted()
    }
    const sendCurrent = async (frame: unknown): Promise<void> => { checkCurrent(); await sendFrame(socket, frame) }
    leaseTimer = setTimeout(abortConnection, Math.ceil(lease.remaining()))
    leaseTimer.unref()

    if (options.approvals && (![SIGNED_APPROVAL_CAPABILITY,APPROVAL_INVALIDATION_CAPABILITY,'session.catalog.v1'].every(capability=>ack.data.payload.capabilities.includes(capability)))) throw new ProbeError('protocol.unsupported')
    if (options.runtime.client.observations && ack.data.payload.capabilities.includes(HOST_OBSERVATIONS_CAPABILITY)) {
      observations = bindNativeObservations(options.runtime.client.observations, { connectionId: challenge.connection_id, runtimeId: options.runtime.client.runtimeId, epoch: options.runtime.epoch }, frame => {
        if (lease.remaining() <= 0 || connection.signal.aborted) { abortConnection(); return false }
        const encoded = JSON.stringify(frame)
        if (socket.readyState !== 1 || socket.bufferedAmount > MAX_BUFFERED_BYTES / 4 || Buffer.byteLength(encoded) > 16 * 1024) return false
        try { socket.send(encoded, () => {}); return true } catch { return false }
      })
    }
    if (options.files && ack.data.payload.capabilities.includes(FILE_HANDOFF_CAPABILITY)) {
      if (!ack.data.payload.capabilities.includes('session.catalog.v1')) throw new ProbeError('protocol.unsupported')
      const origin = new URL(url)
      origin.protocol = origin.protocol === 'wss:' ? 'https:' : 'http:'
      files = options.files({ installationId: credential.installationId, connectionId: challenge.connection_id,
        origin: origin.origin, signer: credential.signer, signal: connection.signal,
        send: sendCurrent, fail: abortConnection })
    }
    if(options.exports&&ack.data.payload.capabilities.includes(EXPORT_CAPABILITY)){
      if(!ack.data.payload.capabilities.includes('session.catalog.v1'))throw new ProbeError('protocol.unsupported')
      const origin=new URL(url);origin.protocol=origin.protocol==='wss:'?'https:':'http:'
      exports=options.exports({installationId:credential.installationId,connectionId:challenge.connection_id,origin:origin.origin,signer:credential.signer,signal:connection.signal,send:sendCurrent,fail:abortConnection})
    }

    const catalogEnabled = ack.data.payload.capabilities.includes('session.catalog.v1')
    const metadataEnabled = ack.data.payload.capabilities.includes(DIRECTORY_METADATA_CAPABILITY)
    if (ack.data.payload.capabilities.includes('session.read.v1')) sessions = new RelaySessions({
      epoch: options.runtime.epoch, client: options.runtime.client,
      follow: (command, signal) => options.runtime.follow(command, signal),
      dispatch: (command, signal) => options.runtime.dispatch(command, signal, { userId: 'relay-read', deviceId: 'relay-read' }),
      ...(options.runtime.claimQuestion ? { claimQuestion: (sessionId: string, questionId: string, signal: AbortSignal) => options.runtime.claimQuestion!(sessionId, questionId, signal) } : {}),
      ...(options.runtime.messageActions ? { messageActions: options.runtime.messageActions } : {}),
      ...(options.runtime.changes ? { changes: options.runtime.changes } : {}),
    }, sendCurrent, ack.data.payload.capabilities.includes('question.timed.v1'), ack.data.payload.capabilities.includes(MODEL_CATALOG_CAPABILITY), {
      media: !!exports && !!options.runtime.mediaCurrent && ack.data.payload.capabilities.includes(SESSION_MEDIA_CAPABILITY),
      messageActions: ack.data.payload.capabilities.includes(MESSAGE_ACTIONS_CAPABILITY),
      changes: ack.data.payload.capabilities.includes(CHANGES_CAPABILITY),
    })
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
          const sourceItems = await options.runtime.client.sessionCatalog(connection.signal, sessionIDs)
          const items = metadataEnabled ? sourceItems : sourceItems.map(({ metadata: _metadata, ...item }) => item)
          if (mode === 'delta' && items.length === 0) continue
          const snapshotId = randomUUID()
          const chunks = splitSessionCatalog(mode, options.runtime.client.runtimeId, options.runtime.epoch, snapshotId, items, metadataEnabled)
          const acknowledged = waitForCatalogAck(snapshotId, items.length)
          // A failed write can end this task before it reaches the acknowledgement.
          void acknowledged.catch(() => {})
          try {
            for (let index = 0; index < chunks.length; index++) {
              await sendCurrent({
                v: 1,
                type: 'session.catalog',
                request_id: snapshotId,
                runtime_id: options.runtime.client.runtimeId,
                runtime_epoch: options.runtime.epoch,
                payload: { mode, index, complete: index === chunks.length - 1, items: chunks[index], ...(metadataEnabled ? { metadata_version: 1 } : {}) },
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
    let creationRequest: string | undefined
    const publishCreationOptions = () => {
      if (!sourceOptions || !ack.data.payload.capabilities.includes(CREATION_OPTIONS_CAPABILITY) || !ack.data.payload.capabilities.includes('session.create.v1') || connection.signal.aborted) return
      creationRequest = randomUUID()
      creationOptionsTimer = setTimeout(publishCreationOptions, 30_000 + Math.floor(Math.random() * 15_000))
      creationOptionsTimer.unref()
      void sendCurrent({ v: 1, type: 'session.create.options', request_id: creationRequest,
        runtime_id: options.runtime.client.runtimeId, runtime_epoch: options.runtime.epoch, payload: sourceOptions }).catch(abortConnection)
    }
    publishCreationOptions()

    const publishCatalog = (nativeId: string, signal: AbortSignal) => new Promise<void>((resolve, reject) => {
        if (catalogBarriers.size >= 128 || connection.signal.aborted || signal.aborted) { reject(new ProbeError('runtime.offline')); return }
        const lifetime = AbortSignal.any([connection.signal, signal])
        const abort = () => barrier.reject(new ProbeError('runtime.offline'))
        const cleanup = () => { catalogBarriers.delete(barrier); lifetime.removeEventListener('abort', abort) }
        const barrier = { nativeId, resolve: () => { cleanup(); resolve() }, reject: (error: Error) => { cleanup(); reject(error) } }
        catalogBarriers.add(barrier); lifetime.addEventListener('abort', abort, { once: true })
        requestCatalogRefresh({ kind: 'delta', sessionIds: [nativeId] })
      })
    if (options.approvals) approvals = options.approvals({
      installationId: credential.installationId, connectionId: ack.data.payload.connection_id, signal: connection.signal,
      send: sendCurrent, fail: abortConnection, publishCatalog,
    })
    if (options.questionReferences && ack.data.payload.capabilities.includes(QUESTION_REFERENCES_CAPABILITY)) questionReferences = options.questionReferences({
      runtimeId: options.runtime.client.runtimeId, epoch: options.runtime.epoch, signal: connection.signal,
      send: sendCurrent, fail: abortConnection, publishCatalog,
    })

    const handleFrame = async (value: unknown) => {
      checkCurrent()
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        const frame = value as Record<string, unknown>
        if (questionReferences && await questionReferences.handle(value)) return
        if (exports && await exports.handle(value)) return
        if (files && await files.handle(value)) return
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
        if (frame.type === 'session.create.options.ack') {
          const parsed = creationOptionsAckSchema.safeParse(value)
          if (!parsed.success || parsed.data.runtime_id !== options.runtime.client.runtimeId || parsed.data.runtime_epoch !== options.runtime.epoch) throw new ProbeError('protocol.invalid')
          if (parsed.data.request_id === creationRequest) {
            if (parsed.data.payload.workspace_count !== sourceOptions?.workspaces.length || parsed.data.payload.preset_count !== sourceOptions?.presets.length) throw new ProbeError('protocol.invalid')
            if (creationOptionsTimer) clearTimeout(creationOptionsTimer)
            creationOptionsTimer = undefined; creationRequest = undefined
          }
          return
        }
        if (frame.type === 'error') {
          const requestId = typeof frame.request_id === 'string' ? frame.request_id : ''
          pendingCatalogAcks.get(requestId)?.reject(new ProbeError(String((frame.payload as { code?: unknown } | undefined)?.code ?? 'internal')))
          return
        }
        if (frame.v === 1 && frame.type === 'server.draining') {
          socket.close(1012, 'server draining')
          abortConnection()
          return
        }
        checkCurrent()
        if (sessions?.handle(value)) return
        const forwarded = parseForwarded(value, options.runtime.client.runtimeId, options.runtime.epoch)
        if (forwarded.type === 'message.files.reconcile' && (!files || !options.runtime.reconcileFileMessage
          || !ack.data.payload.capabilities.includes(FILE_MESSAGE_CAPABILITY) || !ack.data.payload.capabilities.includes(FILE_RECONCILE_CAPABILITY))) throw new ProbeError('protocol.unsupported')
        if ((forwarded.type === 'message.submit' || forwarded.type === 'message.files.reconcile') && forwarded.payload.content.some(part => part.type !== 'text')
          && (!files || !ack.data.payload.capabilities.includes(FILE_MESSAGE_CAPABILITY))) throw new ProbeError('protocol.unsupported')
        if ((forwarded.type === 'message.submit' || forwarded.type === 'message.files.reconcile') && forwarded.payload.content.some(part => part.type === 'image')
          && !ack.data.payload.capabilities.includes(IMAGE_MESSAGE_CAPABILITY)) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'session.cancel' && !ack.data.payload.capabilities.includes('session.cancel.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'session.model.select' && !ack.data.payload.capabilities.includes('session.model.select.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'session.archive' && !ack.data.payload.capabilities.includes('session.archive.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'session.create' && !ack.data.payload.capabilities.includes('session.create.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'session.fork' && !ack.data.payload.capabilities.includes(FORK_CAPABILITY)) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'question.answer' && !ack.data.payload.capabilities.includes('question.blocking.v1')) throw new ProbeError('protocol.unsupported')
        if (forwarded.type === 'question.timed.answer' && !ack.data.payload.capabilities.includes('question.timed.v1')) throw new ProbeError('protocol.unsupported')
        const command = makeCommand(forwarded)
        const owner: CommandOwner = { userId: forwarded.user_id, deviceId: forwarded.device_id }
        let reported: CommandState | undefined
        const observe: CommandStateObserver = async (state: CommandState, result?: unknown) => {
          reported = state
          let item: z.infer<typeof catalogItemSchema> | undefined
          if (forwarded.type === 'session.create' && state === 'settled') {
            const parsed = receiptCatalogItemSchema.safeParse((result as { catalog_item?: unknown } | undefined)?.catalog_item)
            if (!parsed.success || parsed.data.workspace_id !== forwarded.payload.workspace_id || parsed.data.state === 'unavailable') throw new ProbeError('journal.integrity_failed')
            item = parsed.data
          }
          let forkResult: { child_session_id: string; fork_outcome: z.infer<typeof forkOutcomeSchema> } | undefined
          if (forwarded.type === 'session.fork') {
            const value = result as { child_session_id?: unknown; fork_outcome?: unknown; catalog_item?: unknown } | undefined
            if (value?.child_session_id !== undefined || value?.fork_outcome !== undefined) {
              const child = uuid.safeParse(value.child_session_id)
              const outcome = forkOutcomeSchema.safeParse(value.fork_outcome)
              if (!child.success || !outcome.success || child.data === forwarded.session_id) throw new ProbeError('journal.integrity_failed')
              forkResult = { child_session_id: child.data, fork_outcome: outcome.data }
            }
            if (state === 'settled') {
              const parsed = receiptCatalogItemSchema.safeParse(value?.catalog_item)
              if (!forkResult || forkResult.fork_outcome.checkpoint !== 'persisted'
                || !parsed.success || parsed.data.session_id !== forkResult.child_session_id || parsed.data.workspace_id !== forwarded.payload.workspace_id
                || parsed.data.state === 'unavailable') throw new ProbeError('journal.integrity_failed')
              item = parsed.data
            }
          }
          await sendCurrent({
            v: 1,
            type: 'command.receipt',
            request_id: forwarded.request_id,
            runtime_id: forwarded.runtime_id,
            runtime_epoch: forwarded.runtime_epoch,
            ...('session_id' in forwarded ? { session_id: forwarded.session_id } : item ? { session_id: item.session_id } : {}),
            device_id: forwarded.device_id,
            payload: {
              state, payload_sha256: forwarded.payload_sha256,
              ...(forwarded.type === 'session.create' || forwarded.type === 'session.fork' ? { workspace_id: forwarded.payload.workspace_id } : {}),
              ...(forwarded.type === 'session.fork' ? { command_type: 'session.fork', ...forkResult } : {}),
              ...(item ? { created_session: item } : {}),
            },
          })
        }
        try {
          if (forwarded.type === 'message.files.reconcile') {
            if (command.type !== 'message.submit') throw new ProbeError('protocol.invalid')
            await options.runtime.reconcileFileMessage!(command, connection.signal, owner, observe)
          } else await options.runtime.dispatch(command, connection.signal, owner, observe)
        }
        catch (error) {
          // A durably rejected/uncertain operation already has a receipt. It
          // must not tear down unrelated subscriptions on the same transport.
          if (reported !== 'rejected' && reported !== 'outcome_unknown') throw error
        }
        return
      }
      throw new ProbeError('protocol.invalid')
    }

    checkCurrent()
    connected()
    const reader = (async () => {
      while (!connection.signal.aborted) {
        const value = await receiveFrame(queue, 40_000)
        checkCurrent()
        await withAbort(handleFrame(value), connection.signal)
      }
    })()
    const heartbeat = setInterval(() => {
      void sendCurrent({ v: 1, type: 'ping', payload: {} }).catch(abortConnection)
    }, ack.data.payload.heartbeat_seconds * 1000)
    heartbeat.unref()
    try { await reader }
    finally { clearInterval(heartbeat) }
  } finally {
    if (leaseTimer) clearTimeout(leaseTimer)
    observations?.close()
    await exports?.close()
    files?.close()
    approvals?.close()
    questionReferences?.close()
    sessions?.close()
    if (catalogRetryTimer) clearTimeout(catalogRetryTimer)
    if (creationOptionsTimer) clearTimeout(creationOptionsTimer)
    stopWatchingCatalog()
    signal.removeEventListener('abort', abortConnection)
    connection.abort()
    queue.close()
    if (socket.readyState === 1) socket.close(1000, 'connection ended')
    else if (socket.readyState < 2) socket.terminate()
  }
}

async function run(options: HostRelayOptions, url: string, signal: AbortSignal): Promise<void> {
  const backoff = new HostReconnectBackoff()
  while (!signal.aborted) {
    try {
      const credential = await withAbort(options.credentials.acquire(signal), signal)
      await connectOnce(options, url, credential, signal, () => backoff.connected())
    } catch {
      if (signal.aborted) return
    }
    if (signal.aborted) return
    try { await delay(backoff.retryDelay(), undefined, { signal }) }
    catch { return }
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
  const origin = new URL(url)
  origin.protocol = origin.protocol === 'wss:' ? 'https:' : 'http:'
  if (options.credentials.origin !== undefined && options.credentials.origin !== origin.origin) throw new Error('Relay origin does not match its credential provider')
  if ([options.applicationVersion, options.dshVersion, options.pluginVersion].some(value =>
    !value || value !== value.trim() || Buffer.byteLength(value) > 128 || /\p{Cc}/u.test(value))) {
    throw new Error('Relay version metadata must be non-empty, bounded, and contain no control characters')
  }
  if (!uuid.safeParse(options.runtime.client.runtimeId).success || !uuid.safeParse(options.runtime.epoch).success) {
    throw new Error('Relay runtime identity must use UUIDs')
  }
  const controller = new AbortController()
  const lifetime = options.credentials.signal ? AbortSignal.any([controller.signal, options.credentials.signal]) : controller.signal
  const task = run(options, url, lifetime).catch(() => {})
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

export function relayArchiveDigest(sessionId: string, runtimeEpoch: string, payload: z.infer<typeof archivePayload>): string {
  return createHash('sha256').update(JSON.stringify(jcs({ type: 'session.archive', runtime_epoch: runtimeEpoch, session_id: sessionId, payload }))).digest('hex')
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

export function relayModelSelectionDigest(sessionId: string, runtimeEpoch: string, payload: z.infer<typeof modelSelectionPayload>): string {
  return createHash('sha256').update(JSON.stringify(jcs({ type: 'session.model.select', runtime_epoch: runtimeEpoch, session_id: sessionId, payload }))).digest('hex')
}
