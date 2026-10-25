import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { lstat, mkdir, chmod, realpath, unlink } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import type { Socket } from 'node:net'
import { encodeFrames, MAX_FRAME_BYTES, MAX_QUEUE_BYTES, parseCommand, ProbeError, type Frame } from './protocol.js'
import type { ProbeRuntime } from './runtime.js'

export function safeError(error: unknown): string {
  if (error instanceof ProbeError) return error.code
  const code = (error as { code?: unknown } | null)?.code
  if (code === 'session/not-found') return 'session.not_found'
  if (code === 'session/agent-busy') return 'session.writer_held'
  return 'internal'
}

/** One bounded producer queue, drained independently from the DSH follower. */
export class FrameWriter {
  private readonly queue: string[] = []
  private bytes = 0
  private writing = false
  private ended = false
  constructor(private readonly response: ServerResponse, private readonly abort: () => void) {}

  push(frame: Frame): void {
    const lines = encodeFrames(frame)
    const size = lines.reduce((sum, line) => sum + Buffer.byteLength(line), 0)
    if (this.response.destroyed || this.bytes + this.response.writableLength + size > MAX_QUEUE_BYTES) {
      this.abort()
      this.response.destroy()
      throw new ProbeError('protocol.resync_required')
    }
    this.bytes += size
    this.queue.push(...lines)
    this.drain()
  }

  end(): void { this.ended = true; this.drain() }
  private drain(): void {
    if (this.writing || this.response.destroyed) return
    while (this.queue.length) {
      const line = this.queue.shift()!
      this.bytes -= Buffer.byteLength(line)
      if (!this.response.write(line)) {
        this.writing = true
        this.response.once('drain', () => { this.writing = false; this.drain() })
        return
      }
    }
    if (this.ended) this.response.end()
  }
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  let size = 0
  const buffers: Buffer[] = []
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk)
    size += buffer.length
    if (size > MAX_FRAME_BYTES) throw new ProbeError('protocol.frame_too_large')
    buffers.push(buffer)
  }
  try { return JSON.parse(Buffer.concat(buffers).toString('utf8')) }
  catch { throw new ProbeError('protocol.invalid') }
}

/** Validate the local IPC namespace and keep each Windows pipe bound to one runtime identity. */
export function validateSocketPath(socketPath: string, platform = process.platform): void {
  if (platform === 'win32') {
    if (!/^\\\\\.\\pipe\\dsh-mobile-ustc-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(socketPath)) {
      throw new Error('Windows M0 debug requires a per-runtime named pipe under \\\\.\\pipe\\dsh-mobile-ustc-<runtimeId>')
    }
    return
  }
  if (!isAbsolute(socketPath) || Buffer.byteLength(socketPath) > 100) {
    throw new Error('M0 debug requires an absolute Unix socket path of at most 100 bytes')
  }
}

export async function startDebugServer(socketPath: string, runtime: ProbeRuntime) {
  validateSocketPath(socketPath)
  const windowsPipe = process.platform === 'win32'
  if (!windowsPipe) {
    const parent = dirname(socketPath)
    await mkdir(parent, { recursive: true, mode: 0o700 })
    const stat = await lstat(parent)
    if (!stat.isDirectory() || stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0 || await realpath(parent) !== resolve(parent)) {
      throw new Error('M0 debug socket directory must be private (0700), owned by the current user, and contain no symlinks')
    }
  }
  const sockets = new Set<Socket>()
  const operations = new Set<AbortController>()
  const server = createServer({ requestTimeout: 5000, headersTimeout: 5000, maxHeaderSize: 8192 }, (request, response) => {
    const controller = new AbortController()
    operations.add(controller)
    response.on('close', () => { controller.abort(); operations.delete(controller) })
    request.on('aborted', () => controller.abort())
    response.setHeader('cache-control', 'no-store')
    response.setHeader('content-type', 'application/x-ndjson')
    const writer = new FrameWriter(response, () => controller.abort())
    const run = async () => {
      if (request.headers.origin !== undefined) throw new ProbeError('access.denied')
      if (request.method === 'GET' && request.url === '/m0/probe') {
        writer.push({ v: 0, type: 'probe', runtime_epoch: runtime.epoch, payload: {
          runtime_id: runtime.client.runtimeId,
          transport: process.platform === 'win32' ? 'windows-named-pipe' : 'local-unix-socket',
          dsh_version: '0.2.1-rc.2', plugin_version: '0.0.1',
          capabilities: ['session.list', 'session.create', 'message.text', 'session.cancel', 'session.archive', 'session.snapshot', 'session.page', 'assistant.stream', 'local.approval', 'local.question'],
          max_frame_bytes: MAX_FRAME_BYTES, max_queue_bytes: MAX_QUEUE_BYTES,
        } })
      } else {
        if (request.method !== 'POST' || request.url !== '/m0/command') throw new ProbeError('protocol.not_found')
        if (request.headers['content-type']?.split(';')[0] !== 'application/json') throw new ProbeError('protocol.invalid')
        const command = parseCommand(await readBody(request))
        if (command.type === 'session.subscribe') {
          for await (const frame of runtime.follow(command, controller.signal)) writer.push(frame)
        } else writer.push(await runtime.dispatch(command, controller.signal))
      }
      writer.end()
    }
    void run().catch(error => {
      if (response.destroyed || controller.signal.aborted) return
      if (!response.headersSent) response.statusCode = 400
      try { writer.push({ v: 0, type: 'error', runtime_epoch: runtime.epoch, payload: { code: safeError(error) } }); writer.end() }
      catch { response.destroy() }
    })
  })
  server.maxConnections = 16
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)) })
  await new Promise<void>((accept, reject) => {
    server.once('error', reject)
    const onListen = () => { server.off('error', reject); accept() }
    if (windowsPipe) server.listen({ path: socketPath, readableAll: false, writableAll: false }, onListen)
    else server.listen(socketPath, onListen)
  })
  let socketIdentity: { dev: number; ino: number } | undefined
  if (!windowsPipe) {
    await chmod(socketPath, 0o600)
    const stat = await lstat(socketPath)
    if (!stat.isSocket()) throw new Error('M0 debug endpoint did not create a Unix socket')
    socketIdentity = { dev: stat.dev, ino: stat.ino }
  }
  return {
    async close() {
      runtime.close()
      for (const operation of operations) operation.abort()
      for (const socket of sockets) socket.destroy()
      await new Promise<void>((accept, reject) => server.close(error => error ? reject(error) : accept()))
      if (socketIdentity) {
        try {
          const current = await lstat(socketPath)
          if (current.isSocket() && current.dev === socketIdentity.dev && current.ino === socketIdentity.ino) await unlink(socketPath)
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        }
      }
    },
  }
}
