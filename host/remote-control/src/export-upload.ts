import { createHash } from 'node:crypto'
import type { FileExportRegistry, ExportAuthority, ExportEntry } from './file-export-registry.js'
import { exportCapability } from './export-protocol.js'
import { ProbeError } from './protocol.js'

const allowed = new Set(['content-type', 'content-length', 'cache-control', 'x-amz-checksum-sha256', 'x-amz-sdk-checksum-algorithm', 'x-amz-security-token',
  'x-amz-server-side-encryption', 'x-amz-server-side-encryption-aws-kms-key-id'])

/** An anonymous, one-shot PUT. School credentials and native storage paths are not inputs. */
export async function putExportSource(registry: FileExportRegistry, entry: ExportEntry, session: string, authority: ExportAuthority, input: unknown, signal: AbortSignal): Promise<void> {
  const capability = exportCapability.parse(input)
  let uri: URL
  try { uri = new URL(capability.url) } catch { throw new ProbeError('file.export_unavailable') }
  if (uri.protocol !== 'https:' || uri.username || uri.password || uri.hash || /[\x00-\x20\x7f]/.test(capability.url)) throw new ProbeError('file.export_unavailable')
  const headers: Record<string, string> = {}
  for (const [name, value] of Object.entries(capability.headers)) {
    const key = name.toLowerCase()
    if (!allowed.has(key) || key in headers || value.length > 4096 || /[^\x20-\x7e]/.test(value)) throw new ProbeError('file.export_unavailable')
    headers[key] = value
  }
  const checksum = Buffer.from(entry.sha256, 'hex').toString('base64')
  if (headers['content-type'] !== 'application/octet-stream' || headers['content-length'] !== undefined && headers['content-length'] !== String(entry.size_bytes)
    || headers['x-amz-checksum-sha256'] !== undefined && headers['x-amz-checksum-sha256'] !== checksum
    || headers['x-amz-sdk-checksum-algorithm'] !== undefined && headers['x-amz-sdk-checksum-algorithm'] !== 'SHA256'
    || headers['x-amz-server-side-encryption'] !== undefined && headers['x-amz-server-side-encryption'] !== 'aws:kms'
    || headers['cache-control'] !== undefined && headers['cache-control'] !== 'no-store') throw new ProbeError('file.export_unavailable')
  const issued = Date.now(), start = performance.now(), expiry = Math.min(Date.parse(capability.expires_at), Date.parse(entry.expires_at))
  const remaining = expiry - issued
  if (!Number.isFinite(remaining) || remaining <= 0 || remaining > 330_000) throw new ProbeError('file.export_unavailable')
  const deadline = AbortSignal.timeout(Math.max(1, Math.floor(remaining)))
  const lifetime = AbortSignal.any([signal, authority.signal, deadline])
  const check = () => {
    lifetime.throwIfAborted(); authority.current()
    if (Date.now() < issued || Date.now() >= expiry || performance.now() - start >= remaining) throw new ProbeError('file.export_unavailable')
  }
  check()
  const source = registry.read(entry.export_id, session, { owner: { ...authority.owner }, signal: lifetime, current: () => authority.current() })[Symbol.asyncIterator]()
  let bytes = 0
  const hash = createHash('sha256')
  const requestAbort = new AbortController()
  let body: ReadableStream<Uint8Array> | undefined
  try {
    if (entry.size_bytes === 0) {
      const next = await source.next()
      if (!next.done) throw new ProbeError('file.export_changed')
    } else body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          check()
          const next = await source.next()
          check()
          if (next.done) { controller.close(); return }
          bytes += next.value.byteLength
          if (bytes > entry.size_bytes) throw new ProbeError('file.export_changed')
          hash.update(next.value)
          controller.enqueue(next.value)
        } catch { controller.error(new ProbeError('file.export_unavailable')); requestAbort.abort() }
      },
      async cancel() { await source.return?.(undefined) },
    })
    headers['content-length'] = String(entry.size_bytes)
    headers['cache-control'] = 'no-store'
    headers['accept-encoding'] = 'identity'
    const options: RequestInit & { duplex: 'half' } = { method: 'PUT', headers, signal: AbortSignal.any([lifetime, requestAbort.signal]), redirect: 'error', credentials: 'omit', cache: 'no-store', duplex: 'half',
      ...(body ? { body } : { body: new Uint8Array(0) }) }
    const response = await fetch(uri, options)
    await response.body?.cancel()
    check()
    // A normal consumer drains EOF; a Content-Length consumer can stop after
    // the final, already-verified source chunk. The immutable scanner candidate
    // remains the server's authority for actual stored bytes.
    if (response.status < 200 || response.status >= 300 || bytes !== entry.size_bytes || hash.digest('hex') !== entry.sha256) throw new ProbeError('file.export_unavailable')
  } catch (error) {
    if (error instanceof ProbeError) throw error
    throw new ProbeError('file.export_unavailable')
  } finally { requestAbort.abort(); await source.return?.(undefined).catch(() => {}); await registry.release(entry.export_id, session, authority).catch(() => {}) }
}
