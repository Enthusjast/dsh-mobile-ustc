import { constants, type BigIntStats } from 'node:fs'
import { open, statfs, type FileHandle } from 'node:fs/promises'
import { isAbsolute, normalize } from 'node:path'
import { createHash } from 'node:crypto'
import { fileManifest } from './file-admission.js'
import { ProbeError } from './protocol.js'

export function exportPart(value: string): boolean { return fileManifest.shape.name.safeParse(value).success }
export async function exportFilesystemSupported(): Promise<boolean> {
  return process.platform === 'linux' && await statfs('/proc/self/fd').then(info => info.type === 0x9fa0, () => false)
}
export function exportVersion(info: BigIntStats): string {
  return createHash('sha256').update([info.dev, info.ino, info.size, info.mode, info.mtimeNs, info.ctimeNs, info.nlink].join(':')).digest('hex')
}

/** Kernel-relative traversal of Host-owned selectors, never a phone path. */
export async function openExportHandle(root: string, selected: readonly string[], directory: boolean, signal: AbortSignal, current: () => void): Promise<FileHandle> {
  signal.throwIfAborted(); current()
  const parts = [...selected], roots = root === '/' ? [] : root.split('/').slice(1)
  if (!isAbsolute(root) || normalize(root) !== root || parts.length > 32 || !directory && parts.length === 0 || ![...roots, ...parts].every(exportPart)) throw new ProbeError('file.export_invalid')
  if (!await exportFilesystemSupported()) throw new ProbeError('file.export_unsupported')
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  let handle: FileHandle | undefined
  try {
    handle = await open('/', flags | constants.O_DIRECTORY)
    const all = [...roots, ...parts]
    for (let index = 0; index < all.length; index++) {
      signal.throwIfAborted(); current()
      const previous = handle
      handle = await open(`/proc/self/fd/${previous.fd}/${all[index]!}`, flags | (directory || index + 1 < all.length ? constants.O_DIRECTORY : 0))
      await previous.close()
    }
    signal.throwIfAborted(); current()
    const result = handle; handle = undefined; return result
  } catch (error) {
    signal.throwIfAborted()
    if (error instanceof ProbeError) throw error
    throw new ProbeError('file.export_unavailable')
  } finally { await handle?.close().catch(() => {}) }
}
