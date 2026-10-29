import { randomBytes } from 'node:crypto'
import { constants, type Stats } from 'node:fs'
import { link, lstat, mkdir, open, opendir, realpath, unlink, type FileHandle } from 'node:fs/promises'
import { dirname } from 'node:path'

const failure = () => new Error('private file unavailable')
export type LinuxPrivateDirectory = { file: FileHandle; path: string; proc: string; dev: number; ino: number }
export type LinuxPrivateFile = { bytes: Buffer; dev: number; ino: number }

export async function assertLinuxPrivateDirectory(directory: LinuxPrivateDirectory): Promise<void> {
  const entry = await lstat(directory.path)
  if (!entry.isDirectory() || entry.isSymbolicLink() || entry.uid !== process.getuid?.() || (entry.mode & 0o7777) !== 0o700 ||
      entry.dev !== directory.dev || entry.ino !== directory.ino || await realpath(directory.path) !== directory.path) throw failure()
}

export async function openLinuxPrivateDirectory(path: string): Promise<LinuxPrivateDirectory> {
  if (process.platform !== 'linux' || typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_DIRECTORY !== 'number' || process.getuid?.() === undefined) throw failure()
  await mkdir(path, { recursive: true, mode: 0o700 })
  if (await realpath(path) !== path) throw failure()
  const uid = process.getuid!()
  let ancestor = path, immediate = true
  for (;;) {
    const entry = await lstat(ancestor)
    if (!entry.isDirectory() || entry.isSymbolicLink() || (entry.uid !== 0 && entry.uid !== uid) ||
        (immediate && (entry.uid !== uid || (entry.mode & 0o7777) !== 0o700)) ||
        (!immediate && (entry.mode & 0o022) !== 0 && (entry.mode & 0o1000) === 0)) throw failure()
    const parent = dirname(ancestor)
    if (parent === ancestor) break
    ancestor = parent; immediate = false
  }
  const before = await lstat(path)
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  try {
    const actual = await file.stat()
    if (!actual.isDirectory() || actual.dev !== before.dev || actual.ino !== before.ino || actual.uid !== uid || (actual.mode & 0o7777) !== 0o700) throw failure()
    const directory = { file, path, proc: `/proc/self/fd/${file.fd}`, dev: actual.dev, ino: actual.ino }
    await assertLinuxPrivateDirectory(directory)
    return directory
  } catch (error) { await file.close(); throw error }
}

function validName(name: string): boolean {
  return name.length > 0 && name !== '.' && name !== '..' && !name.includes('/') && !name.includes('\0') && Buffer.byteLength(name) <= 255
}
function privateFile(info: Stats, max: number): boolean {
  return info.isFile() && info.uid === process.getuid?.() && (info.mode & 0o7777) === 0o600 && info.size <= max
}

// An interrupted link-based publication can leave its own temporary hard link.
// Remove only matching temporary names for this exact inode, never other aliases.
async function cleanPublicationLinks(directory: LinuxPrivateDirectory, name: string, file: FileHandle, max: number): Promise<void> {
  const initial = await file.stat()
  if (initial.nlink === 1) return
  if (initial.nlink < 1 || initial.nlink > 16) throw failure()
  const prefix = `.${name}.`, entries = await opendir(directory.proc)
  let count = 0, removed = false
  try {
    for await (const entry of entries) {
      if (++count > 4096) throw failure()
      if (!entry.name.startsWith(prefix) || !/^[0-9a-f]{32}\.tmp$/.test(entry.name.slice(prefix.length))) continue
      const path = `${directory.proc}/${entry.name}`
      let candidate
      try { candidate = await lstat(path) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error }
      if (!privateFile(candidate, max) || candidate.dev !== initial.dev || candidate.ino !== initial.ino) continue
      try { await unlink(path); removed = true } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    }
  } finally { await entries.close().catch(() => {}) }
  if (removed) await directory.file.sync()
  const after = await file.stat()
  if (!privateFile(after, max) || after.dev !== initial.dev || after.ino !== initial.ino || after.nlink !== 1) throw failure()
}

/** Returned bytes belong to the caller and must be cleared when sensitive. */
export async function readLinuxPrivateFile(directory: LinuxPrivateDirectory, name: string, max: number, signal: AbortSignal): Promise<LinuxPrivateFile | undefined> {
  if (!validName(name) || !Number.isSafeInteger(max) || max < 1 || max > 64 * 1024 || signal.aborted) throw failure()
  const path = `${directory.proc}/${name}`
  let before
  try { before = await lstat(path) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error }
  if (!privateFile(before, max) || before.isSymbolicLink() || before.size < 1) throw failure()
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const actual = await file.stat()
    if (!privateFile(actual, max) || actual.dev !== before.dev || actual.ino !== before.ino || actual.size !== before.size) throw failure()
    await cleanPublicationLinks(directory, name, file, max)
    const buffer = Buffer.alloc(max + 1)
    try {
      let length = 0
      while (length < buffer.length) {
        if (signal.aborted) throw failure()
        const { bytesRead } = await file.read(buffer, length, buffer.length - length, null)
        if (bytesRead === 0) break
        length += bytesRead
      }
      const after = await file.stat()
      if (!privateFile(after, max) || after.dev !== actual.dev || after.ino !== actual.ino || after.size !== actual.size || after.nlink !== 1 || length !== actual.size || length > max) throw failure()
      await assertLinuxPrivateDirectory(directory)
      if (signal.aborted) throw failure()
      await file.sync()
      const current = await lstat(path)
      if (!privateFile(current, max) || current.nlink !== 1 || current.dev !== actual.dev || current.ino !== actual.ino || current.size !== actual.size) throw failure()
      return { bytes: Buffer.from(buffer.subarray(0, length)), dev: actual.dev, ino: actual.ino }
    } finally { buffer.fill(0) }
  } finally { await file.close() }
}

/** Publish fully synchronized bytes without replacing an existing entry. */
export async function publishLinuxPrivateFile(directory: LinuxPrivateDirectory, name: string, bytes: Uint8Array, max: number, signal: AbortSignal): Promise<boolean> {
  if (!validName(name) || !(bytes instanceof Uint8Array) || !Number.isSafeInteger(max) || max < 1 || max > 64 * 1024 || bytes.length < 1 || bytes.length > max || signal.aborted) throw failure()
  const temporary = `${directory.proc}/.${name}.${randomBytes(16).toString('hex')}.tmp`
  let owned: { dev: number; ino: number } | undefined
  try {
    const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    try {
      const info = await file.stat(); owned = { dev: info.dev, ino: info.ino }
      if (!privateFile(info, max) || info.nlink !== 1) throw failure()
      await file.writeFile(bytes); await file.sync()
    } finally { await file.close() }
    if (signal.aborted) throw failure()
    let created = true
    try { await link(temporary, `${directory.proc}/${name}`) }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; created = false }
    try {
      const current = await lstat(temporary)
      if (!owned || current.dev !== owned.dev || current.ino !== owned.ino) throw failure()
      await unlink(temporary); owned = undefined
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
    if (signal.aborted) throw failure()
    return created
  } finally {
    if (owned) {
      try {
        const current = await lstat(temporary)
        if (current.dev === owned.dev && current.ino === owned.ino) { await unlink(temporary); await directory.file.sync() }
      } catch { /* An absent or replaced temporary entry is not removed. */ }
    }
  }
}

export async function unlinkLinuxPrivateFile(directory: LinuxPrivateDirectory, name: string, stored: LinuxPrivateFile, max: number, signal: AbortSignal): Promise<void> {
  if (!validName(name) || signal.aborted) throw failure()
  const path = `${directory.proc}/${name}`, current = await lstat(path)
  if (!privateFile(current, max) || current.nlink !== 1 || current.dev !== stored.dev || current.ino !== stored.ino) throw failure()
  await assertLinuxPrivateDirectory(directory)
  if (signal.aborted) throw failure()
  await unlink(path); await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
  if (signal.aborted) throw failure()
}
