import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto'
import { basename, dirname, isAbsolute, resolve } from 'node:path'
import { inspect } from 'node:util'
import { z } from 'zod'
import { canonicalObject, parseSigningObject } from './canonical.js'
import { LinuxSecretServiceInstallationSigner } from './secret-service-installation-signer.js'
import { decodeSecretBase64, encodeSecretBase64, LinuxSecretServiceLookup, LinuxSecretServiceWriter } from './linux-secret-service.js'
import { assertLinuxPrivateDirectory, openLinuxPrivateDirectory, publishLinuxPrivateFile, readLinuxPrivateFile, type LinuxPrivateDirectory, type LinuxPrivateFile } from './linux-private-files.js'

type Code = 'unavailable' | 'cancelled' | 'exists' | 'busy' | 'outcome_unknown'
export class LinuxInstallationKeyError extends Error {
  readonly code: `host.installation_key.${Code}`
  constructor(code: `host.installation_key.${Code}`) {
    const allowed: Code[] = ['unavailable', 'cancelled', 'exists', 'busy', 'outcome_unknown']
    const safe = allowed.some(value => code === `host.installation_key.${value}`) ? code : 'host.installation_key.unavailable'
    super(safe); this.code = safe; this.name = 'LinuxInstallationKeyError'
  }
}
const failure = (code: Code = 'unavailable') => new LinuxInstallationKeyError(`host.installation_key.${code}`)
const coordinate = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value)
const jwk = z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: coordinate, y: coordinate })
const payloadSchema = z.strictObject({ version: z.literal(1), purpose: z.literal('dsh-host-installation-reference-v1'), path_hash: z.string().regex(/^[0-9a-f]{64}$/),
  service: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/), account: z.string().regex(/^installation-[0-9a-f]{48}$/), public_jwk: jwk })
const metadataSchema = payloadSchema.extend({ signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value) }).strict()
type Payload = z.infer<typeof payloadSchema>
const MAX_METADATA = 4096
const guardKey = Symbol.for('ustc.dsh.installation-key-paths.v1')
const globalState = globalThis as unknown as Record<symbol, unknown>
const existingGuards = globalState[guardKey]
if (existingGuards !== undefined && !(existingGuards instanceof Map)) throw new Error('installation key process guard unavailable')
const busyPaths = (existingGuards ?? new Map<string, symbol>()) as Map<string, symbol>
if (existingGuards === undefined) Object.defineProperty(globalThis, guardKey, { value: busyPaths, enumerable: false, writable: false, configurable: false })

export interface LinuxInstallationKeyOptions {
  /** Private absolute path for the public, signed key reference. */
  path: string
  /** Trusted absolute path to secret-tool. */
  executable: string
  /** Stable non-secret Secret Service namespace. */
  service: string
  /** Cancel when this local installation's owner lifecycle ends. */
  ownerSignal: AbortSignal
}

export interface LinuxInstallationIdentity {
  readonly publicJwk: Readonly<z.infer<typeof jwk>>
  readonly thumbprint: string
  readonly signer: LinuxSecretServiceInstallationSigner
  close(): void
}

class InstallationIdentity implements LinuxInstallationIdentity {
  readonly publicJwk: Readonly<z.infer<typeof jwk>>
  readonly thumbprint: string
  readonly signer: LinuxSecretServiceInstallationSigner
  constructor(publicJwk: z.infer<typeof jwk>, signer: LinuxSecretServiceInstallationSigner) {
    this.publicJwk = Object.freeze({ ...publicJwk })
    this.thumbprint = createHash('sha256').update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y })).digest('base64url')
    this.signer = signer
    Object.freeze(this)
  }
  close(): void { this.signer.close() }
  toString(): string { return 'LinuxInstallationIdentity' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
}

function pathHash(path: string): string {
  return createHash('sha256').update('dsh-host-installation-reference-v1\0').update(path).digest('hex')
}

function verifyMetadata(raw: Buffer, path: string, service: string): Payload {
  const value = metadataSchema.parse(parseSigningObject(raw))
  const payload = { version: value.version, purpose: value.purpose, path_hash: value.path_hash, service: value.service, account: value.account, public_jwk: value.public_jwk }
  if (payload.path_hash !== pathHash(path) || payload.service !== service) throw failure()
  const key = createPublicKey({ key: payload.public_jwk, format: 'jwk' })
  const signature = Buffer.from(value.signature, 'base64url')
  if (signature.length !== 64 || !verify('sha256', canonicalObject(payload), { key, dsaEncoding: 'ieee-p1363' }, signature)) throw failure()
  return payload
}

async function verifyUnchanged(directory: LinuxPrivateDirectory, name: string, expected: LinuxPrivateFile, signal: AbortSignal): Promise<void> {
  const current = await readLinuxPrivateFile(directory, name, MAX_METADATA, signal)
  if (!current) throw failure()
  try {
    if (current.dev !== expected.dev || current.ino !== expected.ino || !current.bytes.equals(expected.bytes)) throw failure()
  } finally { current.bytes.fill(0) }
}

async function waitForProof(signer: LinuxSecretServiceInstallationSigner, publicJwk: z.infer<typeof jwk>, signal: AbortSignal): Promise<void> {
  const challenge = randomBytes(32)
  let removeAbort = () => {}, proof: Buffer | undefined
  try {
    if (signal.aborted) throw failure('cancelled')
    const task = Promise.resolve().then(() => signer.sign(challenge))
    task.then(value => { if (signal.aborted && value instanceof Uint8Array) value.fill(0) }, () => {})
    const cancelled = new Promise<never>((_, reject) => {
      const abort = () => reject(failure('cancelled'))
      removeAbort = () => signal.removeEventListener('abort', abort)
      signal.addEventListener('abort', abort, { once: true })
      if (signal.aborted) abort()
    })
    proof = Buffer.from(await Promise.race([task, cancelled]))
    if (signal.aborted || proof.length !== 64 || !verify('sha256', challenge, { key: createPublicKey({ key: publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, proof)) throw failure()
  } finally { removeAbort(); challenge.fill(0); proof?.fill(0) }
}

/** Creates one local installation key only on explicit request; opening never
 * regenerates missing or inaccessible key material. */
export class LinuxInstallationKeyStore {
  readonly signal: AbortSignal
  #closed = new AbortController()
  #path: string
  #name: string
  #executable: string
  #service: string

  constructor(options: LinuxInstallationKeyOptions) {
    try {
      if (process.platform !== 'linux' || !options || typeof options.path !== 'string' || !isAbsolute(options.path) || options.path.includes('\0') || !(options.ownerSignal instanceof AbortSignal)) throw failure()
      this.#path = resolve(options.path)
      if (Buffer.byteLength(this.#path) > 8192 || this.#path === dirname(this.#path)) throw failure()
      this.#name = basename(this.#path)
      const reference = { executable: options.executable, service: options.service, account: `installation-${'0'.repeat(48)}` }
      new LinuxSecretServiceLookup(reference)
      this.#executable = resolve(reference.executable); this.#service = reference.service
      this.signal = AbortSignal.any([this.#closed.signal, options.ownerSignal])
      Object.freeze(this)
    } catch { throw failure() }
  }

  toString(): string { return 'LinuxInstallationKeyStore' }
  toJSON(): string { return this.toString() }
  [inspect.custom](): string { return this.toString() }
  close(): void { this.#closed.abort() }

  async #run<T>(caller: AbortSignal, action: (directory: LinuxPrivateDirectory, signal: AbortSignal) => Promise<T>): Promise<T> {
    if (!(caller instanceof AbortSignal)) throw failure()
    if (caller.aborted || this.signal.aborted) throw failure('cancelled')
    if (busyPaths.has(this.#path)) throw failure('busy')
    const token = Symbol('installation-key-operation')
    busyPaths.set(this.#path, token)
    const signal = AbortSignal.any([caller, this.signal, AbortSignal.timeout(15_000)])
    let directory: LinuxPrivateDirectory | undefined
    try {
      directory = await openLinuxPrivateDirectory(dirname(this.#path))
      if (signal.aborted) throw failure('cancelled')
      return await action(directory, signal)
    } catch (cause) {
      if (cause instanceof LinuxInstallationKeyError) throw new LinuxInstallationKeyError(cause.code)
      if (signal.aborted) throw failure('cancelled')
      throw failure()
    } finally {
      try { await directory?.file.close() } catch { throw failure() }
      finally { if (busyPaths.get(this.#path) === token) busyPaths.delete(this.#path) }
    }
  }

  async open(signal: AbortSignal): Promise<LinuxInstallationIdentity | undefined> {
    return await this.#run(signal, async (directory, lifetime) => {
      const stored = await readLinuxPrivateFile(directory, this.#name, MAX_METADATA, lifetime)
      if (!stored) return undefined
      let signer: LinuxSecretServiceInstallationSigner | undefined
      try {
        const payload = verifyMetadata(stored.bytes, this.#path, this.#service)
        signer = new LinuxSecretServiceInstallationSigner({ executable: this.#executable, service: payload.service, account: payload.account,
          publicJwk: payload.public_jwk, ownerSignal: this.signal })
        await waitForProof(signer, payload.public_jwk, lifetime)
        await verifyUnchanged(directory, this.#name, stored, lifetime)
        await assertLinuxPrivateDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
        const identity = new InstallationIdentity(payload.public_jwk, signer)
        signer = undefined
        return identity
      } finally { stored.bytes.fill(0); signer?.close() }
    })
  }

  async create(signal: AbortSignal): Promise<LinuxInstallationIdentity> {
    return await this.#run(signal, async (directory, lifetime) => {
      let written = false, signer: LinuxSecretServiceInstallationSigner | undefined
      let der: Buffer | undefined, encoded: Buffer | undefined, readback: Buffer | undefined, decoded: Buffer | undefined, metadata: Buffer | undefined
      try {
        const existing = await readLinuxPrivateFile(directory, this.#name, MAX_METADATA, lifetime)
        if (existing) { existing.bytes.fill(0); throw failure('exists') }
        if (lifetime.aborted) throw failure('cancelled')
        const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
        const publicJwk = jwk.parse(pair.publicKey.export({ format: 'jwk' }))
        const payload: Payload = { version: 1, purpose: 'dsh-host-installation-reference-v1', path_hash: pathHash(this.#path), service: this.#service,
          account: `installation-${randomBytes(24).toString('hex')}`, public_jwk: publicJwk }
        const signature = sign('sha256', canonicalObject(payload), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')
        metadata = Buffer.from(JSON.stringify({ ...payload, signature }), 'utf8')
        der = pair.privateKey.export({ format: 'der', type: 'pkcs8' })
        encoded = encodeSecretBase64(der)
        const reference = { executable: this.#executable, service: payload.service, account: payload.account }
        const writer = new LinuxSecretServiceWriter(reference), lookup = new LinuxSecretServiceLookup(reference)
        written = true
        await writer.store(encoded, lifetime)
        if (lifetime.aborted) throw failure('cancelled')
        readback = await lookup.lookup(2048, lifetime)
        decoded = decodeSecretBase64(readback, 1024)
        if (decoded.length !== der.length || !timingSafeEqual(decoded, der)) throw failure()
        der.fill(0); der = undefined; encoded.fill(0); encoded = undefined; readback.fill(0); readback = undefined; decoded.fill(0); decoded = undefined
        signer = new LinuxSecretServiceInstallationSigner({ ...reference, publicJwk, ownerSignal: this.signal })
        await waitForProof(signer, publicJwk, lifetime)
        const published = await publishLinuxPrivateFile(directory, this.#name, metadata, MAX_METADATA, lifetime)
        if (!published) throw failure('exists')
        const stored = await readLinuxPrivateFile(directory, this.#name, MAX_METADATA, lifetime)
        if (!stored) throw failure()
        try {
          const verified = verifyMetadata(stored.bytes, this.#path, this.#service)
          if (verified.account !== payload.account || JSON.stringify(verified.public_jwk) !== JSON.stringify(payload.public_jwk)) throw failure()
          await verifyUnchanged(directory, this.#name, stored, lifetime)
        } finally { stored.bytes.fill(0) }
        await directory.file.sync(); await assertLinuxPrivateDirectory(directory)
        if (lifetime.aborted) throw failure('cancelled')
        const identity = new InstallationIdentity(publicJwk, signer)
        signer = undefined
        return identity
      } catch (cause) {
        if (cause instanceof LinuxInstallationKeyError && cause.code === 'host.installation_key.exists') throw cause
        if (written) throw failure('outcome_unknown')
        if (lifetime.aborted) throw failure('cancelled')
        throw failure()
      } finally { der?.fill(0); encoded?.fill(0); readback?.fill(0); decoded?.fill(0); metadata?.fill(0); signer?.close() }
    })
  }
}
