import { execFileSync } from 'node:child_process'
import { createPublicKey, randomBytes, X509Certificate } from 'node:crypto'
import { chmod, lstat, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { connect } from 'node:tls'

// These credentials belong only to a disposable, private fixture tree. No
// external path, process, CA or replacement identity is accepted by renew().
export async function relayNodeFixtures(root: string, nodes: { id: string; address: string }[]) {
  const metadata = await lstat(root)
  if (await realpath(root) !== root || !metadata.isDirectory() || metadata.isSymbolicLink()
    || metadata.uid !== process.getuid?.() || (metadata.mode & 0o777) !== 0o700 || !/^clients-[A-Za-z0-9_-]+$/.test(basename(root))) {
    throw new Error('relay credentials require an owned private fixture directory')
  }
  if (nodes.length < 1 || nodes.length > 2 || new Set(nodes.map(node => node.id)).size !== nodes.length
    || nodes.some(node => !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(node.id)
      || !/^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(node.address) || Number(node.address.split(':')[1]) > 65535)) {
    throw new Error('relay credentials require bounded loopback fixture nodes')
  }
  // Copy inputs: caller mutation must not change the identity selected at creation.
  const owned = nodes.map(node => ({ ...node }))
  const openssl = (args: string[]) => execFileSync('openssl', args, { stdio: 'pipe' })
  const ca = join(root, 'relay-ca.pem'), caKey = join(root, 'relay-ca.key')
  openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-sha256', '-days', '1',
    '-subj', '/CN=Isolated DSH Relay CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', ca])
  await chmod(ca, 0o600); await chmod(caKey, 0o600)
  const authorityFingerprint = new X509Certificate(await readFile(ca)).fingerprint256
  const indexOf = (index: number) => {
    if (!Number.isInteger(index) || index < 0 || index >= owned.length) throw new Error('relay fixture node index is invalid')
    return owned[index]!
  }
  const keyPath = (index: number) => join(root, `relay-${index}.key`)
  const certificatePath = (index: number) => join(root, `relay-${index}.pem`)
  const issue = async (index: number) => {
    const node = indexOf(index)
    if (new X509Certificate(await readFile(ca)).fingerprint256 !== authorityFingerprint) throw new Error('relay fixture authority changed')
    const stage = await mkdtemp(join(root, `relay-stage-${index}-`))
    try {
      const key = join(stage, 'key.pem'), csr = join(stage, 'request.pem'), certificate = join(stage, 'certificate.pem'), extensions = join(stage, 'extensions')
      await writeFile(extensions, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,URI:spiffe://dsh-remote/relay/${node.id}\n`, { mode: 0o600 })
      openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=Isolated DSH Relay Node', '-keyout', key, '-out', csr])
      openssl(['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-set_serial', `0x${randomBytes(16).toString('hex')}`, '-days', '1', '-sha256', '-extfile', extensions, '-out', certificate])
      await chmod(key, 0o600); await chmod(certificate, 0o600)
      openssl(['verify', '-CAfile', ca, '-purpose', 'sslclient', certificate])
      openssl(['verify', '-CAfile', ca, '-purpose', 'sslserver', '-verify_ip', '127.0.0.1', certificate])
      const leaf = new X509Certificate(await readFile(certificate))
      const publicKey = createPublicKey(await readFile(key)).export({ type: 'spki', format: 'der' })
      if (!publicKey.equals(leaf.publicKey.export({ type: 'spki', format: 'der' }))) throw new Error('relay fixture certificate and key differ')
      // The selected owned node must already be stopped. This is a two-file
      // replacement, not a promise of atomic live reload or power-loss recovery.
      await rename(key, keyPath(index)); await rename(certificate, certificatePath(index))
      return leaf
    } finally { await rm(stage, { recursive: true, force: true }) }
  }
  const configs: string[] = []
  for (const [index, node] of owned.entries()) {
    await issue(index)
    const config = join(root, `relay-${index}.json`)
    await writeFile(config, JSON.stringify({ listen_addr: node.address, origin: `https://${node.address}`, ca_file: ca,
      certificate_file: certificatePath(index), key_file: keyPath(index), max_proxy_connections: 32 }), { mode: 0o600 })
    configs.push(config)
  }
  return {
    configs,
    async renew(index: number) {
      indexOf(index)
      const previous = new X509Certificate(await readFile(certificatePath(index)))
      const next = await issue(index)
      if (previous.fingerprint256 === next.fingerprint256 || previous.publicKey.export({ type: 'spki', format: 'der' }).equals(next.publicKey.export({ type: 'spki', format: 'der' }))) {
        throw new Error('relay fixture renewal did not replace certificate and key')
      }
      return { previousFingerprint: previous.fingerprint256, fingerprint: next.fingerprint256, authorityFingerprint }
    },
    async peerFingerprint(target: number, peer: number): Promise<string> {
      const node = indexOf(target); indexOf(peer)
      const [certificate, key, roots] = await Promise.all([readFile(certificatePath(peer)), readFile(keyPath(peer)), readFile(ca)])
      return new Promise((accept, reject) => {
        const socket = connect({ host: '127.0.0.1', port: Number(node.address.split(':')[1]), minVersion: 'TLSv1.3',
          cert: certificate, key, ca: roots, rejectUnauthorized: true })
        socket.setTimeout(3000, () => socket.destroy(new Error('fixture mutual TLS handshake timed out')))
        socket.once('error', () => { socket.destroy(); reject(new Error('fixture mutual TLS handshake failed')) })
        socket.once('secureConnect', () => {
          const fingerprint = socket.getPeerCertificate().fingerprint256
          if (!socket.authorized || !fingerprint) { socket.destroy(); reject(new Error('fixture peer is unverified')); return }
          accept(fingerprint); socket.end()
        })
      })
    },
  }
}
