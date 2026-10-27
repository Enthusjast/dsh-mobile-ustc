import { execFileSync } from 'node:child_process'
import { chmod, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

// Disposable local credentials only, issued by an isolated cluster CA. No
// certificate/key material is printed or copied into repository fixtures.
export async function relayNodeFixtures(root: string, nodes: { id: string; address: string }[]) {
  const openssl = (args: string[]) => execFileSync('openssl', args, { stdio: 'pipe' })
  const ca = join(root, 'relay-ca.pem'), caKey = join(root, 'relay-ca.key')
  openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-sha256', '-days', '1',
    '-subj', '/CN=Isolated DSH Relay CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', ca])
  await chmod(ca, 0o600)
  await chmod(caKey, 0o600)
  const paths: string[] = []
  for (const [index, node] of nodes.entries()) {
    const key = join(root, `relay-${index}.key`), csr = join(root, `relay-${index}.csr`), cert = join(root, `relay-${index}.pem`)
    const extensions = join(root, `relay-${index}.ext`), config = join(root, `relay-${index}.json`)
    await writeFile(extensions, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,URI:spiffe://dsh-remote/relay/${node.id}\n`, { mode: 0o600 })
    openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=Isolated DSH Relay Node', '-keyout', key, '-out', csr])
    openssl(['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-set_serial', String(index + 2), '-days', '1', '-sha256', '-extfile', extensions, '-out', cert])
    await chmod(key, 0o600)
    await chmod(cert, 0o600)
    await writeFile(config, JSON.stringify({ listen_addr: node.address, origin: `https://${node.address}`, ca_file: ca, certificate_file: cert, key_file: key, max_proxy_connections: 32 }), { mode: 0o600 })
    paths.push(config)
  }
  return paths
}
