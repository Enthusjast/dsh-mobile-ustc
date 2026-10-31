import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID, X509Certificate } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { chmod, lstat, mkdtemp, readFile, readdir, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { relayNodeFixtures } from '../../../tools/integration/relay-node-fixture.js'

const runner = fileURLToPath(new URL('../../../tools/integration/run_remote_dsh.py', import.meta.url))
const terminal = fileURLToPath(new URL('../../../tools/integration/run_host_enrollment_terminal.py', import.meta.url))

test('certificate renewal requires an explicit independent native composition before opening resources', () => {
  const base = ['--relay-certificate-renewal', '--cross-node', '--dsh-only']
  for (const args of [
    ['--relay-certificate-renewal'], ['--relay-certificate-renewal', '--dsh-only'], ['--relay-certificate-renewal', '--cross-node'],
    ...['--host-renewal', '--installation-revoke', '--host-account-retire', '--database-outage', '--relay-crash', '--kotlin-relay'].map(mode => [...base, mode]),
    [...base, '--go-run', '^Test'], [...base, '--relay-load', '4', '--load-output', '/never-create-certificate-load'],
  ]) {
    const result = spawnSync('python3', [runner, ...args], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 2)
    assert.match(result.stderr, /error:/)
    assert.doesNotMatch(result.stderr, /Traceback|initdb|Install JDK/)
    assert.equal(result.stdout, '')
  }
  const output = '/never-create-native-relay-certificate.log'
  for (const mode of ['--renewal', '--installation-revoke', '--host-account-retire', '--database-outage', '--relay-crash']) {
    const result = spawnSync('python3', [terminal, '--relay-certificate-renewal', mode, '--output', output], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 2)
    assert.match(result.stderr, /separate composition runs/)
    assert.equal(result.stdout, '')
    assert.equal(existsSync(output), false)
  }
})

test('owned leaf renewal replaces certificate and key while keeping CA, identity, config and private permissions', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'clients-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const id = randomUUID(), nodes = [{ id, address: '127.0.0.1:1' }]
  const fixture = await relayNodeFixtures(root, nodes)
  const configuration = await readFile(fixture.configs[0]!, 'utf8')
  const originalAuthority = new X509Certificate(await readFile(join(root, 'relay-ca.pem'))).fingerprint256
  nodes[0]!.id = randomUUID()
  nodes[0]!.address = 'untrusted.example:443'
  const renewed = await fixture.renew(0)
  assert.notEqual(renewed.fingerprint, renewed.previousFingerprint)
  assert.equal(renewed.authorityFingerprint, originalAuthority)
  const leaf = new X509Certificate(await readFile(join(root, 'relay-0.pem')))
  assert.equal(leaf.fingerprint256, renewed.fingerprint)
  assert.ok(leaf.subjectAltName?.includes(`URI:spiffe://dsh-remote/relay/${id}`))
  assert.equal(await readFile(fixture.configs[0]!, 'utf8'), configuration)
  for (const name of ['relay-ca.key', 'relay-ca.pem', 'relay-0.key', 'relay-0.pem', 'relay-0.json']) {
    assert.equal((await lstat(join(root, name))).mode & 0o777, 0o600)
  }
  for (const index of [-1, 1, 0.5]) await assert.rejects(fixture.renew(index), /fixture node index/)
  await assert.rejects(fixture.peerFingerprint(1, 0), /fixture node index/)
  assert.equal((await readdir(root)).some(name => name.startsWith('relay-stage-')), false)
})

test('credential fixtures reject exposed directories, symlink roots and non-loopback selectors without writes', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'clients-'))
  const alias = root + '-alias'
  t.after(async () => { await rm(alias, { force: true }); await rm(root, { recursive: true, force: true }) })
  const node = { id: randomUUID(), address: '127.0.0.1:1' }
  await chmod(root, 0o755)
  await assert.rejects(relayNodeFixtures(root, [node]), /owned private fixture/)
  await chmod(root, 0o700)
  await symlink(root, alias)
  await assert.rejects(relayNodeFixtures(alias, [node]), /owned private fixture/)
  for (const address of ['0.0.0.0:8444', 'example.invalid:8444', '127.0.0.1:65536']) {
    await assert.rejects(relayNodeFixtures(root, [{ ...node, address }]), /bounded loopback/)
  }
  await assert.rejects(relayNodeFixtures(root, [node, node]), /bounded loopback/)
  assert.deepEqual(await readdir(root), [])
})
