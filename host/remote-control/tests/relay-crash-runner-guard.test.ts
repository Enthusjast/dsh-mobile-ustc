import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const runner = fileURLToPath(new URL('../../../tools/integration/run_remote_dsh.py', import.meta.url))
const terminal = fileURLToPath(new URL('../../../tools/integration/run_host_enrollment_terminal.py', import.meta.url))

test('relay crash requires an explicit independent two-node native composition before opening resources', () => {
  const base = ['--relay-crash', '--cross-node', '--dsh-only']
  for (const args of [
    ['--relay-crash'], ['--relay-crash', '--dsh-only'], ['--relay-crash', '--cross-node'],
    ...['--host-renewal', '--installation-revoke', '--host-account-retire', '--database-outage', '--kotlin-relay'].map(flag => [...base, flag]),
    [...base, '--go-run', '^Test'], [...base, '--relay-load', '4', '--load-output', '/never-create-relay-crash-load'],
  ]) {
    const result = spawnSync('python3', [runner, ...args], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 2, 'invalid fault composition did not stop at argument validation')
    assert.match(result.stderr, /error:/)
    assert.doesNotMatch(result.stderr, /Traceback|initdb|Install JDK/)
    assert.equal(result.stdout, '')
  }
})

test('terminal crash wrapper rejects combinations before creating its output or terminal child', () => {
  const output = '/never-create-native-relay-crash-guard.log'
  assert.equal(existsSync(output), false)
  for (const mode of ['--renewal', '--installation-revoke', '--host-account-retire', '--database-outage']) {
    const result = spawnSync('python3', [terminal, '--relay-crash', mode, '--output', output], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 2)
    assert.match(result.stderr, /separate composition runs/)
    assert.equal(result.stdout, '')
    assert.equal(existsSync(output), false)
  }
})
