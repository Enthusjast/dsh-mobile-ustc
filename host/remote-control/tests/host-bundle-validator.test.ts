import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

test('offline Host bundle verification rejects unsafe archives, untrusted manifests and dirty runtime inputs', { skip: process.platform === 'win32' }, () => {
  const directory = fileURLToPath(new URL('../../../tools/release/', import.meta.url))
  const result = spawnSync('python3', ['-m', 'unittest', 'discover', '-s', directory, '-p', 'test_host_bundle.py'], { encoding: 'utf8', timeout: 20_000 })
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /Ran 7 tests/)
})

test('packaged Host runner arguments fail before creating composition resources', () => {
  const runner = fileURLToPath(new URL('../../../tools/integration/run_remote_dsh.py', import.meta.url))
  const terminal = fileURLToPath(new URL('../../../tools/integration/run_host_enrollment_terminal.py', import.meta.url))
  const pair = ['--host-bundle-directory', '/never-existing-host-bundle', '--host-bundle-manifest-sha256', 'a'.repeat(64)]
  for (const args of [pair, ['--dsh-only', '--host-bundle-directory', '/never-existing-host-bundle'],
    ['--dsh-only', ...pair], ['--dsh-only', ...pair, '--go-run', '^Test']]) {
    const result = spawnSync('python3', [runner, ...args], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 2)
    assert.match(result.stderr, /error:/)
    assert.doesNotMatch(result.stderr, /Traceback|initdb/)
    assert.equal(result.stdout, '')
  }
  const output = '/never-create-host-bundle-terminal.log'
  const result = spawnSync('python3', [terminal, '--host-bundle-directory', '/never-existing-host-bundle', '--output', output], { encoding: 'utf8', timeout: 5000 })
  assert.equal(result.status, 2)
  assert.equal(existsSync(output), false)
})
