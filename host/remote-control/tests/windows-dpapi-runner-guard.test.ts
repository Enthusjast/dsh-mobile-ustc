import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const runner = fileURLToPath(new URL('../../../tools/integration/run_windows_dpapi.py', import.meta.url))

test('native DPAPI Wine probe rejects unowned outputs or missing explicit tools before creating resources', () => {
  const output = resolve('.local', `never-create-dpapi-${randomUUID()}`)
  const tools = ['--compiler', '/not-installed/compiler', '--sdk-root', '/not-installed/sdk', '--wine', '/not-installed/wine', '--wineserver', '/not-installed/wineserver']
  for (const args of [[], [...tools, '--output', output], [...tools, '--output', '/never-create-dpapi-output']]) {
    const result = spawnSync('python3', [runner, ...args], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 2)
    assert.match(result.stderr, /error:/)
    assert.equal(result.stdout, '')
    assert.equal(existsSync(output), false)
  }
})

test('DPAPI fixture never inherits another Wine prefix, server or injected loader', () => {
  const script = `import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('owned_dpapi_probe',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
os.environ.update(WINEPREFIX='/other/prefix',WINESERVER='/other/server',WINELOADER='/other/loader',WINEDLLPATH='/other/dll',LD_PRELOAD='PRIVATE',DYLD_INSERT_LIBRARIES='PRIVATE',NODE_OPTIONS='PRIVATE')
env=module.owned_environment(Path('/owned/prefix'),Path('/owned/server'))
assert env['WINEPREFIX']=='/owned/prefix' and env['WINESERVER']=='/owned/server'
assert all(name not in env for name in ('WINELOADER','WINEDLLPATH','LD_PRELOAD','DYLD_INSERT_LIBRARIES','NODE_OPTIONS'))
print('owned-only')`
  const result = spawnSync('python3', ['-c', script, runner], { encoding: 'utf8', timeout: 5000 })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), 'owned-only')
})
