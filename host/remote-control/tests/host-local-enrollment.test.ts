import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

test('local enrollment requires an exact fresh response on a controlling terminal', { skip: process.platform !== 'linux', timeout: 30_000 }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-host-terminal-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const script = join(root, 'client.mts')
  const module = pathToFileURL(resolve('host/remote-control/src/host-local-enrollment.ts')).href
  const fingerprint = Buffer.alloc(32, 1).toString('base64url')
  const review = { enrollment: {
    organization_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', organization_name: '组织\u001b[2J\n名称',
    host_id: '11111111-1111-4111-8111-111111111111', host_alias: '办公主机', installation_id: '22222222-2222-4222-8222-222222222222',
    installation_key_jkt: fingerprint, runtime_id: '33333333-3333-4333-8333-333333333333', profile_ref: 'profile',
    state: 'user_confirmed', expires_at: new Date(Date.now() + 60_000).toISOString(), host_confirmed: false, user_confirmed: true,
    workspaces: [{ reference: 'project', workspace_id: '44444444-4444-4444-8444-444444444444' }],
  }, confirmed_user: { user_id: '55555555-5555-4555-8555-555555555555', issuer: 'https://id.example.edu', subject: 'alice\u202e\nPRIVATE_SUBJECT', eligible: true } }
  await writeFile(script, [
    `import { approveHostEnrollmentOnTerminal } from ${JSON.stringify(module)}`,
    `const review=${JSON.stringify(review)},mode=process.argv[2],signal=AbortSignal.timeout(mode==='cancel'?700:4000)`,
    "try{const first=approveHostEnrollmentOnTerminal(review,signal);let second;if(mode==='concurrent'){try{await approveHostEnrollmentOnTerminal(review,signal)}catch(error){second=error.code}}const approved=await first;process.stdout.write(JSON.stringify({approved,second})+'\\n')}catch(error){process.stdout.write(JSON.stringify({error:error.code})+'\\n')}", '',
  ].join('\n'), { mode: 0o600 })
  const driver = resolve('host/remote-control/tests/fixtures/host-terminal-pty.py')
  const run = async (mode: string) => {
    const child = spawn('python3', [driver, mode, resolve('node_modules/.bin/tsx'), script],
      { cwd: root, env: { PATH: process.env.PATH ?? '', TMPDIR: root }, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    child.stdout.setEncoding('utf8').on('data', value => { stdout = (stdout + value).slice(-100_000) })
    child.stderr.setEncoding('utf8').on('data', value => { stderr = (stderr + value).slice(-4096) })
    const [exit] = await once(child, 'close')
    assert.equal(exit, 0, `terminal driver failed (${mode}): ${stderr}`)
    const result = JSON.parse(stdout) as { exit: number; stdout: string; stderr: string; terminal: string }
    assert.equal(result.exit, 0, 'terminal client failed')
    assert.equal(result.stdout.includes('PRIVATE_SUBJECT'), false)
    return { value: JSON.parse(result.stdout) as { approved?: boolean; error?: string; second?: string },
      terminal: Buffer.from(result.terminal, 'base64').toString('utf8') }
  }
  const accepted = await run('accept')
  assert.equal(accepted.value.approved, true)
  assert.ok(accepted.terminal.includes('\\u{1B}')); assert.ok(accepted.terminal.includes('\\u{A}')); assert.ok(accepted.terminal.includes('\\u{202E}'))
  assert.equal(accepted.terminal.includes('\u001b'), false); assert.equal(accepted.terminal.includes('\u202e'), false)
  assert.ok(accepted.terminal.includes(fingerprint))
  for (const mode of ['decline', 'long', 'preload']) assert.equal((await run(mode)).value.approved, false, mode)
  assert.equal((await run('cancel')).value.error, 'host.local_enrollment.cancelled')
  assert.equal((await run('no-tty')).value.error, 'host.local_enrollment.unavailable')
  const concurrent = await run('concurrent')
  assert.equal(concurrent.value.approved, true); assert.equal(concurrent.value.second, 'host.local_enrollment.busy')
})
