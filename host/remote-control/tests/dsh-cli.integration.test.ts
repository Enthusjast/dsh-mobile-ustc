import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { once } from 'node:events'
import { randomUUID } from 'node:crypto'
import { access, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { request } from 'node:http'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const dshPackage = dirname(require.resolve('@deepseek-ai/dsh/package.json'))
const dshBin = join(dshPackage, 'lib/bin.js')
const pluginEntry = resolve('host/remote-control/lib/index.js')
const modelFixture = fileURLToPath(new URL('./fixtures/dsh-local-model.mjs', import.meta.url))
const RESPONSE = 'DSH local integration fixture response'

function requestFrames(socketPath: string, method: string, path: string, body?: unknown) {
  return new Promise<{ status: number; frames: any[] }>((accept, reject) => {
    const req = request({ socketPath, method, path, headers: body === undefined ? {} : { 'content-type': 'application/json' } }, response => {
      const chunks: Buffer[] = []
      response.on('data', chunk => chunks.push(Buffer.from(chunk)))
      response.on('end', () => {
        try { accept({
          status: response.statusCode!,
          frames: Buffer.concat(chunks).toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)),
        }) } catch (error) { reject(error) }
      })
      response.on('error', reject)
    })
    req.setTimeout(5000, () => req.destroy(new Error('local DSH request timed out')))
    req.on('error', reject)
    req.end(body === undefined ? undefined : JSON.stringify(body))
  })
}

function waitForLine(iterator: AsyncIterator<string>, timeoutMs = 10_000) {
  let timer: NodeJS.Timeout | undefined
  return Promise.race([
    iterator.next(),
    new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('DSH stream timed out')), timeoutMs); timer.unref() }),
  ]).finally(() => { if (timer) clearTimeout(timer) })
}

async function waitForTurnEnd(iterator: AsyncIterator<string>) {
  for (;;) {
    const line = await waitForLine(iterator)
    const frame = JSON.parse(line.value!)
    if (frame.type === 'session.event' && frame.payload.type === 'turn/end') return frame.payload.data
  }
}

function withTimeout<Value>(value: Promise<Value>, timeoutMs: number): Promise<Value | undefined> {
  let timer: NodeJS.Timeout | undefined
  return Promise.race([
    value,
    new Promise<undefined>(resolve => { timer = setTimeout(() => resolve(undefined), timeoutMs) }),
  ]).finally(() => { if (timer) clearTimeout(timer) })
}

async function startSubscription(socketPath: string, body: unknown) {
  const req = request({ socketPath, path: '/m0/command', method: 'POST', headers: { 'content-type': 'application/json' } })
  req.end(JSON.stringify(body))
  const [response] = await once(req, 'response')
  const reader = createInterface({ input: response })
  return { req, response, reader, iterator: reader[Symbol.asyncIterator]() }
}

function safeTail(value: string): string {
  return value
    .replace(/([?&](?:token|access_token|key|secret)=)[^&\s]+/gi, '$1[redacted]')
    .split(/\r?\n/).slice(-8).join('\n')
}

async function waitForInteraction(command: (type: string, payload: unknown, sessionId?: string) => Promise<any>, failureDetail = '') {
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = await command('interaction.list', {})
    if (result.payload.items?.length) return result.payload.items[0]
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error(`the real DSH Tool Runtime did not create a pending interaction. ${failureDetail}`)
}

test('DSH CLI 0.2.1-rc.2 loads the plugin and completes a local session round trip', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-mobile-cli-integration-'))
  const home = join(root, 'dsh-home')
  const workspace = join(root, 'workspace')
  const socketPath = process.platform === 'win32'
    ? `\\\\.\\pipe\\dsh-mobile-ustc-${randomUUID()}`
    : join(root, 'ipc', 'remote.sock')
  await mkdir(workspace)
  const runtimeId = randomUUID()
  const patchPath = join(root, 'remote-control.patch.yml')
  const quote = (value: string) => JSON.stringify(value)
  const patch = [
    '- insert:',
    '    - id: dsh-m0-model-fixture',
    `      name: ${quote(modelFixture)}`,
    '    - id: ustc-remote-control',
    `      name: ${quote(pluginEntry)}`,
    '      config:',
    '        enabled: true',
    `        runtimeId: ${runtimeId}`,
    `        socketPath: ${quote(socketPath)}`,
    '        workspaces:',
    '          - id: probe',
    `            cwd: ${quote(workspace)}`,
    '        presets: [standard]',
    '        highRiskTools: [bash, pwsh, run_code]',
    '- id: agent-default-model',
    '  config:',
    '    provider: dsh-m0-test',
    '    model: offline',
    '',
  ].join('\n')
  await writeFile(patchPath, patch, { mode: 0o600 })
  const environment: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? '',
    DSH_HOME: home,
    DSH_TELEMETRY_DISABLED: '1',
    NO_COLOR: '1',
    HOME: join(root, 'host-home'),
    TMPDIR: root,
    TMP: root,
    TEMP: root,
    ...(process.platform === 'win32' ? {
      SystemRoot: process.env.SystemRoot,
      ComSpec: process.env.ComSpec,
      USERPROFILE: join(root, 'host-home'),
      APPDATA: join(root, 'host-home', 'AppData', 'Roaming'),
      LOCALAPPDATA: join(root, 'host-home', 'AppData', 'Local'),
    } : {}),
  }
  const child = spawn(process.execPath, [dshBin, '--profile', 'm0-probe', '--from-default-profile', 'web', '--patch', patchPath,
    '--host', '127.0.0.1', '--port', '0', '--no-open'], { cwd: process.cwd(), env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout = (stdout + chunk).slice(-32_768) })
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-32_768) })
  const exited = once(child, 'exit')
  const subscriptions: Awaited<ReturnType<typeof startSubscription>>[] = []
  let completed = false
  try {
    const deadline = Date.now() + 30_000
    let probe: any
    while (Date.now() < deadline) {
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`DSH CLI exited before the local probe opened (${child.exitCode ?? child.signalCode}); ${safeTail(stderr)}`)
      }
      try {
        const response = await requestFrames(socketPath, 'GET', '/m0/probe')
        if (response.status === 200 && response.frames[0]?.type === 'probe') { probe = response.frames[0]; break }
      } catch { await new Promise(resolve => setTimeout(resolve, 100)) }
    }
    assert.ok(probe, `DSH CLI did not open its probe before timeout; ${safeTail(stdout)} ${safeTail(stderr)}`)
    assert.equal(probe.payload.dsh_version, '0.2.1-rc.2')

    const command = async (type: string, payload: unknown, sessionId?: string) => {
      const body = { v: 0, type, request_id: randomUUID(), runtime_epoch: probe.runtime_epoch,
        payload, ...(sessionId === undefined ? {} : { session_id: sessionId }) }
      const result = await requestFrames(socketPath, 'POST', '/m0/command', body)
      const frame = result.frames[0]
      if (result.status !== 200 || frame?.type === 'error') throw new Error(`${type} failed: ${frame?.payload?.code ?? result.status}`)
      return frame
    }
    const created = await command('session.create', { workspace: 'probe', preset: 'standard' })
    const sessionId = created.payload.session_id as string
    const existing = await command('session.list', {})
    assert.ok(existing.payload.items.some((item: { session_id: string }) => item.session_id === sessionId))

    const subscriptionBody = () => ({ v: 0, type: 'session.subscribe', request_id: randomUUID(), runtime_epoch: probe.runtime_epoch,
      session_id: sessionId, payload: { max_messages: 20 } })
    const firstSubscription = await startSubscription(socketPath, subscriptionBody())
    subscriptions.push(firstSubscription)
    const snapshot = JSON.parse((await waitForLine(firstSubscription.iterator)).value!)
    const initialCheckpoint = JSON.parse((await waitForLine(firstSubscription.iterator)).value!)
    assert.equal(snapshot.type, 'session.snapshot')
    assert.equal(initialCheckpoint.type, 'session.checkpoint')

    const accepted = await command('message.submit', { mode: 'queue', text: 'Reply with the local fixture result.' }, sessionId)
    assert.equal(accepted.payload.native_accepted, true)
    let finalMessage: any
    for (;;) {
      const value = JSON.parse((await waitForLine(firstSubscription.iterator)).value!)
      if (value.type === 'session.event' && value.payload.type === 'assistant/message') {
        finalMessage = value.payload
        break
      }
    }
    assert.ok(JSON.stringify(finalMessage.data).includes(RESPONSE))
    await waitForTurnEnd(firstSubscription.iterator)

    firstSubscription.reader.close()
    firstSubscription.response.destroy()
    const secondSubscription = await startSubscription(socketPath, subscriptionBody())
    subscriptions.push(secondSubscription)
    const fresh = JSON.parse((await waitForLine(secondSubscription.iterator)).value!)
    const freshCheckpoint = JSON.parse((await waitForLine(secondSubscription.iterator)).value!)
    assert.equal(fresh.type, 'session.snapshot')
    assert.equal(freshCheckpoint.type, 'session.checkpoint')
    assert.ok(fresh.payload.records.some((record: { type: string; data: unknown }) => record.type === 'assistant/message' && JSON.stringify(record.data).includes(RESPONSE)))
    const page = await command('session.page', {
      sync_id: fresh.sync_id, through_seq: fresh.payload.cursor, before_seq: Math.max(0, fresh.payload.cursor + 1), max_messages: 20,
    }, sessionId)
    assert.ok(page.payload.records.some((record: { type: string; data: unknown }) => record.type === 'assistant/message' && JSON.stringify(record.data).includes(RESPONSE)))

    const denialSubscription = await startSubscription(socketPath, subscriptionBody())
    subscriptions.push(denialSubscription)
    await waitForLine(denialSubscription.iterator) // snapshot
    await waitForLine(denialSubscription.iterator) // checkpoint
    const denialPrompt = await command('message.submit', { mode: 'queue', text: 'M0_APPROVAL_DENY' }, sessionId)
    assert.equal(denialPrompt.payload.native_accepted, true)
    const pending = await waitForInteraction(command)
    assert.equal(pending.kind, 'approval')
    assert.equal(pending.detail.tool, 'bash')
    assert.match(pending.detail.arguments.command, /approval-denied\.txt/)
    await command('interaction.answer', { interaction_id: pending.interaction_id, answer: { decision: 'reject' } })
    let deniedAssistant: any
    for (;;) {
      const value = JSON.parse((await waitForLine(denialSubscription.iterator)).value!)
      if (value.type !== 'session.event') continue
      if (value.payload.type === 'assistant/message') { deniedAssistant = value.payload; break }
    }
    assert.ok(deniedAssistant)
    await waitForTurnEnd(denialSubscription.iterator)
    await assert.rejects(access(join(workspace, 'approval-denied.txt')), { code: 'ENOENT' })

    const questionPrompt = await command('message.submit', { mode: 'queue', text: 'M0_QUESTION_TEST' }, sessionId)
    assert.equal(questionPrompt.payload.native_accepted, true)
    const question = await waitForInteraction(command)
    assert.equal(question.kind, 'question')
    assert.equal(question.detail.questions[0].id, 'm0-choice')
    await command('interaction.answer', { interaction_id: question.interaction_id, answer: {
      answers: [{ id: 'm0-choice', selected: ['Local answer'] }],
    } })
    let questionAssistant: any
    for (;;) {
      const value = JSON.parse((await waitForLine(denialSubscription.iterator)).value!)
      if (value.type === 'session.event' && value.payload.type === 'assistant/message') {
        questionAssistant = value.payload
        break
      }
    }
    assert.ok(questionAssistant)
    await waitForTurnEnd(denialSubscription.iterator)

    assert.ok((await readFile(patchPath, 'utf8')).includes('dsh-m0-test'))
    const cancelled = await command('session.cancel', {}, sessionId)
    assert.deepEqual(cancelled.payload, { accepted: true })
    t.diagnostic(`Loaded via dsh ${probe.payload.dsh_version}; session sync, assistant output, bash approval rejection, and ordinary question response passed with local fixtures.`)
    completed = true
  } finally {
    for (const subscription of subscriptions) {
      subscription.reader.close()
      subscription.response.destroy()
      subscription.req.destroy()
    }
    const shutdownStarted = Date.now()
    child.kill('SIGINT')
    let shutdownCheck: Error | undefined
    try {
      const shutdown = await withTimeout(exited.then(([code, signal]) => ({ code, signal })), 6500)
      if (shutdown === undefined) {
        child.kill('SIGKILL')
        await withTimeout(exited, 1000)
        shutdownCheck = new Error(`DSH CLI did not exit after SIGINT; ${safeTail(stderr)}`)
      } else if (process.platform !== 'win32') {
        await lstat(socketPath).then(() => { throw new Error('DSH CLI exited without removing the local socket') }, error => {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        })
      }
      if (completed && shutdown !== undefined) t.diagnostic(`DSH CLI exited with ${shutdown.code ?? shutdown.signal} after ${Date.now() - shutdownStarted}ms; the local socket was removed.`)
    } catch (error) {
      shutdownCheck = error instanceof Error ? error : new Error(String(error))
    } finally { await rm(root, { recursive: true, force: true }) }
    if (shutdownCheck) throw shutdownCheck
  }
})
