import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { once } from 'node:events'
import { createPrivateKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto'
import { access, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { createServer, request } from 'node:http'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { hostHelloDigest, relayPayloadDigest } from '../src/relay-client.js'

const WebSocketServer = createRequire(import.meta.url)('ws').WebSocketServer as new (options: object) => any

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
  const installationId = randomUUID()
  const hostCredential = 'R'.repeat(43)
  const remoteUserId = '77777777-7777-4777-8777-777777777777'
  const remoteDeviceId = '22222222-2222-4222-8222-222222222222'
  const remoteRequestId = randomUUID()
  const { publicKey, privateKey: generatedPrivateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const privateJwk = generatedPrivateKey.export({ format: 'jwk' })
  const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' })
  const relayHttp = createServer()
  const relayWss = new WebSocketServer({ server: relayHttp })
  let relayRuntimeEpoch = ''
  await new Promise<void>(resolve => relayHttp.listen(0, '127.0.0.1', resolve))
  const relayAddress = relayHttp.address()
  assert.ok(relayAddress && typeof relayAddress === 'object')
  const relayUrl = `http://127.0.0.1:${relayAddress.port}`
  const relayConnectionId = randomUUID()
  const relayChallengeId = randomUUID()
  const relayNonce = Buffer.alloc(32, 11).toString('base64url')
  let relaySocket: any
  let relayFailure: Error | undefined
  const relayReceipts: any[] = []
  let relayCatalog: any[] = []
  const relayCatalogSnapshots = new Map<string, any[]>()
  let resolveRelayConnected!: () => void
  let rejectRelayConnected!: (error: Error) => void
  const relayConnected = new Promise<void>((resolve, reject) => {
    resolveRelayConnected = resolve
    rejectRelayConnected = reject
  })
  relayWss.on('connection', (socket: any, incoming: any) => {
    relaySocket = socket
    if (incoming.headers.authorization !== `DSH-Host ${hostCredential}`) {
      relayFailure = new Error('DSH plugin did not use the host Authorization scheme')
      rejectRelayConnected(relayFailure)
      socket.close()
      return
    }
    socket.send(JSON.stringify({ v: 1, type: 'challenge', payload: {
      connection_id: relayConnectionId, challenge_id: relayChallengeId, nonce: relayNonce,
      role: 'installation', expires_at: new Date(Date.now() + 10_000).toISOString(),
    } }))
    socket.on('message', (raw: Buffer) => {
      try {
        const frame = JSON.parse(raw.toString('utf8'))
        if (frame.type === 'hello.proof') {
          const [headerPart, payloadPart, signaturePart] = frame.payload.proof.split('.')
          const proof = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'))
          const signingInput = Buffer.from(`${headerPart}.${payloadPart}`)
          relayRuntimeEpoch = proof.runtime_epoch
          const helloDigest = hostHelloDigest([
            'host', runtimeId, relayRuntimeEpoch, '0.2.1-rc.2', 'dsh-cli-integration', '0.0.1', '1',
            ['command.relay.v1', 'connection.heartbeat.v1', 'session.catalog.v1'].join('\n'),
          ])
          const valid = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8')).typ === 'dsh-relay-handshake-proof+jwt'
            && proof.iss === installationId && proof.aud === 'urn:dsh-mobile-ustc:realtime'
            && proof.challenge_id === relayChallengeId && proof.connection_id === relayConnectionId
            && proof.nonce === relayNonce && proof.runtime_id === runtimeId && /^[0-9a-f-]{36}$/i.test(relayRuntimeEpoch)
            && proof.hello_sha256 === helloDigest
            && verify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signaturePart, 'base64url'))
          if (!valid) throw new Error('DSH plugin hello proof did not bind its runtime and challenge')
          socket.send(JSON.stringify({ v: 1, type: 'hello.ok', payload: {
            role: 'host', connection_id: relayConnectionId, installation_id: installationId,
            runtime_id: runtimeId, runtime_epoch: relayRuntimeEpoch, protocol_version: 1, protocols: [1],
            capabilities: ['command.relay.v1', 'connection.heartbeat.v1', 'session.catalog.v1'], server_time: new Date().toISOString(),
            heartbeat_seconds: 20, max_frame_bytes: 65_536, lease_expires_at: new Date(Date.now() + 300_000).toISOString(),
          } }))
          resolveRelayConnected()
        } else if (frame.type === 'session.catalog') {
          const items = relayCatalogSnapshots.get(frame.request_id) ?? []
          items.push(...frame.payload.items)
          relayCatalogSnapshots.set(frame.request_id, items)
          if (frame.payload.complete) {
            if (frame.payload.mode === 'snapshot') relayCatalog = items
            else {
              const merged = new Map(relayCatalog.map(item => [item.session_id, item]))
              for (const item of items) merged.set(item.session_id, item)
              relayCatalog = [...merged.values()]
            }
            relayCatalogSnapshots.delete(frame.request_id)
            socket.send(JSON.stringify({
              v: 1, type: 'session.catalog.ack', request_id: frame.request_id,
              runtime_id: runtimeId, runtime_epoch: relayRuntimeEpoch,
              payload: { session_count: items.length, server_time: new Date().toISOString() },
            }))
          }
        } else if (frame.type === 'command.receipt') relayReceipts.push(frame)
        else if (frame.type === 'ping') socket.send(JSON.stringify({ v: 1, type: 'pong', payload: { connection_id: relayConnectionId, server_time: new Date().toISOString() } }))
      } catch (error) {
        relayFailure = error instanceof Error ? error : new Error(String(error))
        rejectRelayConnected(relayFailure)
      }
    })
  })
  const pluginWrapperPath = join(root, 'remote-control-relay.mjs')
  const pluginModuleUrl = pathToFileURL(resolve(pluginEntry)).href
  const pluginWrapper = [
    "import { createPrivateKey, sign } from 'node:crypto'",
    `import { createRemoteControlPlugin } from ${JSON.stringify(pluginModuleUrl)}`,
    `const privateKey = createPrivateKey({ key: ${JSON.stringify(privateJwk)}, format: 'jwk' })`,
    `const plugin = createRemoteControlPlugin({ async acquire() { return { installationId: ${JSON.stringify(installationId)}, credential: ${JSON.stringify(hostCredential)}, signer: { sign(input) { return sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }) } } } } })`,
    'export const { name, inject, apply } = plugin',
    '',
  ].join('\n')
  await writeFile(pluginWrapperPath, pluginWrapper, { mode: 0o600 })
  const commandJournalPath = join(root, 'state', runtimeId, 'commands.sqlite')
  const patchPath = join(root, 'remote-control.patch.yml')
  const quote = (value: string) => JSON.stringify(value)
  const patch = [
    '- insert:',
    '    - id: dsh-m0-model-fixture',
    `      name: ${quote(modelFixture)}`,
    '    - id: ustc-remote-control',
    `      name: ${quote(pluginWrapperPath)}`,
    '      config:',
    '        enabled: true',
    `        runtimeId: ${runtimeId}`,
    `        socketPath: ${quote(socketPath)}`,
    `        commandJournalPath: ${quote(commandJournalPath)}`,
    `        relayUrl: ${quote(relayUrl)}`,
    '        applicationVersion: dsh-cli-integration',
    '        workspaces:',
    '          - id: probe',
    `            remoteId: ${quote('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')}`,
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
  const mutatingRequests: any[] = []
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
    await Promise.race([relayConnected, new Promise<never>((_, reject) => setTimeout(() => reject(new Error('DSH plugin Relay handshake timed out')), 3000))])
    assert.equal(relayRuntimeEpoch, probe.runtime_epoch)
    assert.equal(relayFailure, undefined)

    const command = async (type: string, payload: unknown, sessionId?: string) => {
      const body = { v: 0, type, request_id: randomUUID(), runtime_epoch: probe.runtime_epoch,
        payload, ...(sessionId === undefined ? {} : { session_id: sessionId }) }
      if (['session.create', 'message.submit', 'session.cancel', 'session.model.select', 'interaction.answer'].includes(type)) {
        mutatingRequests.push(body)
      }
      const result = await requestFrames(socketPath, 'POST', '/m0/command', body)
      const frame = result.frames[0]
      if (result.status !== 200 || frame?.type === 'error') throw new Error(`${type} failed: ${frame?.payload?.code ?? result.status}`)
      return frame
    }
    const created = await command('session.create', { workspace: 'probe', preset: 'standard' })
    const sessionId = created.payload.session_id as string
    const existing = await command('session.list', {})
    assert.ok(existing.payload.items.some((item: { session_id: string }) => item.session_id === sessionId))
    const catalogDeadline = Date.now() + 5000
    while (Date.now() < catalogDeadline && !relayCatalog.some(item => item.session_id === sessionId)) {
      if (relayFailure) throw relayFailure
      await new Promise(resolve => setTimeout(resolve, 10))
    }
    const catalogEntry = relayCatalog.find(item => item.session_id === sessionId)
    assert.ok(catalogEntry, 'DSH session was not synchronized to the host Relay catalog')
    assert.equal(catalogEntry.workspace_id, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    assert.equal(catalogEntry.state, 'available')
    assert.ok(catalogEntry.last_persisted_seq >= -1)

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

    const relayPayload = { mode: 'queue' as const, content: [{ type: 'text' as const, text: 'Reply to the remote DSH relay command.' }] }
    const relayFrame = {
      v: 1, type: 'message.submit', request_id: remoteRequestId, runtime_id: runtimeId,
      runtime_epoch: probe.runtime_epoch, session_id: sessionId, user_id: remoteUserId, device_id: remoteDeviceId,
      payload_sha256: relayPayloadDigest(sessionId, relayPayload), payload: relayPayload,
    }
    relaySocket.send(JSON.stringify(relayFrame))
    let relayedAssistant: any
    for (;;) {
      if (relayFailure) throw relayFailure
      const value = JSON.parse((await waitForLine(firstSubscription.iterator)).value!)
      if (value.type === 'session.event' && value.payload.type === 'assistant/message') {
        relayedAssistant = value.payload
        break
      }
    }
    assert.ok(JSON.stringify(relayedAssistant.data).includes(RESPONSE))
    await waitForTurnEnd(firstSubscription.iterator)
    for (const state of ['host_accepted', 'dispatching', 'agent_queued']) {
      const deadline = Date.now() + 5000
      while (Date.now() < deadline && !relayReceipts.some(receipt => receipt.request_id === remoteRequestId && receipt.payload.state === state)) {
        if (relayFailure) throw relayFailure
        await new Promise(resolve => setTimeout(resolve, 10))
      }
      assert.ok(relayReceipts.some(receipt => receipt.request_id === remoteRequestId && receipt.payload.state === state), `missing ${state} host receipt`)
    }
    assert.ok(relayReceipts.filter(receipt => receipt.request_id === remoteRequestId)
      .every(receipt => receipt.payload.payload_sha256 === relayFrame.payload_sha256))

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
    t.diagnostic(`Loaded via dsh ${probe.payload.dsh_version}; authenticated local Relay handshake, DSH session catalog metadata, and command routing into the same Agent passed with local fixtures, alongside snapshot sync, bash approval rejection, and ordinary question response.`)
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
      if (completed && shutdown !== undefined) {
        const journal = await PersistentCommandJournal.open(commandJournalPath, runtimeId)
        try {
          for (const body of mutatingRequests) {
            const record = journal.get(body.request_id, { userId: 'local', deviceId: 'local' })
            assert.ok(record, `missing durable journal entry for ${body.type}`)
            assert.equal(record.command, undefined, 'completed command body was not removed after the DSH persistence checkpoint')
            assert.ok(['agent_queued', 'settled'].includes(record.state), `${body.type} has non-final state ${record.state}`)
          }
          const remoteRecord = journal.get(remoteRequestId, { userId: remoteUserId, deviceId: remoteDeviceId })
          assert.ok(remoteRecord, 'missing durable journal entry for the remote Relay command')
          assert.equal(remoteRecord.command, undefined, 'remote command body was not removed after the DSH persistence checkpoint')
          assert.equal(remoteRecord.state, 'agent_queued')
        } finally { journal.close() }
      }
      if (completed && shutdown !== undefined) t.diagnostic(`DSH CLI exited with ${shutdown.code ?? shutdown.signal} after ${Date.now() - shutdownStarted}ms; the local socket was removed.`)
    } catch (error) {
      shutdownCheck = error instanceof Error ? error : new Error(String(error))
    } finally { await rm(root, { recursive: true, force: true }) }
    relaySocket?.close()
    await new Promise<void>(resolve => relayWss.close(() => relayHttp.close(() => resolve())))
    if (shutdownCheck) throw shutdownCheck
  }
})
