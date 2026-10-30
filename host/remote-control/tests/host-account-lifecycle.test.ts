import test from 'node:test'
import assert from 'node:assert/strict'
import { lstat } from 'node:fs/promises'
import { request } from 'node:http'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { randomUUID } from 'node:crypto'
import { host } from './harness.js'
import { apply, createRemoteControlPlugin, type HostConnectionCredential } from '../src/index.js'
import { DshClient } from '../src/dsh-client.js'

function local(socketPath: string, body?: object): Promise<{ runtime_epoch: string; payload: any }> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath, path: body ? '/m0/command' : '/m0/probe', method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json' } }, response => {
      let data = ''
      response.on('data', chunk => { data += chunk })
      response.once('end', () => {
        try { assert.equal(response.statusCode, 200); resolve(JSON.parse(data)) } catch (error) { reject(error) }
      })
      response.once('error', reject)
    })
    req.once('error', reject)
    req.end(body ? JSON.stringify(body) : undefined)
  })
}

async function follower(socketPath: string, body: object) {
  let finish!: () => void
  const closed = new Promise<void>(resolve => { finish = resolve })
  let req!: ReturnType<typeof request>
  await new Promise<void>((resolve, reject) => {
    req = request({ socketPath, path: '/m0/command', method: 'POST', headers: { 'content-type': 'application/json' } }, response => {
      response.once('close', finish)
      response.on('error', () => {}) // Expected when account retirement destroys the socket.
      response.resume()
      if (response.statusCode === 200) resolve()
      else reject(new Error('follower did not open'))
    })
    req.once('error', reject)
    req.end(JSON.stringify(body))
  })
  return { closed, close() { req.destroy() } }
}

test('account cancellation retires the plugin endpoint without stopping the native DSH host', { skip: process.platform === 'win32', timeout: 10_000 }, async () => {
  const h = await host({ probe: false })
  const owner = new AbortController()
  let acquired!: () => void, acquisitionAborted = false, acquisitions = 0
  const ready = new Promise<void>(resolve => { acquired = resolve })
  const plugin = createRemoteControlPlugin({ signal: owner.signal, async acquire(signal) {
    acquisitions++
    signal.addEventListener('abort', () => { acquisitionAborted = true }, { once: true })
    acquired()
    return await new Promise<HostConnectionCredential>(() => {})
  } })
  try {
    const fiber = h.ctx.plugin(plugin, { ...h.config, commandJournalPath: join(h.directory, 'account', 'commands.sqlite'),
      relayUrl: 'http://127.0.0.1:1', applicationVersion: 'fixture', interactionTimeoutMs: 60_000 })
    await fiber.await()
    await ready
    const initial = await local(h.socketPath)
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, AbortSignal.timeout(1000))
    const agent = h.ctx.agents.get(native)
    assert.ok(agent)
    agent.session.append('turn/start', { turn: 1 })
    const question = h.ctx.userQuestions.ask({ agent, questions: [{ id: 'owner', question: 'Continue?', options: [{ label: 'Continue' }] }] })
    void question.catch(() => {})
    const command = (type: string, payload = {}) => ({ v: 0, type, request_id: randomUUID(), runtime_epoch: initial.runtime_epoch, payload })
    let pending = false
    for (let attempt = 0; attempt < 50; attempt++) {
      if ((await local(h.socketPath, command('interaction.list'))).payload.items.length) { pending = true; break }
      await delay(10)
    }
    assert.equal(pending, true, 'native question never reached the old account')
    const stream = await follower(h.socketPath, { ...command('session.subscribe'), session_id: created.session_id })
    try {
      owner.abort(new Error('PRIVATE_ACCOUNT_CHANGE_REASON'))
      const deadline = Date.now() + 1000
      while (await lstat(h.socketPath).then(() => true, error => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
        throw error
      })) {
        assert.ok(Date.now() < deadline, 'old account left the plugin socket running')
        await delay(10)
      }
      await assert.rejects(local(h.socketPath))
      await Promise.race([stream.closed, delay(1000).then(() => { throw new Error('account retirement left a follower connected') })])
      await assert.rejects(question, /question.cancelled/)
      assert.equal(acquisitionAborted, true)
      assert.equal(acquisitions, 1)
      assert.equal(h.ctx.agents.get(native), agent, 'account cancellation disposed the shared DSH host')
      const nativeAnswer = { answers: [{ id: 'after-owner', selected: ['Continue'] }] }
      const removeNativeAnswerer = h.ctx.on('user-questions/request', async () => nativeAnswer)
      try {
        const answer = await h.ctx.userQuestions.ask({ agent, questions: [{ id: 'after-owner', question: 'Still available?', options: [{ label: 'Continue' }] }] })
        assert.deepEqual(answer, nativeAnswer, 'retired plugin left its old native question listener installed')
      } finally { removeNativeAnswerer() }
      const accepted = await client.prompt(native, randomUUID(), 'queue', 'after account retirement', AbortSignal.timeout(2000))
      assert.equal(accepted.native_accepted, true)
      await agent.whenIdle()
      await fiber.dispose()
      assert.equal(h.errors.length, 0)
      const replacement = createRemoteControlPlugin({ async acquire() { return await new Promise<HostConnectionCredential>(() => {}) } })
      const reopened = h.ctx.plugin(replacement, { ...h.config, commandJournalPath: join(h.directory, 'account', 'commands.sqlite'),
        relayUrl: 'http://127.0.0.1:1', applicationVersion: 'fixture' })
      await reopened.await()
      assert.notEqual((await local(h.socketPath)).runtime_epoch, initial.runtime_epoch)
      assert.equal(h.ctx.agents.get(native), agent)
      await reopened.dispose()
    } finally { stream.close() }
  } finally { owner.abort(); await h.close() }
})

test('direct apply account retirement preserves its parent context', { skip: process.platform === 'win32', timeout: 5000 }, async () => {
  const h = await host({ probe: false })
  const owner = new AbortController()
  try {
    const parent = h.ctx.fiber, uid = parent.uid
    await apply(h.ctx, { ...h.config, relayUrl: 'http://127.0.0.1:1', applicationVersion: 'fixture' }, {
      signal: owner.signal,
      async acquire() { return await new Promise<HostConnectionCredential>(() => {}) },
    })
    await local(h.socketPath)
    owner.abort()
    const deadline = Date.now() + 1000
    while (await lstat(h.socketPath).then(() => true, error => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
      throw error
    })) {
      assert.ok(Date.now() < deadline, 'direct apply left its old account endpoint')
      await delay(10)
    }
    assert.equal(parent.uid, uid)
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const created = await client.create('fixture', 'fixture')
    assert.ok(h.ctx.agents.get(await client.resolve(created.session_id, AbortSignal.timeout(1000))))
    assert.equal(h.errors.length, 0)
  } finally { owner.abort(); await h.close() }
})
