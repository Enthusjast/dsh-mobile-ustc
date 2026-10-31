import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { request } from 'node:http'
import { DatabaseSync } from 'node:sqlite'
import * as plugin from '../src/index.js'
import { host } from './harness.js'
import { DshClient } from '../src/dsh-client.js'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand } from '../src/protocol.js'
import type { InteractionRouter } from '../src/interaction-router.js'
import { injectJournalFull, journalDatabase, sqliteFull, TEST_JOURNAL_BYTES } from './journal-capacity-fixture.js'

test('real SQLite FULL gates DSH admission/dispatch and preserves native facts after result-write failure', async t => {
  for (const phase of ['admit', 'start', 'result', 'result-and-unknown'] as const) {
    await t.test(phase, async t => {
      const fixture = await host({ probe: false })
      const path = join(fixture.directory, 'journal', 'commands.sqlite')
      let journal = await PersistentCommandJournal.open(path, fixture.runtimeId, { maxDatabaseBytes: TEST_JOURNAL_BYTES })
      let client = new DshClient(fixture.ctx, fixture.runtimeId, [{ id: 'fixture', cwd: fixture.cwd }], ['fixture'])
      let runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
      const owner = { userId: randomUUID(), deviceId: randomUUID() }, signal = new AbortController()
      let restore: (() => void) | undefined
      try {
        const created = await client.create('fixture', 'fixture')
        const native = await client.resolve(created.session_id, signal.signal)
        const agent = fixture.ctx.agents.get(native)!
        const command = parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: runtime.epoch,
          session_id: created.session_id, payload: { mode: 'queue', text: `PRIVATE_SQLITE_FULL_${randomUUID()}` } })
        const condition = phase === 'start' ? "NEW.state='dispatching'"
          : phase === 'result' ? "NEW.state='agent_queued'"
          : phase === 'result-and-unknown' ? "NEW.state IN ('agent_queued','outcome_unknown')" : '1'
        restore = injectJournalFull(journal, 'commands', phase === 'admit' ? 'INSERT' : 'UPDATE', condition)
        const receipts: string[] = []
        await assert.rejects(runtime.dispatch(command, signal.signal, owner, state => { receipts.push(state) }), sqliteFull)
        await agent.whenIdle()
        const messages = () => agent.session.snapshotEvents().filter(event => event.type === 'user/message'
          && (event.data.source as unknown as { rpcId?: string }).rpcId === `m0:${owner.deviceId}:${command.request_id}`)
        assert.equal(receipts.includes('agent_queued'), false, 'a failed result write emitted a durable success receipt')
        assert.equal(messages().length, phase === 'admit' || phase === 'start' ? 0 : 1)
        assert.deepEqual(receipts, phase === 'admit' ? [] : phase === 'start' ? ['host_accepted']
          : phase === 'result' ? ['host_accepted', 'dispatching', 'outcome_unknown'] : ['host_accepted', 'dispatching'])
        const expected = phase === 'admit' ? undefined : phase === 'start' ? 'host_accepted' : phase === 'result' ? 'outcome_unknown' : 'dispatching'
        assert.equal(journal.lookup(command, owner)?.state, expected)
        assert.equal(journalDatabase(journal).prepare('SELECT count(*) n FROM fixture_full_padding').get()?.n, 0)
        restore(); restore = undefined
        runtime.close(); journal.close()
        journal = await PersistentCommandJournal.open(path, fixture.runtimeId, { maxDatabaseBytes: TEST_JOURNAL_BYTES })
        client = new DshClient(fixture.ctx, fixture.runtimeId, [{ id: 'fixture', cwd: fixture.cwd }], ['fixture'])
        runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter, journal)
        assert.equal(journal.lookup(command, owner)?.state, expected)
        const retry = { ...command, runtime_epoch: runtime.epoch }
        if (phase === 'result') {
          await assert.rejects(runtime.dispatch(retry, signal.signal, owner), /command.outcome_unknown/)
          assert.equal(journal.lookup(retry, owner)?.state, 'outcome_unknown')
        } else {
          const result = await runtime.dispatch(retry, signal.signal, owner)
          assert.equal((result.payload as { native_accepted: boolean }).native_accepted, true)
          assert.equal(journal.lookup(retry, owner)?.state, 'agent_queued')
          await runtime.dispatch(retry, signal.signal, owner)
        }
        await agent.whenIdle()
        assert.equal(messages().length, 1, 'restored capacity or original-ID reconciliation duplicated native work')
      } finally {
        signal.abort()
        restore?.()
        runtime.close(); journal.close()
        await fixture.close()
      }
    })
  }
})

test('plugin configuration applies the shared capacity before local native dispatch', async t => {
  const fixture = await host({ probe: false })
  t.after(() => fixture.close())
  const path = join(fixture.directory, 'bounded', 'commands.sqlite')
  const fiber = fixture.ctx.plugin(plugin, { ...fixture.config, commandJournalPath: path, commandJournalMaxBytes: TEST_JOURNAL_BYTES })
  await fiber.await()
  const call = (method: string, path: string, value?: object) => new Promise<any[]>((accept, reject) => {
    const req = request({ socketPath: fixture.socketPath, method, path, headers: value ? { 'content-type': 'application/json' } : {} }, response => {
      const chunks: Buffer[] = []
      response.on('data', chunk => chunks.push(Buffer.from(chunk)))
      response.on('end', () => {
        try { accept(Buffer.concat(chunks).toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))) }
        catch (error) { reject(error) }
      })
      response.on('error', reject)
    })
    req.setTimeout(3000, () => req.destroy(new Error('capacity fixture IPC timeout')))
    req.on('error', reject)
    req.end(value ? JSON.stringify(value) : undefined)
  })
  const [probe] = await call('GET', '/m0/probe')
  const create = { v: 0, type: 'session.create', request_id: randomUUID(), runtime_epoch: probe.runtime_epoch,
    payload: { workspace: 'fixture', preset: 'fixture' } }
  const control = new DatabaseSync(path)
  try { control.exec(`CREATE TABLE fixture_full_padding(data BLOB);
    CREATE TRIGGER fixture_force_full BEFORE INSERT ON commands
    BEGIN INSERT INTO fixture_full_padding(data) VALUES(zeroblob(${2 * TEST_JOURNAL_BYTES})); END;`) }
  finally { control.close() }
  const refused = await call('POST', '/m0/command', create)
  assert.equal(refused.some(frame => frame.type === 'error' && frame.payload.code === 'internal'), true)
  const client = new DshClient(fixture.ctx, fixture.runtimeId, [{ id: 'fixture', cwd: fixture.cwd }], ['fixture'])
  assert.equal((await client.list(t.signal)).items.length, 0, 'full configured journal let a native session be created')
  const recover = new DatabaseSync(path)
  try { recover.exec('DROP TRIGGER fixture_force_full; DROP TABLE fixture_full_padding;') }
  finally { recover.close() }
  const accepted = await call('POST', '/m0/command', create)
  const result = accepted.find(frame => frame.type === 'session.create.result')
  assert.ok(result)
  const repeated = await call('POST', '/m0/command', create)
  assert.deepEqual(repeated.find(frame => frame.type === 'session.create.result')?.payload, result.payload)
  assert.equal((await client.list(t.signal)).items.length, 1)
})
