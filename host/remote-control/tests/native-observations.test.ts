import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { SessionId } from '@deepseek-ai/dsh-session'
import { NativeObservations, NativeObservationWindow, bindNativeObservations, hostObservationsFrame } from '../src/native-observations.js'
import { DshClient } from '../src/dsh-client.js'
import { ProbeRuntime } from '../src/runtime.js'
import { parseCommand } from '../src/protocol.js'
import type { InteractionRouter } from '../src/interaction-router.js'
import { host } from './harness.js'

test('native windows aggregate fixed cells, keep snapshots immutable and report invalid samples without text', () => {
  const window = new NativeObservationWindow(), connection = randomUUID()
  window.record('checkpoint', 'persisted', 1500)
  const first = window.snapshot(connection)!
  window.record('checkpoint', 'persisted', 2500)
  window.record('checkpoint', 'failed', 2000)
  window.record('PRIVATE_PATH_OR_ERROR' as never, 'ok', 10)
  window.record('prompt', 'ok', -1)
  const next = window.snapshot(connection)!
  assert.equal(first.series[0]!.count, 1)
  assert.equal(next.series.find(item => item.result === 'persisted')!.count, 2)
  assert.equal(next.series.find(item => item.result === 'persisted')!.sum_micros, 4000)
  assert.equal(next.dropped, 2)
  assert.equal(JSON.stringify(next).includes('PRIVATE_PATH_OR_ERROR'), false)
  assert.equal(hostObservationsFrame.safeParse({ v: 1, type: 'host.observations', runtime_id: randomUUID(), runtime_epoch: randomUUID(), payload: next }).success, true)
})

test('telemetry failures and connection replacement never affect native results or move old spans to a new connection', async () => {
  let now = 0
  const source = new NativeObservations(() => now)
  let frame: any, attempts = 0
  const identity = { connectionId: randomUUID(), runtimeId: randomUUID(), epoch: randomUUID() }
  const first = bindNativeObservations(source, identity, value => { attempts++; if (attempts === 1) throw new Error('PRIVATE_SEND_FAILURE'); if (attempts === 2) return false; frame = value; return true })
  try {
    const pending = source.start('prompt')
    now = 2; pending('ok'); pending('ok')
    assert.doesNotThrow(first.flush)
    first.flush()
    first.flush()
    assert.equal(frame.payload.series[0].count, 1)
    assert.equal(frame.payload.sequence, 3)
    const oldSpan = source.start('create')
    const second = bindNativeObservations(source, { ...identity, connectionId: randomUUID() }, value => { frame = value; return true })
    try {
      first.close(); now = 3; oldSpan('ok')
      now = 4
      assert.equal(await source.measure('prompt', async () => { now = 6; return 'unchanged native value' }), 'unchanged native value')
      second.flush()
      assert.equal(frame.payload.sequence, 1)
      assert.deepEqual(frame.payload.series.map((item: any) => item.operation), ['prompt'])
      assert.equal(frame.payload.series[0].sum_micros, 2000)
    } finally { second.close() }
    source.listen(() => { throw new Error('PRIVATE_OBSERVER_FAILURE') })
    assert.equal(await source.measure('prompt', async () => 'still accepted'), 'still accepted')
  } finally { first.close() }
})

test('a sample completed during a send stays pending for the next cumulative report', () => {
  let now = 0
  const source = new NativeObservations(() => now), frames: any[] = []
  let duringSend: (result: 'ok') => void = () => {}
  const peer = bindNativeObservations(source, { connectionId: randomUUID(), runtimeId: randomUUID(), epoch: randomUUID() }, frame => {
    frames.push(frame)
    if (frames.length === 1) { now = 2; duringSend('ok') }
    return true
  })
  try {
    duringSend = source.start('create')
    const prompt = source.start('prompt'); now = 1; prompt('ok')
    peer.flush(); peer.flush()
    assert.equal(frames.length, 2)
    assert.equal(frames[1].payload.series.find((item: any) => item.operation === 'create').count, 1)
  } finally { peer.close() }
})

test('real DSH checkpoints distinguish persisted, unavailable and failed without replaying an uncertain prompt', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const window = new NativeObservationWindow(), dispose = client.observations.listen((operation, result, micros) => window.record(operation, result, micros))
  const originalFlush = h.ctx.sessions.flush.bind(h.ctx.sessions)
  const runtime = new ProbeRuntime(client, { close() {} } as InteractionRouter)
  try {
    const created = await client.create('fixture', 'fixture')
    const native = await client.resolve(created.session_id, new AbortController().signal)
    assert.equal((await client.checkpoint(native)).state, 'persisted')
    assert.equal((await client.checkpoint(SessionId(randomUUID()))).state, 'unavailable')
    h.ctx.sessions.flush = async () => false
    assert.equal((await client.checkpoint(native)).state, 'unavailable')
    h.ctx.sessions.flush = async () => { throw new Error('PRIVATE_DISK_PATH_AND_CONTENT') }
    assert.equal((await client.checkpoint(native)).state, 'failed')
    const command = parseCommand({ v: 0, type: 'message.submit', request_id: randomUUID(), runtime_epoch: runtime.epoch, session_id: created.session_id,
      payload: { mode: 'queue', text: 'PRIVATE_NATIVE_PROMPT_BODY' } })
    const states: string[] = []
    const result = await runtime.dispatch(command, new AbortController().signal, undefined, state => { states.push(state) })
    assert.equal((result.payload as { command_state: string }).command_state, 'outcome_unknown')
    assert.deepEqual(states, ['host_accepted', 'dispatching', 'outcome_unknown'])
    await assert.rejects(runtime.dispatch(command, new AbortController().signal), /command.outcome_unknown/)
    const report = window.snapshot(randomUUID())!
    assert.equal(report.series.find(item => item.operation === 'prompt' && item.result === 'ok')!.count, 1)
    assert.ok(report.series.find(item => item.operation === 'checkpoint' && item.result === 'failed')!.count >= 2)
    assert.ok(report.series.find(item => item.operation === 'checkpoint' && item.result === 'unavailable')!.count >= 2)
    for (const privateValue of ['PRIVATE_DISK_PATH_AND_CONTENT', 'PRIVATE_NATIVE_PROMPT_BODY', created.session_id, native]) assert.equal(JSON.stringify(report).includes(privateValue), false)
  } finally { h.ctx.sessions.flush = originalFlush; dispose(); runtime.close(); await h.close() }
})
