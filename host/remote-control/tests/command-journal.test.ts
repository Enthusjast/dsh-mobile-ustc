import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { PersistentCommandJournal } from '../src/command-journal.js'
import { ProbeError, parseCommand } from '../src/protocol.js'

const owner = { userId: 'user-1', deviceId: 'device-1' }

function submit(text: string, requestId: string = randomUUID(), epoch: string = randomUUID()) {
  return parseCommand({
    v: 0,
    type: 'message.submit',
    request_id: requestId,
    runtime_epoch: epoch,
    session_id: '55555555-5555-4555-8555-555555555555',
    payload: { mode: 'queue', text },
  })
}

test('SQLite command journal encrypts payloads and survives restart without replaying completed work', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-command-journal-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtimeId = randomUUID()
  const path = join(root, runtimeId, 'commands.sqlite')
  const command = submit('this text must not appear in the database')
  let journal = await PersistentCommandJournal.open(path, runtimeId)
  try {
    assert.equal(journal.lookup(command, owner), undefined)
    assert.equal(journal.get(command.request_id, owner), undefined)
    const admitted = journal.admit(command, owner)
    assert.equal(admitted.inserted, true)
    assert.equal(admitted.state, 'host_accepted')
    assert.deepEqual(journal.get(command.request_id, owner)?.command, command)
    const pendingFiles = await Promise.all([path, `${path}-wal`, `${path}-shm`].map(file =>
      readFile(file).catch(() => Buffer.alloc(0))))
    assert.equal(Buffer.concat(pendingFiles).includes(Buffer.from('this text must not appear in the database')), false)
    journal.start(command.request_id, owner)
    journal.complete(command.request_id, owner, 'agent_queued', { native_accepted: true, checkpoint: { state: 'persisted', through_seq: 5 } })

    const retry = submit('this text must not appear in the database', command.request_id, randomUUID())
    const duplicate = journal.admit(retry, owner)
    assert.deepEqual(journal.lookup(retry, owner), duplicate)
    assert.equal(duplicate.inserted, false)
    assert.equal(duplicate.state, 'agent_queued')
    assert.deepEqual(duplicate.result, { native_accepted: true, checkpoint: { state: 'persisted', through_seq: 5 } })
    assert.throws(() => journal.admit(submit('different body', command.request_id), owner), error =>
      error instanceof ProbeError && error.code === 'command.request_conflict')
    assert.throws(() => journal.admit(retry, { userId: 'other-user', deviceId: owner.deviceId }), error =>
      error instanceof ProbeError && error.code === 'access.denied')
  } finally { journal.close() }

  const database = await readFile(path)
  assert.equal(database.includes(Buffer.from('this text must not appear in the database')), false)
  assert.equal((await lstat(path)).mode & 0o777, 0o600)
  assert.equal((await lstat(`${path}.key`)).mode & 0o777, 0o600)
  assert.equal((await lstat(join(root, runtimeId))).mode & 0o777, 0o700)

  journal = await PersistentCommandJournal.open(path, runtimeId)
  try {
    const recovered = journal.admit(submit('this text must not appear in the database', command.request_id, randomUUID()), owner)
    assert.equal(recovered.state, 'agent_queued')
    assert.deepEqual(recovered.result, { native_accepted: true, checkpoint: { state: 'persisted', through_seq: 5 } })
    assert.equal(journal.get(command.request_id, owner)?.command, undefined)
  } finally {
    journal.close()
  }
})

test('SQLite command journal preserves pre-dispatch acceptance and marks interrupted dispatch unknown', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-command-recovery-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const runtimeId = randomUUID()
  const path = join(root, 'journal.sqlite')
  const accepted = submit('accepted before dispatch')
  const interrupted = submit('dispatch may have run')
  let journal = await PersistentCommandJournal.open(path, runtimeId)
  journal.admit(accepted, owner)
  journal.admit(interrupted, owner)
  journal.start(interrupted.request_id, owner)
  journal.close()

  journal = await PersistentCommandJournal.open(path, runtimeId)
  try {
    assert.equal(journal.admit(accepted, owner).state, 'host_accepted')
    assert.equal(journal.admit(interrupted, owner).state, 'dispatching')
    assert.equal(journal.get(interrupted.request_id, owner)?.command?.request_id, interrupted.request_id)
    journal.fail(interrupted.request_id, owner, 'outcome_unknown', 'command.outcome_unknown')
    assert.equal(journal.admit(interrupted, owner).state, 'outcome_unknown')
    assert.throws(() => journal.complete(interrupted.request_id, owner, 'agent_queued', { ok: true }), error =>
      error instanceof ProbeError && error.code === 'journal.invalid_transition')
  } finally {
    journal.close()
  }
})

test('SQLite command journal fails closed when its decryption key is missing or changed', async t => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-command-key-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const path = join(root, 'journal.sqlite')
  const runtimeId = randomUUID()
  const command = submit('secret payload')
  let journal = await PersistentCommandJournal.open(path, runtimeId)
  journal.admit(command, owner)
  journal.start(command.request_id, owner)
  journal.complete(command.request_id, owner, 'agent_queued', { ok: true })
  journal.close()

  const keyPath = `${path}.key`
  const originalKey = await readFile(keyPath)
  const wrongKey = Buffer.from(originalKey)
  wrongKey[0] = wrongKey[0]! ^ 0xff
  await writeFile(keyPath, wrongKey, { mode: 0o600 })
  await assert.rejects(PersistentCommandJournal.open(path, runtimeId), error =>
    error instanceof ProbeError && error.code === 'journal.integrity_failed')

  await writeFile(keyPath, originalKey, { mode: 0o600 })
  await rm(keyPath)
  await assert.rejects(PersistentCommandJournal.open(path, runtimeId), /key is missing/)
})
