// Test-only observation of the normal native controller. Never replaces a native operation.
import assert from 'node:assert/strict'
import { renameSync, writeFileSync } from 'node:fs'
import { isHumanInput } from '../../host/remote-control/lib/visible-message.js'
import { WorkspaceChanges } from '../../host/remote-control/lib/workspace-changes.js'

export function inspectKotlinReview(ctx, path) {
  const state = { human_seq: null, hidden_contexts: 0, fork_calls: 0, inclusive_prefix: false, source_unchanged: false, child_checkpoint: false, patch_reads: 0, patch_reopens: 0, repeated_patch_cursor: false }
  const sources = new Set()
  const prompt = ctx.sessionController.prompt, fork = ctx.sessionController.fork, flush = ctx.sessions.flush
  const patch = WorkspaceChanges.prototype.patch, opened = new Set(), returnedCursors = new Set()
  const observedPatch = async function (...args) {
    state.patch_reads++
    if (!args[2].cursor) {
      if (opened.has(args[2].file_id)) state.patch_reopens++
      opened.add(args[2].file_id)
    }
    const result = await patch.apply(this, args)
    if (result.next_cursor && returnedCursors.has(result.next_cursor)) state.repeated_patch_cursor = true
    if (result.next_cursor) returnedCursors.add(result.next_cursor)
    collect(); return result
  }
  WorkspaceChanges.prototype.patch = observedPatch
  let source, child, original
  function collect() {
    for (const id of sources) {
      const events = ctx.agents.get(id)?.session.snapshotEvents() ?? []
      const target = events.find(event => event.type === 'user/message' && isHumanInput(event.data.source) && event.data.content.some(part => part.type === 'text' && part.text === 'KOTLIN_REVIEW_HUMAN'))
      if (target) state.human_seq = target.seq
      state.hidden_contexts = events.filter(event => event.type === 'user/message' && !isHumanInput(event.data.source)).length
    }
    if (source && original) state.source_unchanged = JSON.stringify(ctx.agents.get(source)?.session.snapshotEvents()) === original
    writeFileSync(path + '.tmp', JSON.stringify(state), { mode: 0o600 })
    renameSync(path + '.tmp', path)
  }
  const observedPrompt = async (...args) => {
    sources.add(args[0].sessionId)
    const result = await prompt.apply(ctx.sessionController, args)
    collect(); return result
  }
  const observedFork = async (...args) => {
    state.fork_calls++
    source = args[0].sessionId
    const events = ctx.agents.get(source).session.snapshotEvents()
    original = JSON.stringify(events)
    assert.equal(args[0].allowMigration, false)
    assert.equal(args[0].atSeq, state.human_seq)
    const result = await fork.apply(ctx.sessionController, args)
    child = result.sessionId
    assert.notEqual(child, source)
    const childEvents = ctx.agents.get(child).session.snapshotEvents()
    assert.deepEqual(childEvents.slice(0, args[0].atSeq + 1), events.slice(0, args[0].atSeq + 1))
    state.inclusive_prefix = true
    collect(); return result
  }
  const observedFlush = async (...args) => {
    const result = await flush.apply(ctx.sessions, args)
    if (child && args[0] === ctx.sessions.get(child) && result === true) state.child_checkpoint = true
    collect(); return result
  }
  ctx.sessionController.prompt = observedPrompt
  ctx.sessionController.fork = observedFork
  ctx.sessions.flush = observedFlush
  const timer = setInterval(collect, 100); timer.unref(); collect()
  ctx.effect(() => () => {
    clearInterval(timer)
    if (ctx.sessionController.prompt === observedPrompt) ctx.sessionController.prompt = prompt
    if (ctx.sessionController.fork === observedFork) ctx.sessionController.fork = fork
    if (ctx.sessions.flush === observedFlush) ctx.sessions.flush = flush
    if (WorkspaceChanges.prototype.patch === observedPatch) WorkspaceChanges.prototype.patch = patch
  }, 'kotlin-review-inspection')
}
