import { LlmAdapter } from '@deepseek-ai/dsh-llm'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'

class LocalModel extends LlmAdapter {
  constructor() {
    super()
    this.approvalToolIssued = false
    this.questionToolIssued = false
    this.cancelWaitIssued = new Set()
    this.timedQuestionsIssued = new Set()
    this.signedApprovalsIssued = new Set()
  }

  providerInfo(provider) { return { id: provider, name: 'Local DSH integration fixture' } }
  async listModels(provider) { return [{ provider, id: 'offline', name: 'Offline fixture' }] }
  async *stream(options) {
    options.signal?.throwIfAborted()
    const userText = options.messages
      .filter(message => message.role === 'user')
      .flatMap(message => Array.isArray(message.content) ? message.content : [])
      .filter(part => part.type === 'text')
      .map(part => part.text)
      .join('\n')
    const timed = ['REMOTE_TIMED_FOREGROUND', 'REMOTE_TIMED_RELEASE', 'REMOTE_TIMED_LATE', 'REMOTE_TIMED_BACKGROUND']
      .find(marker => userText.includes(marker) && !this.timedQuestionsIssued.has(marker))
    if (timed) {
      this.timedQuestionsIssued.add(timed)
      const args = JSON.stringify({ timeout: timed === 'REMOTE_TIMED_FOREGROUND' ? 10 : timed === 'REMOTE_TIMED_RELEASE' ? 2 : 1,
        questions: [{ id: 'timed-choice', question: 'Answer the timed DSH fixture question.', options: [{ label: 'Reply' }] }] })
      const id = randomUUID()
      yield { type: 'block-start', index: 0, blockType: 'tool-call' }
      yield { type: 'tool-call-delta', index: 0, id, name: 'ask_user_question', argumentsDelta: args }
      yield { type: 'block-end', index: 0, block: { type: 'tool-call', id, name: 'ask_user_question', arguments: args } }
      yield { type: 'finish', reason: { kind: 'tool-calls' } }
      return
    }
    const signedApproval = ['ALLOW', 'REJECT', 'CANCEL', 'REVOKE'].find(mode => userText.includes(`REMOTE_APPROVAL_${mode}`) && !this.signedApprovalsIssued.has(mode))
    if (signedApproval) {
      this.signedApprovalsIssued.add(signedApproval)
      const args = JSON.stringify({ description: `Signed approval ${signedApproval.toLowerCase()} fixture`, command: `printf authorized >> approval-${signedApproval.toLowerCase()}.txt` })
      const id = randomUUID()
      yield { type: 'block-start', index: 0, blockType: 'tool-call' }
      yield { type: 'tool-call-delta', index: 0, id, name: 'bash', argumentsDelta: args }
      yield { type: 'block-end', index: 0, block: { type: 'tool-call', id, name: 'bash', arguments: args } }
      yield { type: 'finish', reason: { kind: 'tool-calls' } }
      return
    }
    const cancelWait = (userText.match(/REMOTE_CANCEL_WAIT_[0-9a-f-]{36}/g) ?? (userText.includes('REMOTE_CANCEL_WAIT') ? ['REMOTE_CANCEL_WAIT'] : []))
      .find(marker => !this.cancelWaitIssued.has(marker))
    if (cancelWait) {
      this.cancelWaitIssued.add(cancelWait)
      yield { type: 'block-start', index: 0, blockType: 'text' }
      yield { type: 'text-delta', index: 0, text: 'Cancelable model call is waiting' }
      await delay(30_000, undefined, { signal: options.signal })
      options.signal?.throwIfAborted()
      yield { type: 'block-end', index: 0, block: { type: 'text', text: 'Unexpected uncanceled completion' } }
      yield { type: 'finish', reason: { kind: 'stop' } }
      return
    }
    if (!this.approvalToolIssued && userText.includes('M0_APPROVAL_DENY')) {
      this.approvalToolIssued = true
      const args = JSON.stringify({ description: 'Create the local denial sentinel file', command: 'printf unauthorized > approval-denied.txt' })
      yield { type: 'block-start', index: 0, blockType: 'tool-call' }
      const id = randomUUID()
      yield { type: 'tool-call-delta', index: 0, id, name: 'bash', argumentsDelta: args }
      yield { type: 'block-end', index: 0, block: { type: 'tool-call', id, name: 'bash', arguments: args } }
      yield { type: 'finish', reason: { kind: 'tool-calls' } }
      return
    }
    if (!this.questionToolIssued && userText.includes('M0_QUESTION_TEST')) {
      this.questionToolIssued = true
      const args = JSON.stringify({ questions: [{
        id: 'm0-choice', question: 'Choose the local DSH fixture answer.', options: [{ label: 'Local answer' }],
      }] })
      yield { type: 'block-start', index: 0, blockType: 'tool-call' }
      const id = randomUUID()
      yield { type: 'tool-call-delta', index: 0, id, name: 'ask_user_question', argumentsDelta: args }
      yield { type: 'block-end', index: 0, block: { type: 'tool-call', id, name: 'ask_user_question', arguments: args } }
      yield { type: 'finish', reason: { kind: 'tool-calls' } }
      return
    }
    yield { type: 'block-start', index: 0, blockType: 'text' }
    yield { type: 'text-delta', index: 0, text: 'DSH local integration fixture response' }
    yield { type: 'block-end', index: 0, block: { type: 'text', text: 'DSH local integration fixture response' } }
    yield { type: 'finish', reason: { kind: 'stop' } }
  }
}

export const name = 'dsh-mobile-local-model-fixture'
export const inject = ['llm']

export function apply(ctx) {
  const adapter = new LocalModel()
  ctx.effect(() => ctx.llm.registerAdapter(['dsh-m0-test'], adapter), 'dsh-mobile.local-model-fixture')
}
