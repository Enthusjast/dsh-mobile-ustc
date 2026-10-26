// Explicit device fixture only. Persist counts/digests, never native IDs, receipts or message bodies.
import { createHash } from 'node:crypto'
import { renameSync, writeFileSync } from 'node:fs'

export function inspectAndroidFiles(ctx, path) {
  const state = { prompt_calls: 0, uploads: [], human_messages: 0, file_messages: [] }
  const native = new Set()
  const prompt = ctx.sessionController.prompt, upload = ctx.fileUploads.uploadStream
  const collect = () => {
    const messages = [...native].flatMap(id => ctx.agents.get(id)?.session.snapshotEvents() ?? [])
      .filter(event => event.type === 'user/message' && event.data.source.kind === 'user')
    state.human_messages = messages.length
    state.file_messages = messages.flatMap(event => event.data.content)
      .filter(part => part.type === 'file').map(part => ({
        sha256: String(part.attachment.attachmentId).slice('sha256:'.length), size_bytes: part.attachment.bytes,
      }))
    writeFileSync(path + '.tmp', JSON.stringify(state), { mode: 0o600 })
    renameSync(path + '.tmp', path)
  }
  const observedPrompt = async (...args) => {
    native.add(args[0].sessionId); state.prompt_calls++; collect()
    return prompt.apply(ctx.sessionController, args)
  }
  const observedUpload = async request => {
    const receipt = await upload.call(ctx.fileUploads, request)
    const hash = createHash('sha256'); let size = 0
    for await (const bytes of ctx.attachments.readFileStream(receipt.file)) { hash.update(bytes); size += bytes.byteLength }
    state.uploads.push({ sha256: hash.digest('hex'), size_bytes: size }); collect()
    return receipt
  }
  ctx.sessionController.prompt = observedPrompt
  ctx.fileUploads.uploadStream = observedUpload
  const timer = setInterval(collect, 250); timer.unref(); collect()
  ctx.effect(() => () => {
    clearInterval(timer)
    if (ctx.sessionController.prompt === observedPrompt) ctx.sessionController.prompt = prompt
    if (ctx.fileUploads.uploadStream === observedUpload) ctx.fileUploads.uploadStream = upload
  }, 'android-device-file-inspection')
}
