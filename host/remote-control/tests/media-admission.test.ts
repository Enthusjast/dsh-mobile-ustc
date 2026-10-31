import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { host, TestModel } from './harness.js'
import { mediaPixelPNG } from './media-fixtures.js'
import { DshClient } from '../src/dsh-client.js'
import { NativeFileRegistry } from '../src/file-registry.js'
import { rasterHeader, imagePromptError } from '../src/image-admission.js'
import { MAX_IMAGE_DIMENSION, MAX_IMAGE_PIXELS } from '../src/image-protocol.js'
import type { FileOffer } from '../src/file-protocol.js'

const signal = () => new AbortController().signal
const actor = { userId: randomUUID(), deviceId: randomUUID() }
function offer(bytes: Buffer): FileOffer {
  return { handoff_id: randomUUID(), file_id: randomUUID(), user_id: actor.userId, device_id: actor.deviceId, key_version: 1, grant_version: 1,
    name: 'picture.png', size_bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), download_token: '',
    lease_until: new Date(Date.now() + 5000).toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString() }
}

test('only an explicit image part promotes same validated staged bytes to real native image input', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new NativeFileRegistry(client, randomUUID())
  try {
    const session = (await client.create('fixture', 'fixture')).session_id
    const bytes = mediaPixelPNG(), file = offer(bytes)
    await registry.stage(session, file, (async function* () { yield bytes })(), signal(), () => true)
    await assert.rejects(registry.resolveImage(file.file_id, session, actor, signal()), /file.staging_required/)
    registry.confirm(file.file_id)
    assert.equal(registry.resolve(file.file_id, session, actor).type, 'file')
    await assert.rejects(registry.resolveImage(file.file_id, session, { ...actor, deviceId: randomUUID() }, signal()), /file.staging_required/)
    const image = await registry.resolveImage(file.file_id, session, actor, signal())
    assert.equal(image.type, 'image')
    if (image.type !== 'image') assert.fail('not a visual image')
    assert.equal(image.mediaType, 'image/png'); assert.deepEqual(Buffer.from(image.data, 'base64'), bytes)
    const native = await client.resolve(session, signal())
    await client.prompt(native, randomUUID(), 'queue', [image], signal())
    await h.ctx.agents.get(native)!.whenIdle()
    const messages = h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message' && event.data.source.kind === 'user')
    assert.equal(messages.length, 1)
    const message = messages[0]!
    if (message.type !== 'user/message') assert.fail('no persisted native message')
    assert.equal(message.data.content[0]!.type, 'image')
    assert.equal(h.errors.length, 0)
  } finally { registry.close(); await h.close() }
})

test('a plausible raster header cannot bypass a real full native decode or create a native message', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new NativeFileRegistry(client, randomUUID())
  try {
    const session = (await client.create('fixture', 'fixture')).session_id
    const truncated = mediaPixelPNG().subarray(0, 33), file = offer(truncated)
    assert.equal(rasterHeader(truncated).mediaType, 'image/png')
    await registry.stage(session, file, (async function* () { yield truncated })(), signal(), () => true)
    registry.confirm(file.file_id)
    await assert.rejects(registry.resolveImage(file.file_id, session, actor, signal()), /image.invalid/)
    const native = await client.resolve(session, signal())
    assert.equal(h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message' && event.data.source.kind === 'user').length, 0)
  } finally { registry.close(); await h.close() }
})

test('predecode bounds reject raster bombs, nonrasters and unsupported remote content', () => {
  for (const [width, height] of [[MAX_IMAGE_DIMENSION + 1, 1], [8000, 8000]]) {
    const bytes = mediaPixelPNG(); bytes.writeUInt32BE(width!, 16); bytes.writeUInt32BE(height!, 20)
    assert.ok(width! > MAX_IMAGE_DIMENSION || width! * height! > MAX_IMAGE_PIXELS)
    assert.throws(() => rasterHeader(bytes), /image.too_large/)
  }
  for (const text of ['<svg xmlns="http://www.w3.org/2000/svg"/>', '<html><img src="https://invalid.example/picture"/></html>', 'https://invalid.example/picture.png']) {
    assert.throws(() => rasterHeader(Buffer.from(text)), /image.invalid/)
  }
  assert.equal(imagePromptError({ isDSHRemoteError: true, code: 'session/attachment-invalid', details: { reason: 'MODEL_DOES_NOT_SUPPORT_IMAGES' } })?.code, 'image.model_unsupported')
  assert.equal(imagePromptError({ isDSHRemoteError: true, code: 'gateway/internal', details: {} }), undefined)
  assert.equal(imagePromptError(new Error('MODEL_DOES_NOT_SUPPORT_IMAGES')), undefined)
})

test('native selected-model inputModalities rejects real image prompts instead of treating them as generic files', async () => {
  const h = await host({ probe: false })
  class TextOnlyModel extends TestModel {
    override providerInfo() { return { id: 'image-text-only', name: 'Text only fixture' } }
    override async listModels() { return [{ provider: 'image-text-only', id: 'text-only', name: 'Text only', inputModalities: ['text'] as const }] }
    override async resolveModel(provider: string, model: string) { return { provider, id: model, name: 'Text only', inputModalities: ['text'] as const } }
  }
  const registration = h.ctx.llm.registerAdapter(['image-text-only'], new TextOnlyModel())
  try {
    const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
    const session = (await client.create('fixture', 'fixture')).session_id, native = await client.resolve(session, signal())
    assert.deepEqual((await h.ctx.llm.resolveModelInfo('image-text-only', 'text-only')).inputModalities, ['text'])
    const selection = await client.selectModel(native, { provider: 'image-text-only', model: 'text-only' }, signal())
    assert.equal(selection.selected.provider, 'image-text-only'); assert.equal(selection.selected.model, 'text-only')
    await assert.rejects(client.prompt(native, randomUUID(), 'queue', [{ type: 'image', mediaType: 'image/png', data: mediaPixelPNG().toString('base64') }], signal()), /image.model_unsupported/)
    assert.equal(h.ctx.agents.get(native)!.session.snapshotEvents().filter(event => event.type === 'user/message' && event.data.source.kind === 'user').length, 0)
  } finally { registration(); await h.close() }
})

test('revocation at completion of the real decoder cannot publish image bytes', async () => {
  const h = await host({ probe: false })
  const client = new DshClient(h.ctx, h.runtimeId, [{ id: 'fixture', cwd: h.cwd }], ['fixture'])
  const registry = new NativeFileRegistry(client, randomUUID())
  const validate = h.ctx.attachments.validateImage.bind(h.ctx.attachments)
  try {
    const session = (await client.create('fixture', 'fixture')).session_id, bytes = mediaPixelPNG(), file = offer(bytes)
    let authorized = true
    await registry.stage(session, file, (async function* () { yield bytes })(), signal(), () => authorized)
    registry.confirm(file.file_id)
    h.ctx.attachments.validateImage = async input => { await validate(input); authorized = false }
    await assert.rejects(registry.resolveImage(file.file_id, session, actor, signal()), /file.staging_required/)
    assert.equal(registry.available(file.file_id), false)
  } finally { h.ctx.attachments.validateImage = validate; registry.close(); await h.close() }
})
