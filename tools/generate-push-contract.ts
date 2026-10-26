import { readFile, writeFile } from 'node:fs/promises'
import { z } from 'zod'
import { questionReference, questionReferencesFrame, questionReferencesAck } from '../host/remote-control/src/question-reference-protocol.js'

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const digest = z.string().regex(/^[0-9a-f]{64}$/)
const secret = z.string().regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/)
const time = z.iso.datetime({ offset: true })
const base = { v: z.literal('1'), binding_id: uuid, expires_at: time }
const data = z.discriminatedUnion('kind', [
  z.strictObject({ ...base, kind: z.literal('registration_challenge'), challenge: secret }),
  z.strictObject({ ...base, kind: z.literal('interaction'), notification_id: uuid }),
])
const registration = z.strictObject({ binding_id: uuid, organization_id: uuid, provider: z.literal('fcm'), address: z.string().regex(/^[A-Za-z0-9_-]{22}$/), revoke_secret_sha256: digest })
const referenceFields = { notification_id: uuid, binding_id: uuid, reference_id: uuid, runtime_id: uuid, runtime_epoch: uuid, session_id: uuid,
  availability: z.enum(['online', 'host_offline', 'stale_epoch', 'ended','state_unavailable']), expires_at: time }
const reference = z.discriminatedUnion('kind',[
  z.strictObject({ ...referenceFields, kind:z.literal('approval'),state:z.enum(['pending','decision_received','allowed','denied','expired','cancelled','invalidated','outcome_unknown']) }),
  z.strictObject({ ...referenceFields, kind:z.literal('question'),state:z.enum(['pending','expired','ended']) }),
  z.strictObject({ ...referenceFields, kind:z.literal('timed_question'),state:z.enum(['pending','continued','reply_queued','ended']) }),
])
async function output(path: string, value: unknown) {
  const target = new URL(`../contracts/push/v1/${path}`, import.meta.url), body = JSON.stringify(value, null, 2) + '\n'
  if (process.argv.includes('--check')) { if (await readFile(target, 'utf8').catch(() => '') !== body) { console.error(`contracts/push/v1/${path} is stale; run npm run contracts`); process.exitCode = 1 } }
  else await writeFile(target, body)
}
for (const [name, schema] of Object.entries({ 'provider-data': data, registration, reference,
  'question-reference-item': questionReference, 'question-references': questionReferencesFrame, 'question-references-ack': questionReferencesAck })) {
  await output(`${name}.schema.json`, { ...z.toJSONSchema(schema, { target: 'draft-2020-12' }), $id: `urn:dsh-mobile-ustc:push:${name}:v1`,
    description: 'Minimal notification references, not execution authority. FCM delivery is data only and never carries tool arguments, question text, signed decisions or file contents. Confirmation requires the original authenticated device and a fresh provider-delivered challenge. Interaction details and all actions require current authorization and native state.' })
}
const binding = '11111111-1111-4111-8111-111111111111', id = '22222222-2222-4222-8222-222222222222', expires = '2026-10-26T12:03:00.000Z'
const challenge = { v: '1', kind: 'registration_challenge', binding_id: binding, challenge: 'A'.repeat(43), expires_at: expires }
const interaction = { v: '1', kind: 'interaction', binding_id: binding, notification_id: id, expires_at: expires }
const input = { binding_id: binding, organization_id: '33333333-3333-4333-8333-333333333333', provider: 'fcm', address: 'c' + 'A'.repeat(21), revoke_secret_sha256: 'a'.repeat(64) }
const view = { notification_id: id, binding_id: binding, kind: 'approval', reference_id: '44444444-4444-4444-8444-444444444444', runtime_id: '55555555-5555-4555-8555-555555555555',
  runtime_epoch: '66666666-6666-4666-8666-666666666666', session_id: '77777777-7777-4777-8777-777777777777', state: 'pending', availability: 'online', expires_at: expires }
for (const [name, sample, schema] of [['registration-challenge', challenge, data], ['interaction', interaction, data], ['registration', input, registration], ['reference', view, reference]] as const) {
  schema.parse(sample); await output(`golden/${name}.json`, sample)
}
const feed = { v: 1, type: 'question.references', request_id: id, runtime_id: view.runtime_id, runtime_epoch: view.runtime_epoch, payload: { sequence: 1, items: [
  { question_id: view.reference_id, session_id: view.session_id, kind: 'question', state: 'pending', expires_at: expires },
  { question_id: '88888888-8888-4888-8888-888888888888', session_id: view.session_id, kind: 'timed_question', state: 'continued', expires_at: null },
] } }
const acknowledged = { ...feed, type: 'question.references.ack', payload: { sequence: 1, item_count: 2 } }
for (const [name, sample, schema] of [['question-references',feed,questionReferencesFrame],['question-references-ack',acknowledged,questionReferencesAck],
  ['question-reference',{ ...view,kind:'question' },reference],['timed-question-reference',{ ...view,kind:'timed_question',state:'continued' },reference]] as const) {
  schema.parse(sample); await output(`golden/${name}.json`,sample)
}

// Keep the general Relay contract in sync without reformatting its other frames.
const relayPath = new URL('../contracts/ws/v1/relay.schema.json',import.meta.url)
let relayText = await readFile(relayPath,'utf8')
function relaySchema(value: unknown): any {
  if (Array.isArray(value)) return value.map(relaySchema)
  if (value && typeof value==='object') return Object.fromEntries(Object.entries(value).filter(([key,item])=>key!=='$schema' && !(key==='format' && item==='date-time')).map(([key,item])=>[key,relaySchema(item)]))
  return value
}
for (const [name,schema] of [['questionReferences',questionReferencesFrame],['questionReferencesAck',questionReferencesAck]] as const) {
  const root=JSON.parse(relayText), definition=relaySchema(z.toJSONSchema(schema,{target:'draft-2020-12'})), ref={ $ref:`#/$defs/${name}` }
  const hasRef=root.oneOf.some((item: any)=>item.$ref===ref.$ref)
  if (JSON.stringify(root.$defs[name])===JSON.stringify(definition) && hasRef) continue
  if (process.argv.includes('--check')) { console.error(`Relay ${name} is stale; run npm run contracts`);process.exitCode=1;continue }
  const entry=`    "${name}": `+JSON.stringify(definition,null,2).replaceAll('\n','\n    ')
  const pattern=new RegExp(`^    "${name}": \\{[\\s\\S]*?^    \\},?`,'m')
  if (pattern.test(relayText)) relayText=relayText.replace(pattern,()=>entry+',')
  else relayText=relayText.replace('  "$defs": {','  "$defs": {\n'+entry+',')
  if (!hasRef) relayText=relayText.replace('  "oneOf": [','  "oneOf": [\n    '+JSON.stringify(ref)+',')
}
if (!process.argv.includes('--check')) await writeFile(relayPath,relayText)
