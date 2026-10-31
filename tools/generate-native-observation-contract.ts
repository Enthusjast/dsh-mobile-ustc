import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { z } from 'zod'
import { hostObservationsFrame, NativeObservationWindow } from '../host/remote-control/src/native-observations.js'

function plain(value: unknown): any {
  if (Array.isArray(value)) return value.map(plain)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key]) => key !== '$schema' && key !== 'format').map(([key, item]) => [key, plain(item)]))
  return value
}
const definition = plain(z.toJSONSchema(hostObservationsFrame, { target: 'draft-2020-12' }))
const resultRule = (operations: string[], results: string[]) => ({
  if: { required: ['operation'], properties: { operation: { enum: operations } } },
  then: { properties: { result: { enum: results } } },
})
definition.properties.payload.properties.series.items.allOf = [
  resultRule(['checkpoint', 'cold_checkpoint'], ['persisted', 'failed', 'unavailable']),
  resultRule(['prompt', 'create', 'prompt_reconcile'], ['ok', 'error', 'cancelled']),
  resultRule(['journal_command', 'journal_approval'], ['persisted', 'failed']),
]

definition.description = 'Optional host.observations.v1, installation-only, current connection/epoch. Journal cells additionally require host.journal.observations.v1. Self-reported fixed operations; never authority or command acceptance. Runtime validators also check unique cells, histogram arithmetic and monotone counter deltas.'
const path = new URL('../contracts/ws/v1/relay.schema.json', import.meta.url)
let text = await readFile(path, 'utf8')
const root = JSON.parse(text), name = 'hostObservations', ref = `#/$defs/${name}`
if (JSON.stringify(root.$defs[name]) !== JSON.stringify(definition) || !root.oneOf.some((item: any) => item.$ref === ref)) {
  if (process.argv.includes('--check')) { console.error('Relay Host observations schema is stale; run npm run contracts'); process.exitCode = 1 }
  else {
    const entry = `    "${name}": ` + JSON.stringify(definition, null, 2).replaceAll('\n', '\n    ')
    const pattern = new RegExp(`^    "${name}": \\{[\\s\\S]*?^    \\},?`, 'm')
    text = pattern.test(text) ? text.replace(pattern, () => entry + ',') : text.replace('  "$defs": {', '  "$defs": {\n' + entry + ',')
    if (!root.oneOf.some((item: any) => item.$ref === ref)) text = text.replace('  "oneOf": [', '  "oneOf": [\n    ' + JSON.stringify({ $ref: ref }) + ',')
    await writeFile(path, text)
  }
}
const identity = { runtime_id: '33333333-3333-4333-8333-333333333333', runtime_epoch: '44444444-4444-4444-8444-444444444444' }
const window = new NativeObservationWindow(), connection = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
window.record('checkpoint', 'persisted', 1500)
const first = { v: 1, type: 'host.observations', ...identity, payload: window.snapshot(connection) }
window.record('checkpoint', 'failed', 2000); window.record('prompt', 'ok', 200)
const next = { ...first, payload: window.snapshot(connection) }
window.record('journal_command', 'persisted', 7000); window.record('journal_approval', 'failed', 12000)
const journal = { ...first, payload: window.snapshot(connection) }
for (const [name, value] of [['host-observations', first], ['host-observations-next', next], ['host-observations-journal', journal]] as const) {
  hostObservationsFrame.parse(value)
  const path = new URL(`../contracts/ws/v1/golden/${name}.json`, import.meta.url), body = JSON.stringify(value, null, 2) + '\n'
  if (process.argv.includes('--check')) { if (await readFile(path, 'utf8').catch(() => '') !== body) { console.error(`${name} golden is stale`); process.exitCode = 1 } }
  else { await mkdir(new URL('../contracts/ws/v1/golden/', import.meta.url), { recursive: true }); await writeFile(path, body) }
}
