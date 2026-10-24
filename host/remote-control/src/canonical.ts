import serialize from 'canonicalize'

export const MAX_CANONICAL_BYTES = 128 * 1024
const MAX_NODES = 16_384
const invalid = () => new Error('canonical: invalid JSON object')
function wellFormed(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index)
    if (code >= 0xdc00 && code <= 0xdfff) return false
    if (code < 0xd800 || code > 0xdbff) continue
    const low = text.charCodeAt(++index)
    if (!(low >= 0xdc00 && low <= 0xdfff)) return false
  }
  return true
}

/** Only inert, finite JSON values enter signing; no getters, toJSON or sparse arrays. */
export function canonicalObject(value: unknown): Uint8Array {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid()
  const ancestors = new Set<object>()
  let nodes = 0
  let textBytes = 0
  const text = (value: string) => { textBytes += Buffer.byteLength(value); if (textBytes > MAX_CANONICAL_BYTES || !wellFormed(value)) throw invalid() }
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > MAX_NODES || depth > 32) throw invalid()
    if (typeof item === 'string') { text(item); return }
    if (typeof item === 'number') { if (!Number.isFinite(item)) throw invalid(); return }
    if (item === null || typeof item === 'boolean') return
    if (typeof item !== 'object' || ancestors.has(item)) throw invalid()
    if (Object.getOwnPropertySymbols(item).length) throw invalid()
    const prototype = Object.getPrototypeOf(item)
    if (Array.isArray(item) ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) throw invalid()
    ancestors.add(item)
    const descriptors = Object.getOwnPropertyDescriptors(item)
    if (Array.isArray(item)) {
      if (Object.keys(descriptors).length !== item.length + 1) throw invalid()
      for (let index = 0; index < item.length; index++) {
        const property = descriptors[String(index)]
        if (!property || !('value' in property) || !property.enumerable) throw invalid()
        visit(property.value, depth + 1)
      }
    } else for (const [key, property] of Object.entries(descriptors)) {
      text(key)
      if (!('value' in property) || !property.enumerable) throw invalid()
      visit(property.value, depth + 1)
    }
    ancestors.delete(item)
  }
  visit(value, 0)
  const encoded = Buffer.from(serialize(value)!)
  if (encoded.length > MAX_CANONICAL_BYTES) throw invalid()
  return encoded
}

/** Decode JSON while rejecting duplicate names before JCS can normalize them away. */
function parseObject(raw: Uint8Array | string): Record<string, unknown> {
  const text = typeof raw === 'string' ? raw : new TextDecoder('utf-8', { fatal: true }).decode(raw)
  if (!wellFormed(text) || Buffer.byteLength(text) > MAX_CANONICAL_BYTES) throw invalid()
  const value = JSON.parse(text) as unknown
  let position = 0, nodes = 0
  const space = () => { while (/[\t\n\r ]/.test(text[position] ?? '!')) position++ }
  const string = (): string => {
    const start = position++
    while (text[position] !== '"') { if (text[position] === '\\') position++; position++ }
    return JSON.parse(text.slice(start, ++position)) as string
  }
  const scan = (depth: number): void => {
    if (++nodes > MAX_NODES || depth > 32) throw invalid()
    space()
    if (text[position] === '{') {
      position++; space()
      const names = new Set<string>()
      if (text[position] === '}') { position++; return }
      for (;;) {
        space()
        const key = string()
        if (names.has(key)) throw invalid()
        names.add(key)
        space(); position++ // colon; JSON.parse has already checked syntax.
        scan(depth + 1); space()
        if (text[position++] === '}') break
      }
    } else if (text[position] === '[') {
      position++; space()
      if (text[position] === ']') { position++; return }
      for (;;) { scan(depth + 1); space(); if (text[position++] === ']') break }
    } else if (text[position] === '"') string()
    else while (position < text.length && !/[,}\]\t\n\r ]/.test(text[position]!)) position++
  }
  scan(0)
  canonicalObject(value)
  return value as Record<string, unknown>
}

export function parseSigningObject(raw: Uint8Array | string): Record<string, unknown> {
  try { return parseObject(raw) } catch { throw invalid() }
}

export function canonicalJSON(raw: Uint8Array | string): Uint8Array { return canonicalObject(parseSigningObject(raw)) }
