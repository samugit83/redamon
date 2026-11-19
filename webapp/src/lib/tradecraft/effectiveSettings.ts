/**
 * The effective settings of one ingestion or one run: spec default, then the user's saved
 * value, then the resource's override, clamped to the ceiling. Each value carries where it
 * came from, and the hash of the values tells a resource ingested with other settings
 * (the stale badge, §3.3).
 *
 * Stored values that no longer fit the spec (a key removed, a type changed) are skipped
 * so an old row never breaks a read: the spec ignores what it does not know. The module
 * stays free of Node APIs so a form can show inherited values with the same code.
 */
import {
  SETTINGS, cloneValue, type ListOverride, type ResourceOverrides, type SettingDef, type SettingScope,
  type SettingValue, type SettingsValues, type TextOverride,
} from './settingsSpec'

export type Provenance = 'system' | 'user' | 'resource'

export interface UserSettingsInput {
  ingestion?: unknown
  search?: unknown
}

export interface EffectiveSettings {
  values: SettingsValues
  provenance: Record<string, Provenance>
  hash: string
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * The value as the spec's type, clamped to [min, ceiling] and to the length limits, or
 * undefined when it cannot be read as that type. Lenient on purpose: the validators decide
 * what a person may save; this decides what an ingestion may run with.
 */
export function clampValue(def: SettingDef, v: unknown): SettingValue | undefined {
  switch (def.type) {
    case 'int':
    case 'number': {
      if (typeof v !== 'number' || !Number.isFinite(v)) return undefined
      const n = def.type === 'int' ? Math.round(v) : v
      return Math.min(def.ceiling!, Math.max(def.min!, n))
    }
    case 'bool':
      return typeof v === 'boolean' ? v : undefined
    case 'enum':
      return typeof v === 'string' && def.values!.includes(v) ? v : undefined
    case 'string':
      return typeof v === 'string' ? v.slice(0, def.maxLength) : undefined
    case 'list':
      return Array.isArray(v) ? clampList(def, v) : undefined
  }
}

function clampList(def: SettingDef, items: unknown[]): string[] {
  const out: string[] = []
  for (const item of items) {
    if (typeof item !== 'string' || item.length === 0) continue
    const s = item.slice(0, def.maxLength)
    if (def.values && !def.values.includes(s)) continue
    if (!out.includes(s)) out.push(s)
    if (out.length >= def.maxItems!) break
  }
  return out
}

function applyOverride(def: SettingDef, inherited: SettingValue, raw: unknown): SettingValue | undefined {
  if (!def.listMode) return clampValue(def, raw)
  if (!isPlainObject(raw) || (raw.mode !== 'add' && raw.mode !== 'replace')) return undefined
  if (def.type === 'list') {
    const items = (raw as ListOverride).items
    if (!Array.isArray(items)) return undefined
    return raw.mode === 'replace' ? clampList(def, items) : clampList(def, [...(inherited as string[]), ...items])
  }
  const text = (raw as TextOverride).text
  if (typeof text !== 'string') return undefined
  if (raw.mode === 'replace') return text.slice(0, def.maxLength)
  return [inherited as string, text].filter(Boolean).join('\n').slice(0, def.maxLength)
}

/**
 * Effective values for one scope. `user` is the account's TradecraftUserSettings row
 * (`ingestion`/`search` JSON, or nothing), `resource` its `overrides` JSON (search
 * settings are user-only, so a resource changes nothing there).
 */
export function effectiveSettings(
  { user, resource, scope = 'ingestion' }: { user?: UserSettingsInput | null; resource?: ResourceOverrides | unknown; scope?: SettingScope },
): EffectiveSettings {
  const userValues = user && isPlainObject(user[scope]) ? (user[scope] as Record<string, unknown>) : {}
  const overrides = isPlainObject(resource) ? resource : {}
  const values: SettingsValues = {}
  const provenance: Record<string, Provenance> = {}
  for (const def of SETTINGS) {
    if (def.scope !== scope) continue
    let value: SettingValue = cloneValue(def.default)
    let from: Provenance = 'system'
    if (def.level !== 'resource' && Object.hasOwn(userValues, def.key)) {
      const v = clampValue(def, userValues[def.key])
      if (v !== undefined) { value = v; from = 'user' }
    }
    if (def.level !== 'user' && Object.hasOwn(overrides, def.key)) {
      const v = applyOverride(def, value, overrides[def.key])
      if (v !== undefined) { value = v; from = 'resource' }
    }
    values[def.key] = clampValue(def, value) ?? cloneValue(def.default)
    provenance[def.key] = from
  }
  return { values, provenance, hash: settingsHash(values) }
}

/** Canonical JSON: object keys sorted at every level, no whitespace. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  if (isPlainObject(v)) {
    return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

/** The first 16 hex characters of the SHA-256 of the values' canonical JSON. */
export function settingsHash(values: SettingsValues): string {
  return sha256Hex(canonicalJson(values)).slice(0, 16)
}

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

/**
 * SHA-256 (FIPS 180-4) of a string's UTF-8 bytes. Written here rather than taken from
 * node:crypto so the module also runs in the browser; the test compares it with Node's.
 */
export function sha256Hex(text: string): string {
  const data = new TextEncoder().encode(text)
  const bitLength = data.length * 8
  const padded = new Uint8Array((((data.length + 9 + 63) >> 6) << 6))
  padded.set(data)
  padded[data.length] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000))
  view.setUint32(padded.length - 4, bitLength >>> 0)
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  const w = new Uint32Array(64)
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4)
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, hh] = h
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) >>> 0
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0
  }
  return Array.from(h, x => x.toString(16).padStart(8, '0')).join('')
}
