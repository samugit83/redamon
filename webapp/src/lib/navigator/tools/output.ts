/**
 * What a tool result may carry back to the model (plan §7.10), as defence in depth behind the MCP
 * functions:
 *   - graph nodes go through `stripStepContent`, so a reader below Raw data & files never gets
 *     attack-chain step content;
 *   - the owner-only project columns (`share: secret`) and a short list of credential fields are
 *     never returned, to anyone: the model needs none of them;
 *   - unless the project's RoE says `full_access`, every secret-valued property is withheld by name
 *     (secretGuard.ts) and every string is passed through the secret-shape masker shared with the
 *     agent (D14);
 *   - arrays are cut at ROWS_MAX and the whole at TOOL_RESULT_MAX_BYTES, with `truncated: true`.
 */
import { SHARE_SECRET_FIELDS } from '@/lib/authz/projectReadView'
import { stripStepContent } from '@/lib/authz/stepContent'
import type { ProjectAccess } from '@/lib/authz/projectAccess'
import { redactDeep } from '@/lib/plugins/redact'
import { ROWS_MAX, TOOL_RESULT_MAX_BYTES } from '../constants'
import { maskSecretValues } from './secretGuard'

const NEVER_RETURNED = new Set<string>([
  ...SHARE_SECRET_FIELDS,
  'password', 'passwordHash', 'tokenHash', 'apiKey', 'apiKeyEncrypted', 'secretKey',
  'ngrokAuthtoken', 'chiselAuth', 'authProfile', 'roeDocumentData', 'roeDocumentText', 'roeContacts',
  'roeEmergencyContacts',
])

interface GraphNodeLike {
  labels?: readonly string[]
  type?: string
  properties: Record<string, unknown>
}

function isGraphNode(v: unknown): v is GraphNodeLike {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false
  const o = v as Record<string, unknown>
  return !!o.properties && typeof o.properties === 'object' && (Array.isArray(o.labels) || typeof o.type === 'string')
}

export interface Shaped {
  result: unknown
  truncated: boolean
}

function walk(value: unknown, access: ProjectAccess, state: { truncated: boolean }, depth = 0): unknown {
  if (depth > 40) return '[nested too deep]'
  if (Array.isArray(value)) {
    let arr = value
    if (arr.length > ROWS_MAX) {
      arr = arr.slice(0, ROWS_MAX)
      state.truncated = true
    }
    return arr.map((v) => walk(v, access, state, depth + 1))
  }
  if (value && typeof value === 'object') {
    let obj = value as Record<string, unknown>
    if (isGraphNode(obj)) obj = stripStepContent([obj as GraphNodeLike], access)[0] as unknown as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(obj)) {
      if (NEVER_RETURNED.has(k)) continue
      out[k] = walk(v, access, state, depth + 1)
    }
    return out
  }
  return value
}

function halveLargestArray(value: unknown): boolean {
  let best: unknown[] | null = null
  const visit = (v: unknown) => {
    if (Array.isArray(v)) {
      if (!best || v.length > best.length) best = v
      v.forEach(visit)
    } else if (v && typeof v === 'object') {
      Object.values(v as Record<string, unknown>).forEach(visit)
    }
  }
  visit(value)
  const arr = best as unknown[] | null
  if (!arr || arr.length <= 1) return false
  arr.splice(Math.ceil(arr.length / 2))
  return true
}

export function shapeToolResult(raw: unknown, opts: { access: ProjectAccess; mask: boolean }): Shaped {
  const state = { truncated: false }
  let result = walk(raw, opts.access, state)
  if (opts.mask) result = redactDeep(maskSecretValues(result))
  for (let i = 0; i < 12 && JSON.stringify(result ?? null).length > TOOL_RESULT_MAX_BYTES; i += 1) {
    if (!halveLargestArray(result)) break
    state.truncated = true
  }
  const text = JSON.stringify(result ?? null)
  if (text.length > TOOL_RESULT_MAX_BYTES) {
    return { result: { partial: text.slice(0, TOOL_RESULT_MAX_BYTES - 200), truncated: true, hint: 'Narrow the query.' }, truncated: true }
  }
  if (state.truncated && result && typeof result === 'object' && !Array.isArray(result)) {
    return { result: { ...(result as Record<string, unknown>), truncated: true, hint: 'Narrow the query.' }, truncated: true }
  }
  if (state.truncated) return { result: { items: result, truncated: true, hint: 'Narrow the query.' }, truncated: true }
  return { result, truncated: false }
}
