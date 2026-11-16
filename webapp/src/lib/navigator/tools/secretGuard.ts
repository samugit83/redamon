/**
 * Secret values under the project's rules of engagement (plan §7.10, §10.2 rows 8 and 27). Unless the
 * RoE says `full_access`, no secret value reaches the person's model provider.
 *
 * The secret-shape masker alone cannot promise that: it knows an AWS key id (`AKIA...`) but not the
 * 40-character secret access key beside it, which has no shape. So two rules sit on top of it:
 *   - every property that holds a secret value is masked by name in a tool result, on a node or in
 *     any map (`maskSecretValues`);
 *   - a Cypher query may not name one, and may not read a property by a computed key (`s[k]`),
 *     which reaches any property under a name the query never spells (`cypherSecretRefusal`).
 * A secret pasted into ordinary text (a finding's evidence, a page title) is still left to the
 * shape masker: no rule over free text can find a value with no shape.
 */
import { DISPLAY_ONLY_PROPS } from '@/lib/secrets/secretProps'

/**
 * The recon-found secret values and the links or text with one left in them (DISPLAY_ONLY_PROPS),
 * plus `matched_text`: a Secret node's full match. On a Vulnerability it is the evidence a template
 * matched, but a map carries no label to tell them apart, so it is masked everywhere.
 */
export const SECRET_VALUE_KEYS: ReadonlySet<string> = new Set([...DISPLAY_ONLY_PROPS, 'matched_text'])

export const SECRET_WITHHELD = "[withheld: this project's rules of engagement keep secret values from the AI]"

const WORD = '[A-Za-z0-9_]'
const NAMED = new RegExp(`(?<!${WORD})(?:${[...SECRET_VALUE_KEYS].join('|')})(?!${WORD})`, 'i')

// Words after which `[` opens a list, never a subscript: `x IN [1, 2]`, `RETURN [n IN ...]`.
const LIST_AFTER = new Set([
  'in', 'return', 'with', 'unwind', 'and', 'or', 'xor', 'not', 'where', 'as', 'when', 'then', 'else',
  'distinct', 'by', 'set', 'contains', 'is', 'case', 'any', 'all', 'none', 'single', 'yield', 'limit',
  'skip', 'starts', 'ends', 'order', 'union', 'optional', 'match', 'call', 'exists',
])
const INTEGER_INDEX = /^\s*(?:\$\w+|-?\d*)\s*(?:\.\.\s*(?:\$\w+|-?\d*)\s*)?$/

/** The first `[` that reads a property by a computed key, or -1. List indexes and slices pass. */
function computedKeyAt(cypher: string): number {
  for (let i = cypher.indexOf('['); i >= 0; i = cypher.indexOf('[', i + 1)) {
    let j = i - 1
    while (j >= 0 && /\s/.test(cypher[j])) j -= 1
    if (j < 0) continue
    const before = cypher[j]
    if (before === ')' || before === ']' || before === '`' || before === '}') {
      // a call, an index, a quoted name or a map: `collect(x)[0]` is fine, `properties(s)[k]` is not
    } else if (/[A-Za-z0-9_]/.test(before)) {
      let k = j
      while (k > 0 && /[A-Za-z0-9_]/.test(cypher[k - 1])) k -= 1
      if (LIST_AFTER.has(cypher.slice(k, j + 1).toLowerCase())) continue
    } else {
      continue
    }
    const close = cypher.slice(i + 1).search(/[\[\]]/)
    const inside = close < 0 ? cypher.slice(i + 1) : cypher.slice(i + 1, i + 1 + close)
    const closesHere = close >= 0 && cypher[i + 1 + close] === ']'
    if (!closesHere || !INTEGER_INDEX.test(inside)) return i
  }
  return -1
}

/** Why a query may not run while secret values are withheld, or null. */
export function cypherSecretRefusal(cypher: string): string | null {
  if (NAMED.test(cypher)) {
    return "This project's rules of engagement keep secret values from the AI, so a query may not read " +
      `${[...SECRET_VALUE_KEYS].join(', ')}. Ask for the secret's type, severity, source or where it was found instead.`
  }
  if (computedKeyAt(cypher) >= 0) {
    return "This project's rules of engagement keep secret values from the AI, so a query may not read a " +
      'property by a computed key (n[k]). Name the properties you need: n.name, n.severity.'
  }
  return null
}

/** The result with every secret-valued property replaced by SECRET_WITHHELD, at any depth. */
export function maskSecretValues(value: unknown, depth = 0): unknown {
  if (depth > 40) return value
  if (Array.isArray(value)) return value.map((v) => maskSecretValues(v, depth + 1))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_VALUE_KEYS.has(k) && v !== null && v !== undefined ? SECRET_WITHHELD : maskSecretValues(v, depth + 1)
    }
    return out
  }
  return value
}
