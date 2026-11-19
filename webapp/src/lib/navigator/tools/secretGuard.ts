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
 *     The query is judged as Neo4j reads it: a `\uXXXX` escape (decoded before Neo4j reads a
 *     name: `s.\u006datched_text`) and a comment (which may sit between an expression and its
 *     subscript: `properties(s)/**\/[k]`) are refused, and string literals are not code.
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
const SINGLE_LITERAL = /^\s*(?:-?\d+(?:\.\d+)?|'\s*'|"\s*"|true|false|null|\$\w+)?\s*$/i
// Neo4j decodes \uXXXX before it lexes the query, names and backticked names included
// (graph_db/tenant_filter.py refuses it too, but this check runs first).
const UNICODE_ESCAPE = /\\u[0-9A-Fa-f]{4}/
const COMMENT = /\/\/|\/\*/

/**
 * The query with each string literal's content blanked and each quoted name's replaced by `_`,
 * same length, so a `[`, a `//` or a quote inside one is never read as code.
 */
function codeView(cypher: string): string {
  const out: string[] = []
  for (let i = 0; i < cypher.length;) {
    const c = cypher[i]
    if (c !== "'" && c !== '"' && c !== '`') {
      out.push(c)
      i += 1
      continue
    }
    let j = i + 1
    while (j < cypher.length && cypher[j] !== c) j += c !== '`' && cypher[j] === '\\' ? 2 : 1
    const end = Math.min(j, cypher.length)
    out.push(c, (c === '`' ? '_' : ' ').repeat(end - i - 1))
    if (end < cypher.length) out.push(c)
    i = end + 1
  }
  return out.join('')
}

/**
 * Whether the `[` at `open` holds a list: empty, a comprehension, several items or one literal.
 * A nested group counts as an item that is none of these, so `limit[[k][0]]` is a subscript.
 */
function holdsList(code: string, open: number): boolean {
  let depth = 0
  let top = ''
  for (let i = open + 1; i < code.length; i += 1) {
    const ch = code[i]
    if (ch === '[' || ch === '(' || ch === '{') {
      if (depth === 0) top += 'x'
      depth += 1
    } else if (ch === ']' || ch === ')' || ch === '}') {
      if (depth === 0) return ch === ']' && (/,|\||\bIN\b/i.test(top) || SINGLE_LITERAL.test(top))
      depth -= 1
    } else if (depth === 0) {
      top += ch
    }
  }
  return false
}

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
      // A keyword opens a list (`x IN [1, 2]`), but Neo4j also takes most keywords as variable
      // names (`WITH properties(s) AS limit RETURN limit[k]`): only a real list passes.
      if (LIST_AFTER.has(cypher.slice(k, j + 1).toLowerCase()) && holdsList(cypher, i)) continue
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

/**
 * Why a query may not run whatever the RoE, or null: a `\uXXXX` escape ends a string literal for
 * Neo4j and not for the agent's tenant scoper (`'x\u0027 ...'` hid an unscoped UNION branch from
 * it), so `run_cypher` refuses one before the agent sees it, as the agent's scoper does too.
 */
export function cypherEscapeRefusal(cypher: string): string | null {
  return UNICODE_ESCAPE.test(cypher)
    ? 'A query may not contain a \\uXXXX escape: Neo4j decodes it before it reads the query. Write names and text plainly.'
    : null
}

/** Why a query may not run while secret values are withheld, or null. */
export function cypherSecretRefusal(cypher: string): string | null {
  const escaped = cypherEscapeRefusal(cypher)
  if (escaped) return escaped
  const code = codeView(cypher)
  if (COMMENT.test(code)) {
    return "This project's rules of engagement keep secret values from the AI, so a query may not contain a " +
      'comment (// or /* */). Send the query without comments.'
  }
  if (NAMED.test(cypher)) {
    return "This project's rules of engagement keep secret values from the AI, so a query may not read " +
      `${[...SECRET_VALUE_KEYS].join(', ')}. Ask for the secret's type, severity, source or where it was found instead.`
  }
  if (computedKeyAt(code) >= 0) {
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
