/**
 * Inject a project_id tenant filter into every node pattern of a Cypher query.
 *
 * The earlier version only rewrote `(var:Label ...)` patterns, so an
 * unlabeled or anonymous node pattern (`(n)`, `()`, `MATCH (n) RETURN n`)
 * slipped through with NO project_id predicate and could read across tenants.
 * This version scopes labeled, unlabeled, and anonymous node patterns alike,
 * skips the global reference labels, and never touches function-call parens.
 *
 * Extracted as a standalone function for testability.
 */

// ---- reading the query ------------------------------------------------------
//
// Every check below and the injection itself read the same view of the query:
// comments removed, string literals set aside behind placeholders, quoted names
// that are plain identifiers unwrapped. Set aside FIRST, in one left-to-right
// pass: stripping `//` before strings turned `'http://x'` into the start of a
// "comment" and hid the rest of its line (a DETACH DELETE, an apoc call) from
// every check; and a `(` inside a string or a comment hid a whole node pattern
// from the scanner, so it ran with no tenant filter. A literal comes back as
// typed in the query that runs; its placeholder holds no word, quote or paren.

const LITERAL_MARK = '\u0001'
const QUOTED_MARK = '\u0002'
const MARK_RE = /'\u0001(\d+)\u0001'|\u0002(\d+)\u0002/g
const MARK_CHARS = /[\u0001\u0002]/
// A quoted name that reads the same unquoted. Anything else (a space, a colon,
// a dot) stays quoted behind a placeholder, which no node pattern accepts.
const PLAIN_NAME = /^[A-Za-z_]\w*$/

interface ReadQuery {
  code: string
  literals: string[]
}

function readQuery(cypher: string): ReadQuery | { problem: string } {
  if (MARK_CHARS.test(cypher)) return { problem: 'a control character' }
  let code = ''
  const literals: string[] = []
  const setAside = (text: string, mark: (n: number) => string) => {
    literals.push(text)
    code += mark(literals.length - 1)
  }
  let i = 0
  while (i < cypher.length) {
    const c = cypher[i]
    const next = cypher[i + 1]
    if (c === '/' && next === '/') {
      const end = cypher.indexOf('\n', i)
      i = end === -1 ? cypher.length : end
      code += ' '
    } else if (c === '/' && next === '*') {
      const end = cypher.indexOf('*/', i + 2)
      if (end === -1) return { problem: 'an unterminated comment' }
      i = end + 2
      code += ' '
    } else if (c === "'" || c === '"') {
      let j = i + 1
      while (j < cypher.length && cypher[j] !== c) j += cypher[j] === '\\' ? 2 : 1
      if (j >= cypher.length) return { problem: 'an unterminated string' }
      setAside(cypher.slice(i, j + 1), n => `'${LITERAL_MARK}${n}${LITERAL_MARK}'`)
      i = j + 1
    } else if (c === '`') {
      let j = i + 1
      let name = ''
      for (; j < cypher.length; j++) {
        if (cypher[j] !== '`') { name += cypher[j]; continue }
        if (cypher[j + 1] !== '`') break
        name += '`' // a doubled backtick is one backtick of the name
        j++
      }
      if (j >= cypher.length) return { problem: 'an unterminated quoted name' }
      if (PLAIN_NAME.test(name)) code += name
      else setAside(cypher.slice(i, j + 1), n => `${QUOTED_MARK}${n}${QUOTED_MARK}`)
      i = j + 1
    } else {
      code += c
      i += 1
    }
  }
  return { code, literals }
}

function restore(code: string, literals: string[]): string {
  return code.replace(MARK_RE, (_m, literal?: string, quoted?: string) => literals[Number(literal ?? quoted)])
}

/** The read view with quoted names shown by their name, for the call check: `` `apoc.cypher.run`( `` is a call. */
function callView(read: ReadQuery): string {
  return read.code.replace(MARK_RE, (m, literal?: string, quoted?: string) =>
    quoted === undefined ? m : read.literals[Number(quoted)].slice(1, -1).replace(/``/g, '`'))
}

// Words after which `(` opens a pattern or an expression, never a call's
// arguments: `MATCH(n)` is a node pattern although no space separates them, and
// so is `ANY(n)` / `SHORTEST(...)` of a path selector. `any(x IN l WHERE ...)`
// stays harmless here: its interior does not start like a node pattern.
const NOT_A_CALL = new Set([
  'MATCH', 'OPTIONAL', 'MERGE', 'CREATE', 'WHERE', 'AND', 'OR', 'XOR', 'NOT', 'RETURN', 'WITH',
  'UNWIND', 'IN', 'AS', 'DISTINCT', 'BY', 'SKIP', 'LIMIT', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'IS', 'UNION', 'CALL', 'YIELD', 'EXISTS', 'DELETE', 'DETACH', 'SET', 'REMOVE', 'FOREACH', 'ON',
  'ANY', 'ALL', 'SHORTEST', 'PATH', 'PATHS', 'GROUP', 'GROUPS', 'ELEMENTS', 'RELATIONSHIPS',
  'NEXT', 'FILTER', 'LET', 'USE',
])

/**
 * True when the `(` at `open` opens a call's arguments: a name written right
 * against the paren (`count(n)`) that is not a keyword. A paren after
 * whitespace or an arrow opens a pattern or a group, as in the Python filter's
 * _is_function_call, so `count (n)` is scoped and then fails at Neo4j rather
 * than run unscoped.
 */
function opensCall(code: string, open: number): boolean {
  let start = open
  while (start > 0 && /\w/.test(code[start - 1])) start--
  if (start === open) return false
  const word = code.slice(start, open)
  return !/^\d+$/.test(word) && !NOT_A_CALL.has(word.toUpperCase())
}

interface Group {
  open: number
  close: number
  interior: string
}

/** Every `(...)` that is not a call's argument list, or null when the parentheses do not balance. */
function patternGroups(code: string): Group[] | null {
  const opens: number[] = []
  const groups: Group[] = []
  for (let i = 0; i < code.length; i++) {
    if (code[i] === '(') opens.push(i)
    else if (code[i] === ')') {
      const open = opens.pop()
      if (open === undefined) return null
      if (!opensCall(code, open)) groups.push({ open, close: i, interior: code.slice(open + 1, i) })
    }
  }
  return opens.length ? null : groups
}

// A group whose interior starts the way a node pattern does: an optional
// variable, then a label, a property map, an inline WHERE, or nothing.
// `(a.x > 1)` and `(x IN list)` are expressions; `(n {x: f(1)})`,
// `(n:(A|B))` and `(n:A WHERE ...)` are node patterns this filter cannot
// rewrite, so they are refused, never run unscoped.
const NODE_HEAD = /^\s*(?:[A-Za-z_]\w*)?\s*(?::|\{|WHERE\b|$)/i

function looksLikeNode(interior: string): boolean {
  return NODE_HEAD.test(interior)
}

/** Why the query cannot be read safely (an unterminated literal, unbalanced parentheses), or null. */
export function unreadableQuery(cypher: string): string | null {
  const read = readQuery(cypher)
  if ('problem' in read) return `The query has ${read.problem}.`
  if (patternGroups(read.code) === null) return 'The query has unbalanced parentheses.'
  return null
}

// Global node types that exist across all projects (no project_id property).
// These are enrichment/reference data from public databases (NVD, MITRE, CAPEC).
//
// Mirror of graph_db/tenant_filter.py GLOBAL_REFERENCE_LABELS, and it must stay
// in step: ExploitGvm is NOT here, though it once was. An ExploitGvm node is
// per-tenant data (gvm_mixin writes it with user_id + project_id, and triage
// can mute it), so exempting it left `MATCH (e:ExploitGvm) ...` completely
// unscoped - a cross-tenant read on this saved-view path.
const GLOBAL_LABELS = new Set(['CVE', 'MitreData', 'Capec'])

// A label string is exempt ONLY when it is a plain `:A` / `:A:B` conjunction and
// every label is global. A label EXPRESSION never qualifies: `(n:!CVE)` means
// "every node that is NOT a CVE" (i.e. all tenant data), `(n:A|CVE)` is a union,
// and `labelsFrom` would find 'CVE' in both and wrongly exempt them. This is the
// port of _is_global_reference_pattern in the Python filter.
const SIMPLE_LABELS_RE = /^(?::[A-Za-z_]\w*)+$/

function isSimpleGlobalReference(labelStr: string): boolean {
  const raw = labelStr.trim()
  if (!raw || !SIMPLE_LABELS_RE.test(raw)) return false
  const labels = raw.split(':').map(s => s.trim()).filter(Boolean)
  return labels.length > 0 && labels.every(l => GLOBAL_LABELS.has(l))
}

const FILTER_PROP = 'project_id: $projectId'

// A finding an operator suppressed as noise keeps its own label and gains this
// one. A saved view renders into the same graph screen as the live loader, so it
// is an enforcement site in its own right: without the exclusion below, a view
// would show findings the operator has already told the system to hide.
const MUTED_LABEL = 'Muted'

/**
 * Rewrite a label expression so it ALSO excludes `:Muted`.
 *
 * Mirrors `_labels_excluding_muted` in `graph_db/tenant_filter.py`, with one
 * deliberate difference: a union is distributed (`:A&!Muted|B&!Muted`) instead
 * of parenthesised (`:(A|B)&!Muted`). Both mean the same thing, because `&`
 * binds tighter than `|` -- but INTERIOR below cannot parse parentheses, and
 * `findUnscopedNodePattern` re-scans this function's own output. A form it could
 * not read would be reported as unscoped and the query refused.
 *
 * Legacy colon conjunction becomes `&` first: Neo4j 5 rejects `:A:B&!Muted`,
 * which mixes the two syntaxes in one pattern.
 */
function excludeMuted(labelStr: string): string {
  const raw = labelStr.trim()
  const body = raw.startsWith(':') ? raw.slice(1) : raw
  if (!body) return `:!${MUTED_LABEL}`
  const conjunction = body.replace(/:/g, '&')
  return ':' + conjunction.split('|').map(term => `${term}&!${MUTED_LABEL}`).join('|')
}

/**
 * True when the query mentions the reserved `Muted` label.
 *
 * The exclusion is applied automatically, so naming the label can only be an
 * attempt to inspect what was suppressed. Comments and string literals are
 * stripped first, so an ordinary text comparison is not mistaken for one.
 */
export function namesMutedLabel(cypher: string): boolean {
  const read = readQuery(cypher)
  const code = 'problem' in read ? cypher : read.code
  return new RegExp(`\\b${MUTED_LABEL}\\b`).test(code)
}

// Interior grammar of a node pattern: optional variable, optional :Label(s)
// (including label-expression separators), optional {props}. A parenthesized
// expression such as `(a.x > 1)` fails this grammar and is left untouched.
const INTERIOR = /^(\w+)?\s*((?::[\w|&!]+)*)\s*(\{[\s\S]*\})?$/

function labelsFrom(labelStr: string): string[] {
  return labelStr.split(/[:|&!]+/).map(s => s.trim()).filter(Boolean)
}

interface ParsedNode {
  varName: string
  labelStr: string
  labels: string[]
  props?: string // includes the surrounding braces
}

/** Parse a node-pattern interior, or return null if it is not one. */
function parseInterior(interior: string): ParsedNode | null {
  const m = INTERIOR.exec(interior.trim())
  if (!m) return null
  const labelStr = m[2] || ''
  return {
    varName: m[1] || '',
    labelStr,
    labels: labelsFrom(labelStr),
    props: m[3],
  }
}

// The tenant filter, and nothing that could widen it: a property map naming
// project_id in any other way (`{project_id: 'another-project'}`) is not
// "already scoped", it is refused.
const TENANT_PROP_RE = /\bproject_id\s*:\s*\$projectId\b/

function hasTenantProps(props: string | undefined): boolean {
  if (!props) return false
  return TENANT_PROP_RE.test(props) && (props.match(/\bproject_id\b/g) ?? []).length === 1
}

function namesProjectId(props: string | undefined): boolean {
  return !!props && /\bproject_id\b/.test(props)
}

/** The rewritten `(...)` of a node pattern, or null to leave the group as written. */
function scopedNode(interior: string): string | null {
  if (/[()]/.test(interior)) return null // refused by findUnscopedNodePattern when it is a node
  const node = parseInterior(interior)
  if (!node) return null
  if (isSimpleGlobalReference(node.labelStr)) return null
  if (namesProjectId(node.props)) return null

  const head = `${node.varName}${excludeMuted(node.labelStr)}`
  if (node.props != null) {
    const inner = node.props.slice(1, -1).trim()
    const body = inner ? `${FILTER_PROP}, ${inner}` : FILTER_PROP
    return `(${head} {${body}})`
  }
  return `(${head} {${FILTER_PROP}})`
}

export function injectProjectFilter(cypher: string): string {
  const read = readQuery(cypher)
  if ('problem' in read) return cypher // findUnscopedNodePattern refuses it
  const groups = patternGroups(read.code)
  if (!groups) return cypher
  // A group scopedNode rewrites holds no paren, so no two edits overlap; applied
  // from the end, each leaves the earlier offsets valid.
  let code = read.code
  for (const g of [...groups].sort((a, b) => b.open - a.open)) {
    const scoped = scopedNode(g.interior)
    if (scoped !== null) code = code.slice(0, g.open) + scoped + code.slice(g.close + 1)
  }
  return restore(code, read.literals)
}

/**
 * Safety net. After injection, scan for any node pattern that still carries a
 * variable or a non-global label but lacks the project_id predicate, or that
 * the filter cannot read. Returns the first offending interior (or why the
 * query cannot be read), or null when the query is fully tenant-scoped.
 *
 * A global reference pattern is exempt only when the query is ITSELF anchored to
 * the caller's data (at least one scoped pattern). Without that, `MATCH (c:CVE)
 * RETURN c` would dump every CVE in the database - no tenant data, but still the
 * union of what every tenant has scanned. Mirrors find_unscoped_node_pattern in
 * the Python filter.
 */
export function findUnscopedNodePattern(cypher: string): string | null {
  const read = readQuery(cypher)
  if ('problem' in read) return `(${read.problem})`
  const groups = patternGroups(read.code)
  if (!groups) return '(unbalanced parentheses)'
  const nodes: Array<ParsedNode & { interior: string }> = []
  for (const g of groups) {
    if (!looksLikeNode(g.interior)) continue
    const interior = restore(g.interior, read.literals).trim()
    const node = /[()]/.test(g.interior) ? null : parseInterior(g.interior)
    if (!node) return interior || '(anonymous)'
    nodes.push({ ...node, interior })
  }
  const scopedOf = (n: ParsedNode) => hasTenantProps(n.props)
  const hasAnchor = nodes.some(scopedOf)
  for (const node of nodes) {
    if (scopedOf(node)) continue
    if (namesProjectId(node.props)) return node.interior
    if (hasAnchor && isSimpleGlobalReference(node.labelStr)) continue // reference data, anchored
    if (node.varName || node.labels.length > 0) {
      return node.interior || '(anonymous)'
    }
  }
  return null
}

// A relationship carrying `*` (variable length), or a quantifier on a path /
// relationship group (`{n,m}`), or a quantified relationship (`-[:R]->+`,
// `-->*`). The nodes such a pattern traverses have NO node pattern of their
// own, so injectProjectFilter never reaches them and findUnscopedNodePattern
// never sees them: a `[*]` hop from an exempt reference node (or between two of
// the caller's nodes) reaches other tenants' nodes. Read on the read view, with
// literals blanked.
const QUANTIFIED_REL_RE = /(?:\]-+>?|-->?|<--)\s*[+*]/

export function hasVariableLengthPath(cypher: string): boolean {
  const read = readQuery(cypher)
  if ('problem' in read) return true
  const code = read.code.replace(MARK_RE, ' ')
  return /\[[^[\]]*\*[^[\]]*\]/.test(code)
    || /[)\]]\s*(?:<?-+>?)?\s*\{\s*\d/.test(code)
    || QUANTIFIED_REL_RE.test(code)
}

// Clauses a saved view may not run: the writes, the procedure call (a
// subquery `CALL {}` included: no view needs one), and the reads that leave
// the graph (LOAD CSV fetches a URL from inside the database, USE and SHOW
// reach the system database). The session is read-only as well (route.ts), so
// Neo4j refuses a write this list misses; the list answers a clear 400 first.
// Not after a `.`: `n.set` is a property.
const REFUSED_CLAUSE_RE = new RegExp(
  '(?<![.\\w])(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|CALL|FOREACH|LOAD|USE|SHOW|ALTER|GRANT|DENY|REVOKE|TERMINATE)(?!\\w)',
  'i',
)

/** The first clause a view may not run (upper case), or null; an unreadable query answers its first word. */
export function findWriteClause(cypher: string): string | null {
  const read = readQuery(cypher)
  const code = 'problem' in read ? cypher : read.code.replace(MARK_RE, ' ')
  const m = REFUSED_CLAUSE_RE.exec(code)
  return m ? m[1].toUpperCase() : null
}

// Built-in FUNCTION namespaces a read may legitimately call. Everything else
// namespaced-and-called is refused - notably apoc, whose function forms
// (`apoc.cypher.runFirstColumn*`, `apoc.load.*`) run unscoped Cypher or fetch
// URLs and need no CALL, so the route's CALL block never saw them.
const SAFE_CALL_NAMESPACES = new Set([
  'point', 'duration', 'date', 'time', 'datetime', 'localtime', 'localdatetime', 'vector',
])
const NAMESPACED_CALL_RE = /([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(/g

/**
 * The first namespaced procedure OR function call that is not allowlisted, or
 * null. Runs on the read view (comments removed, literals blanked, quoted
 * names shown by their name, whitespace around `.` removed) so
 * `` `apoc`.`cypher`.`run` `` and `apoc . cypher . run` cannot hide the name.
 * Mirrors find_disallowed_call in the Python filter.
 */
export function findDisallowedCall(cypher: string): string | null {
  const read = readQuery(cypher)
  if ('problem' in read) return read.problem
  const normalised = callView(read)
    .replace(MARK_RE, ' ')
    .replace(/\s*\.\s*/g, '.')
  let m: RegExpExecArray | null
  NAMESPACED_CALL_RE.lastIndex = 0
  while ((m = NAMESPACED_CALL_RE.exec(normalised)) !== null) {
    const name = m[1]
    const root = name.split('.', 1)[0].toLowerCase()
    if (SAFE_CALL_NAMESPACES.has(root)) continue
    return name
  }
  return null
}
