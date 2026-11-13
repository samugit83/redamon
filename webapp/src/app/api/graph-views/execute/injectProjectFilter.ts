/**
 * The saved-view filter: inject a project_id tenant filter into every node pattern of a caller's
 * Cypher, and refuse any query it cannot read with certainty.
 *
 * It reads by ALLOWLIST. A denylist of shapes kept missing the shapes Neo4j 5.26 reads and the
 * filter did not (a backticked name with a space, a Unicode letter, the `IS` label form, a `$`
 * inside a name, a control character Neo4j counts as whitespace or as a name character, a
 * quantifier written `{,n}` or with a Unicode dash): each ran with no tenant filter, a read of every
 * project's graph. Now a query runs only when every character, every call and every node pattern is
 * one the filter positively knows; anything else answers 400:
 *   - characters: printable ASCII, tab, CR and LF outside string literals and quoted names; no
 *     control character anywhere; `$` only as `$projectId`, the one parameter the route binds;
 *   - calls: the built-in pure functions only (FUNCTION_ALLOWLIST), never a procedure or a plugin;
 *   - node patterns: an optional plain variable, an optional `:` label expression of plain names, an
 *     optional property map of plain keys, an optional inline WHERE. Each one is scoped and hides
 *     muted findings; a global reference node only through a scoped node of the same path.
 *
 * The query that runs is the filter's own view of it (comments removed, quoted plain names
 * unwrapped, literals restored as typed), so Neo4j never parses a character the checks did not read.
 */
import { RAW_DATA_GRAPH_PROPS, STEP_CONTENT_BY_LABEL } from '@/lib/authz/stepContent'

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
// A quoted name that reads the same unquoted. Anything else (a space, a colon,
// a dot) stays quoted behind a placeholder, which no node pattern accepts.
const PLAIN_NAME = /^[A-Za-z_]\w*$/

// Neo4j reads U+001C-U+001F as whitespace and the other C0/C1 controls as name characters; JS's
// `\s` and `\w` do neither, so one of them inside code hid a node pattern or a call name. Refused
// everywhere, string literals included: no view needs one. Tab, LF and CR are ordinary whitespace.
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029]/
// What code (outside literals, quoted names and comments) may hold. Neo4j also reads Unicode
// letters, dashes, arrows and spaces, which these checks never see: refused.
const CODE_CHAR = /[A-Za-z0-9_ \t\r\n()[\]{}<>=!\-+*/%^.,:;|&$~]/
// Neo4j reads `$` inside a name (`n$` is a variable), so a `$` is read only as the bound parameter.
const PARAM_RE = /\$projectId(?![\w$])/y

interface ReadQuery {
  code: string
  literals: string[]
}

function readQuery(cypher: string): ReadQuery | { problem: string } {
  if (CONTROL_CHARS.test(cypher)) return { problem: 'a control character' }
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
      if (c > '~') return { problem: 'a non-ASCII character outside a string literal' }
      if (!CODE_CHAR.test(c)) return { problem: `a character views do not use: '${c}'` }
      code += c
      i += 1
    }
  }
  for (let k = code.indexOf('$'); k !== -1; k = code.indexOf('$', k + 1)) {
    PARAM_RE.lastIndex = k
    if (/[\w$]/.test(code[k - 1] ?? '') || !PARAM_RE.test(code)) return { problem: 'a parameter other than $projectId' }
  }
  const semicolon = code.indexOf(';')
  if (semicolon !== -1 && code.slice(semicolon + 1).trim() !== '') return { problem: 'more than one statement (;)' }
  return { code, literals }
}

function restore(code: string, literals: string[]): string {
  return code.replace(MARK_RE, (_m, literal?: string, quoted?: string) => literals[Number(literal ?? quoted)])
}

/** The code with every literal shown as `0` and every quoted name as `x`: no placeholder looks like syntax. */
function neutralView(read: ReadQuery): string {
  return read.code.replace(MARK_RE, (_m, literal?: string) => (literal !== undefined ? '0' : 'x'))
}

// Words after which `(` opens a pattern or an expression, never a call's
// arguments: `MATCH(n)` is a node pattern although no space separates them, and
// so is `ANY(n)` / `SHORTEST(...)` of a path selector. `any(x IN l WHERE ...)`
// stays harmless here: its interior does not start like a node pattern. A word
// missing here makes its `(` a call, which FUNCTION_ALLOWLIST then refuses.
const NOT_A_CALL = new Set([
  'MATCH', 'OPTIONAL', 'MERGE', 'CREATE', 'WHERE', 'AND', 'OR', 'XOR', 'NOT', 'RETURN', 'WITH',
  'UNWIND', 'IN', 'AS', 'DISTINCT', 'BY', 'SKIP', 'LIMIT', 'OFFSET', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'IS', 'UNION', 'CALL', 'YIELD', 'EXISTS', 'DELETE', 'DETACH', 'SET', 'REMOVE', 'FOREACH', 'ON',
  'ANY', 'ALL', 'SHORTEST', 'PATH', 'PATHS', 'GROUP', 'GROUPS', 'ELEMENTS', 'RELATIONSHIPS',
  'NEXT', 'FILTER', 'LET', 'USE', 'CONTAINS', 'STARTS', 'ENDS',
])

interface CallBefore {
  kind: 'none' | 'keyword' | 'call' | 'quoted'
  /** The name, or for `quoted` the placeholder of the quoted name. */
  name: string
  spaced: boolean
}

/**
 * What stands before the `(` at `open`: nothing (a pattern or a group), a keyword, a quoted name, or
 * a call's name (dotted, `apoc . cypher . run` read as one). One reading for the scanner and the
 * allowlist: a `(` the scanner skips as a call's arguments is a call the allowlist checks.
 */
function callBefore(code: string, open: number): CallBefore {
  let j = open
  while (j > 0 && /\s/.test(code[j - 1])) j--
  const spaced = j !== open
  if (code[j - 1] === QUOTED_MARK) {
    return { kind: 'quoted', name: code.slice(code.lastIndexOf(QUOTED_MARK, j - 2), j), spaced }
  }
  let start = j
  while (start > 0) {
    if (/\w/.test(code[start - 1])) { start--; continue }
    let k = start
    while (k > 0 && /\s/.test(code[k - 1])) k--
    if (code[k - 1] !== '.') break
    k--
    while (k > 0 && /\s/.test(code[k - 1])) k--
    if (!/\w/.test(code[k - 1] ?? '')) break
    start = k
  }
  const name = code.slice(start, j).replace(/\s+/g, '')
  if (!name || /^\d+$/.test(name)) return { kind: 'none', name, spaced }
  if (!name.includes('.') && NOT_A_CALL.has(name.toUpperCase())) return { kind: 'keyword', name, spaced }
  return { kind: 'call', name, spaced }
}

/** True when the `(` at `open` opens a call's arguments: a name written right against the paren. */
function opensCall(code: string, open: number): boolean {
  const before = callBefore(code, open)
  return before.kind === 'call' && !before.spaced
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

const FILTER_PROP = 'project_id: $projectId'

// A finding an operator suppressed as noise keeps its own label and gains this
// one. A saved view renders into the same graph screen as the live loader, so it
// is an enforcement site in its own right: without the exclusion below, a view
// would show findings the operator has already told the system to hide.
const MUTED_LABEL = 'Muted'
const MUTED_TERM = `&!${MUTED_LABEL}`

/** The top-level `|` terms of a normalised label expression. */
function unionTerms(labels: string): string[] {
  const terms: string[] = []
  let depth = 0
  let start = 0
  for (let i = 0; i < labels.length; i++) {
    if (labels[i] === '(') depth++
    else if (labels[i] === ')') depth--
    else if (labels[i] === '|' && depth === 0) {
      terms.push(labels.slice(start, i))
      start = i + 1
    }
  }
  terms.push(labels.slice(start))
  return terms
}

/**
 * The label expression that ALSO excludes `:Muted`. A union is distributed (`A&!Muted|B&!Muted`)
 * because `&` binds tighter than `|`: `A|B&!Muted` would return a muted A. Mirrors
 * `_labels_excluding_muted` in graph_db/tenant_filter.py.
 */
function withMutedExcluded(labels: string): string {
  if (!labels) return `!${MUTED_LABEL}`
  return unionTerms(labels).map(term => term + MUTED_TERM).join('|')
}

/** True for this filter's own output, so injecting twice changes nothing. */
function excludesMuted(labels: string): boolean {
  return labels === `!${MUTED_LABEL}` || (labels !== '' && unionTerms(labels).every(t => t.endsWith(MUTED_TERM)))
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

// ---- node patterns ----------------------------------------------------------

/** A text edit of the code, in code offsets. */
interface Edit {
  start: number
  end: number
  text: string
}

interface NodePattern {
  open: number
  close: number
  /** The interior as typed (literals restored), for the refusal message. */
  shown: string
  labels: string
  global: boolean
  tenant: 'none' | 'exact' | 'other'
  edits: Edit[]
}

type Reading =
  | { kind: 'expression' }
  | { kind: 'node'; node: NodePattern; labelSpan: [number, number] | null }
  | { kind: 'refused' }

const WORD_AT = /[A-Za-z_]\w*/y

function wordAt(s: string, i: number): string {
  WORD_AT.lastIndex = i
  const m = WORD_AT.exec(s)
  return m ? m[0] : ''
}

function skipWs(s: string, i: number): number {
  while (i < s.length && /\s/.test(s[i])) i++
  return i
}

function isWord(s: string, i: number, word: string): boolean {
  return wordAt(s, i).toUpperCase() === word
}

/** Where a node pattern goes on after its variable: `)`, `:`, `{`, `$`, `WHERE` or `IS` (Neo4j 5.26). */
function continuesNode(s: string, i: number): boolean {
  if (i >= s.length) return true
  if (s[i] === ':') return s[i + 1] !== ':' // `x :: INTEGER` is a type predicate
  return s[i] === '{' || s[i] === '$' || isWord(s, i, 'WHERE') || isWord(s, i, 'IS')
}

/** The index of the bracket closing the one at `open` (any of `([{`), or -1. */
function matching(s: string, open: number): number {
  let depth = 0
  for (let i = open; i < s.length; i++) {
    if ('([{'.includes(s[i])) depth++
    else if (')]}'.includes(s[i]) && --depth === 0) return i
  }
  return -1
}

/** True when the `{` at `open` starts a subquery body (`EXISTS { MATCH ... }`), not a property map. */
function opensSubquery(s: string, open: number): boolean {
  const i = skipWs(s, open + 1)
  if (s[i] === '(') return true
  const w = wordAt(s, i)
  return w !== '' && s[skipWs(s, i + w.length)] !== ':'
}

interface LabelExpression {
  end: number
  normalised: string
  names: string[]
  operators: boolean
}

/**
 * A `:` label expression of plain names, `&`, `|`, `!` and parentheses, starting after the colon
 * at `from`: where it ends and its normalised text (spaces dropped, the legacy `:A:B` conjunction
 * and `|:` respelled `&` and `|`: Neo4j 5 refuses `:A:B&!Muted`). Null for anything else: a quoted
 * name, the `%` wildcard, a dynamic `$(...)` label.
 */
function readLabels(s: string, from: number): LabelExpression | null {
  let i = from
  let out = ''
  let expectOperand = true
  let depth = 0
  let operators = false
  let lastEnd = from
  const names: string[] = []
  for (;;) {
    i = skipWs(s, i)
    const c = s[i]
    if (expectOperand) {
      const w = wordAt(s, i)
      if (w) {
        out += w
        names.push(w)
        i += w.length
        lastEnd = i
        expectOperand = false
      } else if (c === '!' || c === '(') {
        operators = true
        out += c
        if (c === '(') depth++
        i++
      } else if (c === ':' && out.endsWith('|')) {
        i++ // the legacy `|:` of `:A|:B`
      } else {
        return null
      }
      continue
    }
    if (c === '&' || c === '|') {
      operators = true
      out += c
      i++
      expectOperand = true
    } else if (c === ':') {
      out += '&'
      i++
      expectOperand = true
    } else if (c === ')' && depth > 0) {
      out += c
      depth--
      i++
      lastEnd = i
    } else if (depth === 0 && (i >= s.length || c === '{' || isWord(s, i, 'WHERE'))) {
      return { end: lastEnd, normalised: out, names, operators }
    } else {
      return null
    }
  }
}

/**
 * Read one `(...)` group: an expression, a node pattern (with the edits that scope it), or a
 * pattern this filter cannot read. `at` is the offset of the interior in the code.
 */
function readGroup(s: string, at: number, literals: string[]): Reading {
  const refused: Reading = { kind: 'refused' }
  let i = skipWs(s, 0)
  let varEnd = -1
  if (s[i] === QUOTED_MARK) {
    const end = s.indexOf(QUOTED_MARK, i + 1) + 1
    return continuesNode(s, skipWs(s, end)) ? refused : { kind: 'expression' }
  }
  const first = wordAt(s, i)
  if (first) {
    const after = skipWs(s, i + first.length)
    const upper = first.toUpperCase()
    if (upper === 'IS' && !continuesNode(s, after)) {
      // `(IS Domain)` is a node with the IS label form; `(x IS NULL)` never reaches here.
      return refused
    } else if (upper === 'WHERE' && !continuesNode(s, after)) {
      // `(WHERE true)`: an inline WHERE with no variable, read on from the WHERE
    } else if (['EXISTS', 'COUNT', 'COLLECT'].includes(upper) && s[after] === '{' && opensSubquery(s, after)) {
      return { kind: 'expression' }
    } else if (!continuesNode(s, after)) {
      return { kind: 'expression' }
    } else {
      varEnd = i + first.length
      i = after
      if (isWord(s, i, 'IS')) {
        const next = skipWs(s, i + 2)
        if (isWord(s, next, 'NULL') || isWord(s, next, 'NOT') || s.startsWith('::', next)) return { kind: 'expression' }
        return refused // the IS label form
      }
    }
  } else if (!continuesNode(s, i)) {
    return { kind: 'expression' }
  }

  let labels: LabelExpression | null = null
  let labelStart = -1
  if (s[i] === ':') {
    labelStart = i
    labels = readLabels(s, i + 1)
    if (!labels) return refused
    i = skipWs(s, labels.end)
  }
  let mapOpen = -1
  let mapClose = -1
  if (s[i] === '{') {
    mapOpen = i
    mapClose = matching(s, i)
    if (mapClose === -1) return refused
    i = skipWs(s, mapClose + 1)
  }
  if (s[i] === '$') return refused // a parameter map
  if (i < s.length && !isWord(s, i, 'WHERE')) return refused

  let tenant: NodePattern['tenant'] = 'none'
  if (mapOpen !== -1) {
    const entries = splitTopLevel(s.slice(mapOpen + 1, mapClose))
    if (entries === null) return refused
    const tenantEntries = entries.filter(e => e.key === 'project_id')
    if (tenantEntries.length === 1 && tenantEntries[0].value === '$projectId') tenant = 'exact'
    else if (tenantEntries.length > 0) tenant = 'other'
  }

  const normalised = labels?.normalised ?? ''
  const global = !!labels && !labels.operators && labels.names.every(n => GLOBAL_LABELS.has(n))
  const edits: Edit[] = []
  const needsTenant = tenant === 'none' && !global
  const needsMuted = (tenant === 'exact' || needsTenant) && !excludesMuted(normalised)
  if (needsTenant || needsMuted) {
    const headStart = at + (labelStart !== -1 ? labelStart : varEnd !== -1 ? varEnd : 0)
    const headEnd = at + (labels ? labels.end : varEnd !== -1 ? varEnd : 0)
    let text = `:${needsMuted ? withMutedExcluded(normalised) : normalised}`
    if (needsTenant && mapOpen === -1) text += ` {${FILTER_PROP}}`
    const nextChar = s[headEnd - at]
    if (nextChar !== undefined && !/[\s)]/.test(nextChar)) text += ' '
    edits.push({ start: headStart, end: headEnd, text })
  }
  if (needsTenant && mapOpen !== -1) {
    const firstEntry = skipWs(s, mapOpen + 1)
    edits.push(firstEntry === mapClose
      ? { start: at + mapOpen + 1, end: at + mapClose, text: FILTER_PROP }
      : { start: at + mapOpen + 1, end: at + firstEntry, text: `${FILTER_PROP}, ` })
  }
  return {
    kind: 'node',
    labelSpan: labels ? [at + labelStart, at + labels.end] : null,
    node: {
      open: at - 1,
      close: at + s.length,
      shown: restore(s, literals).trim(),
      labels: normalised,
      global,
      tenant,
      edits,
    },
  }
}

const MAP_ENTRY = /^\s*([A-Za-z_]\w*)\s*:(?!:)([\s\S]*)$/

/** The top-level `key: value` entries of a property map's interior, or null when one is not. */
function splitTopLevel(inner: string): Array<{ key: string; value: string }> | null {
  if (inner.trim() === '') return []
  const parts: string[] = []
  let depth = 0
  let start = 0
  for (let i = 0; i < inner.length; i++) {
    if ('([{'.includes(inner[i])) depth++
    else if (')]}'.includes(inner[i])) depth--
    else if (inner[i] === ',' && depth === 0) {
      parts.push(inner.slice(start, i))
      start = i + 1
    }
  }
  parts.push(inner.slice(start))
  const entries: Array<{ key: string; value: string }> = []
  for (const part of parts) {
    const m = MAP_ENTRY.exec(part)
    if (!m) return null
    entries.push({ key: m[1], value: m[2].trim() })
  }
  return entries
}

// Two node patterns in one path: a relationship and nothing else between them (`--`, `-->`,
// `<-[r:R]-`, with the spaces Neo4j allows inside an arrow). Quantified forms never get here.
const RELATIONSHIP_GAP = /^\s*<?\s*-\s*(?:\[[^[\]]*\]\s*)?-\s*>?\s*$/

interface Analysis {
  read: ReadQuery
  nodes: NodePattern[]
  /** Per node, its path: the nodes joined to it by relationships. */
  path: number[]
}

/** The query's node patterns, or the first interior it cannot read (or why it cannot read the query). */
function analyse(cypher: string): Analysis | { refused: string } {
  const read = readQuery(cypher)
  if ('problem' in read) return { refused: `(${read.problem})` }
  const groups = patternGroups(read.code)
  if (!groups) return { refused: '(unbalanced parentheses)' }
  const nodes: NodePattern[] = []
  const labelSpans: Array<[number, number]> = []
  for (const g of [...groups].sort((a, b) => a.open - b.open)) {
    // a parenthesised group inside a label expression, `(n:(A|B))`, is the parent's
    if (labelSpans.some(([from, to]) => g.open > from && g.open < to)) continue
    const reading = readGroup(g.interior, g.open + 1, read.literals)
    if (reading.kind === 'refused') return { refused: restore(g.interior, read.literals).trim() || '(anonymous)' }
    if (reading.kind === 'node') {
      nodes.push(reading.node)
      if (reading.labelSpan) labelSpans.push(reading.labelSpan)
    }
  }
  const path = nodes.map((_n, i) => i)
  const root = (i: number): number => (path[i] === i ? i : (path[i] = root(path[i])))
  nodes.forEach((node, i) => {
    const next = nodes.findIndex(other => other.open > node.close)
    if (next !== -1 && RELATIONSHIP_GAP.test(read.code.slice(node.close + 1, nodes[next].open))) path[root(next)] = root(i)
  })
  return { read, nodes, path: path.map((_p, i) => root(i)) }
}

export function injectProjectFilter(cypher: string): string {
  const analysis = analyse(cypher)
  if ('refused' in analysis) return cypher // findUnscopedNodePattern refuses it
  const edits = analysis.nodes.flatMap(n => n.edits).sort((a, b) => b.start - a.start)
  // Edits never overlap (a node's edits sit in its head and the start of its map; a nested pattern
  // starts after both); an overlap would mean a misread, so the query is left to the backstop.
  if (edits.some((e, k) => k > 0 && e.end > edits[k - 1].start)) return cypher
  let code = analysis.read.code
  for (const e of edits) code = code.slice(0, e.start) + e.text + code.slice(e.end)
  return restore(code, analysis.read.literals)
}

/**
 * Safety net. After injection, find any node pattern that does not carry exactly the tenant filter
 * and the mute exclusion, or that the filter cannot read. Returns the first offending interior (or
 * why the query cannot be read), or null when the query is fully tenant-scoped.
 *
 * A global reference pattern is exempt only when a scoped node of the SAME path anchors it: a
 * traversal from the caller's own data. A scoped node elsewhere in the query is no anchor:
 * `MATCH (a:Domain) WITH count(a) AS c MATCH (x:CVE) RETURN x` would still list every CVE in the
 * database, the union of what every tenant has scanned.
 */
export function findUnscopedNodePattern(cypher: string): string | null {
  const analysis = analyse(cypher)
  if ('refused' in analysis) return analysis.refused
  const { nodes, path } = analysis
  const scoped = (n: NodePattern) => n.tenant === 'exact' && excludesMuted(n.labels)
  for (const [i, node] of nodes.entries()) {
    if (scoped(node)) continue
    if (node.global && node.tenant === 'none'
      && nodes.some((other, j) => path[j] === path[i] && !other.global && scoped(other))) continue
    return node.shown || '(anonymous)'
  }
  return null
}

/**
 * True for a variable-length relationship or a quantified path or relationship. The nodes such a
 * pattern traverses have NO node pattern of their own, so the filter never reaches them: a `[*]`
 * hop from an exempt reference node (or between two of the caller's nodes) reaches other tenants'
 * nodes. Read with the whitespace Neo4j allows inside an arrow (`- -+`, `-[r]- ->+`) removed.
 */
export function hasVariableLengthPath(cypher: string): boolean {
  const read = readQuery(cypher)
  if ('problem' in read) return true
  const code = neutralView(read)
  const squeezed = code.replace(/\s+/g, '')
  if (/\[[^[\]]*\*[^[\]]*\]/.test(squeezed)) return true // `-[*1..3]-`, `-[:R*]-`
  // a relationship's brackets hold `*` beside a nested list: `-[r*1..2 {tags: [1]}]-`
  for (let i = squeezed.indexOf('-['); i !== -1; i = squeezed.indexOf('-[', i + 1)) {
    const close = matching(squeezed, i + 1)
    if (close === -1 || squeezed.slice(i + 2, close).includes('*')) return true
  }
  if (/[->][+*]\(/.test(squeezed)) return true // `-->+(b)`, `-[r]-*(b)`
  if (/[-)>]\{[\d,]/.test(squeezed)) return true // `-->{1,3}`, `-[r]-{,}`, `(...){,3}`
  // `((a)-->(b))+`: a parenthesised path followed by `+` or `*`
  for (const g of patternGroups(code) ?? []) {
    const after = code[skipWs(code, g.close + 1)]
    if (after !== '+' && after !== '*') continue
    const inner = g.interior.replace(/\s+/g, '')
    if (inner.startsWith('(') || /-\[|\]-|--|->|<-/.test(inner)) return true
  }
  return false
}

// Clauses a saved view may not run: the writes, the procedure call (a
// subquery `CALL {}` included: no view needs one), and the reads that leave
// the graph (LOAD CSV fetches a URL from inside the database, USE and SHOW
// reach the system database, SHOW TRANSACTIONS lists other sessions' queries).
// The session is read-only as well (route.ts), so Neo4j refuses a write this
// list misses; the list answers a clear 400 first. Not after `.` or `:`:
// `n.set` is a property, `:Load` a label.
const REFUSED_CLAUSE_RE = new RegExp(
  '(?<![.:\\w])(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|CALL|FOREACH|LOAD|USE|SHOW|ALTER|GRANT|DENY|REVOKE|TERMINATE)(?!\\w)',
  'gi',
)

/** The first clause a view may not run (upper case), or null; an unreadable query answers its first word. */
export function findWriteClause(cypher: string): string | null {
  const read = readQuery(cypher)
  const code = 'problem' in read ? cypher : read.code.replace(MARK_RE, ' ')
  REFUSED_CLAUSE_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = REFUSED_CLAUSE_RE.exec(code)) !== null) {
    const word = m[1].toUpperCase()
    // A SHOW command only ever opens a statement, so right after AS it is an alias (`AS show`).
    // Not for the others: `WITH 1 AS AS LOAD CSV ...` is an alias named AS, then a LOAD clause.
    if (word === 'SHOW' && /\bAS\s+$/i.test(code.slice(0, m.index))) continue
    return word
  }
  return null
}

// The functions a view may call: Neo4j 5.26's built-in functions that read nothing but their
// arguments. Everything else is refused, notably every plugin function (apoc's
// `apoc.cypher.runFirstColumn*` runs unscoped Cypher, `apoc.load.*` fetches URLs, and neither
// needs CALL), `db.*`, `graph.*` (other databases), `genai.*` (an outside service) and
// `shortestPath` (a variable-length pattern).
const FUNCTION_ALLOWLIST = new Set([
  'abs', 'acos', 'asin', 'atan', 'atan2', 'avg', 'btrim', 'ceil', 'char_length', 'character_length',
  'coalesce', 'collect', 'cos', 'cot', 'count', 'degrees', 'e', 'elementid', 'endnode', 'exp', 'floor',
  'haversin', 'head', 'id', 'isempty', 'isnan', 'keys', 'labels', 'last', 'left', 'length', 'log', 'log10',
  'lower', 'ltrim', 'max', 'min', 'nodes', 'none', 'normalize', 'nullif', 'percentilecont', 'percentiledisc',
  'pi', 'properties', 'radians', 'rand', 'randomuuid', 'range', 'reduce', 'relationships', 'replace',
  'reverse', 'right', 'round', 'rtrim', 'sign', 'sin', 'single', 'size', 'split', 'sqrt', 'startnode',
  'stdev', 'stdevp', 'substring', 'sum', 'tail', 'tan', 'timestamp', 'toboolean', 'tobooleanlist',
  'tobooleanornull', 'tofloat', 'tofloatlist', 'tofloatornull', 'tointeger', 'tointegerlist',
  'tointegerornull', 'tolower', 'tostring', 'tostringlist', 'tostringornull', 'toupper', 'trim', 'type',
  'upper', 'valuetype', 'date', 'datetime', 'localdatetime', 'localtime', 'time', 'duration', 'point',
  'vector.similarity.cosine', 'vector.similarity.euclidean',
])
// Namespaces whose every built-in function is pure (`date.truncate`, `duration.between`, `point.distance`).
const PURE_NAMESPACES = new Set(['date', 'datetime', 'localdatetime', 'localtime', 'time', 'duration', 'point'])

function allowedCall(name: string): boolean {
  const lower = name.toLowerCase()
  if (FUNCTION_ALLOWLIST.has(lower)) return true
  const dot = lower.indexOf('.')
  return dot !== -1 && PURE_NAMESPACES.has(lower.slice(0, dot))
}

/**
 * The first called name that is not an allowlisted built-in function (a procedure, a plugin or an
 * unknown function), or null. Read on the same view as the node scanner, so a call cannot hide
 * behind backticks (`` `apoc`.`cypher`.`run` ``), spaces (`apoc . cypher . run (`) or a comment.
 */
export function findDisallowedCall(cypher: string): string | null {
  const read = readQuery(cypher)
  if ('problem' in read) return read.problem
  const code = read.code
  for (let i = code.indexOf('('); i !== -1; i = code.indexOf('(', i + 1)) {
    const before = callBefore(code, i)
    if (before.kind === 'quoted') {
      const quoted = restore(before.name, read.literals)
      const name = quoted.slice(1, -1).replace(/``/g, '`')
      return /^[\w.]+$/.test(name) ? name : quoted
    }
    if (before.kind === 'call' && !allowedCall(before.name)) return before.name
  }
  return null
}

// ---- step content (SH-30) ---------------------------------------------------

const RAW_PROPS = new Set(
  [...Object.values(STEP_CONTENT_BY_LABEL).flat(), ...RAW_DATA_GRAPH_PROPS].map(p => p.toLowerCase()),
)
// Before `[`, these open a list literal (`IN [...]`, `RETURN [...]`), not a subscript.
const LIST_OPENERS = NOT_A_CALL
const NUMERIC_INDEX = /^\s*-?\s*\d+\s*$|^\s*(?:-?\s*\d+)?\s*\.\.\s*(?:-?\s*\d+)?\s*$/

/**
 * For a reader below Raw data & files (R*): the step-content property the query names, or why it
 * computes a property name, or null. graphReadView strips the content from what a view returns,
 * but a filter on it (`WHERE s.thought STARTS WITH 'a'`) would still read it bit by bit from which
 * rows come back. So any word naming a raw property is refused, wherever it stands (a property, a
 * map key, a projection), and so is a subscript that is not a number or a slice (`s['thought']`,
 * `s[k]`): a computed key reaches the same property.
 */
export function findStepContentReference(cypher: string): string | null {
  const read = readQuery(cypher)
  if ('problem' in read) return null // refused as unreadable
  // Literal placeholders hold no word and are no number, so `s['thought']` is a computed key.
  const code = read.code
  for (const m of code.matchAll(/[A-Za-z_]\w*/g)) {
    if (/\w/.test(code[m.index - 1] ?? '')) continue
    if (RAW_PROPS.has(m[0].toLowerCase())) return m[0].toLowerCase()
  }
  for (let i = code.indexOf('['); i !== -1; i = code.indexOf('[', i + 1)) {
    let j = i
    while (j > 0 && /\s/.test(code[j - 1])) j--
    const prev = code[j - 1] ?? ''
    if (!/[\w)\]}'\u0002]/.test(prev)) continue
    if (/\w/.test(prev)) {
      let start = j
      while (start > 0 && /\w/.test(code[start - 1])) start--
      if (LIST_OPENERS.has(code.slice(start, j).toUpperCase())) continue
    }
    const close = matching(code, i)
    if (close === -1 || !NUMERIC_INDEX.test(code.slice(i + 1, close))) return 'a computed property or index'
  }
  return null
}
