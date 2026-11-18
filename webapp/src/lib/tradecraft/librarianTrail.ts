/**
 * The chat's trail line for a `tradecraft_ask` result (Q9.5 "In the chat", T7.5): "Librarian:
 * searched 3 queries, inspected 4 pages, picked 2", read from the result's header once the tool
 * returns. The format is the agent's (`agentic/tradecraft/library/types.py`, `LIBRARIAN_HEADER`
 * and `find_librarian_header`): the header is the first line inside the untrusted envelope, never
 * a line further down, which an excerpt could imitate. Everything else is display only.
 */
export interface LibrarianTrail {
  verdict: 'FOUND' | 'PARTIAL' | 'NOT FOUND'
  confidence: 'high' | 'medium' | 'low'
  calls: number
  pages: number
  seconds: number
  queries: number
  picked: number
}

const OPENING = /^<<<UNTRUSTED_TRADECRAFT_RESULT id=[0-9a-f]+>>>$/
const HEADER = /^librarian: (FOUND|PARTIAL|NOT FOUND) \((high|medium|low)\) · (\d+) model calls · (\d+) pages inspected · (\d+(?:\.\d+)?) s$/
const PICK = /^[1-3]\. [a-z0-9][a-z0-9-]{0,199}:[1-9][0-9]{0,9}(?:\s|$)/
/** The librarian returns at most three pages (Q11 "Fixed in code"). */
const PAGES_RETURNED = 3

export function parseLibrarianTrail(result: string): LibrarianTrail | null {
  const lines = result.replace(/^\s+/, '').split('\n').map(l => l.replace(/\r$/, ''))
  if (lines.length < 2 || !OPENING.test(lines[0].trim())) return null
  const m = HEADER.exec(lines[1].trim())
  if (!m) return null
  const searched = lines[2]?.startsWith('searched: ') ? (lines[2].match(/"[^"]*"/g) ?? []).length : 0
  let picked = 0
  for (const line of lines.slice(2)) {
    if (line.startsWith('also relevant: ') || line.startsWith('read more: ') || line.startsWith('<<<END_UNTRUSTED')) break
    if (PICK.test(line)) picked++
  }
  return {
    verdict: m[1] as LibrarianTrail['verdict'],
    confidence: m[2] as LibrarianTrail['confidence'],
    calls: Number(m[3]),
    pages: Number(m[4]),
    seconds: Number(m[5]),
    queries: searched,
    picked: Math.min(picked, PAGES_RETURNED),
  }
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

export function trailText(t: LibrarianTrail): string {
  return `Librarian: searched ${plural(t.queries, 'query', 'queries')}, inspected ${plural(t.pages, 'page', 'pages')}, picked ${t.picked}`
}

export function trailDetail(t: LibrarianTrail): string {
  return `${t.verdict} (${t.confidence}) · ${plural(t.calls, 'model call', 'model calls')} · ${t.seconds.toFixed(1)} s`
}
