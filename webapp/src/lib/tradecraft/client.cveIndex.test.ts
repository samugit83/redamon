/**
 * What a CVE archive's card says about its index (NQ-9), read from the archive's last report only,
 * and the agent's words that report carries: a code or a stop reason the agent rewords alone would
 * put the hint on every indexed archive, or take it off every archive that needs a token.
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { IngestionReport } from './agentContract'
import { CVE_INDEX_NEEDS_TOKEN, CVE_INDEX_STOP_PREFIX, cveIndexHint } from './client'

const BUILDERS_PY = join(__dirname, '../../../../agentic/tradecraft/ingest/builders.py')

const archive = (report: IngestionReport | null, over: { forcedType?: string; resourceType?: string; githubTokenOverride?: '' | 'set' } = {}) => ({
  resourceType: 'cve-poc-db', forcedType: '', githubTokenOverride: '' as const, report, ...over,
})

describe('cveIndexHint', () => {
  test('a report from before the index: refresh', () => {
    expect(cveIndexHint(archive(IngestionReport.parse({ kept: 0 })))).toBe('refresh')
    expect(cveIndexHint(archive(IngestionReport.parse({ stopReason: 'sitemap' })))).toBe('refresh')
  })

  test('no GitHub token at the last ingestion: token, or refresh once the resource has its own', () => {
    const report = IngestionReport.parse({ stopReason: 'cve index: add a GitHub token to index this archive', errors: [{ code: 'cve_index_needs_token', count: 1 }] })
    expect(cveIndexHint(archive(report))).toBe('token')
    expect(cveIndexHint(archive(report, { githubTokenOverride: 'set' }))).toBe('refresh')
  })

  test('the index ran: nothing to say', () => {
    expect(cveIndexHint(archive(IngestionReport.parse({ kept: 20000, stopReason: 'cve index: largest 20000 of 183523 files' })))).toBeNull()
    expect(cveIndexHint(archive(IngestionReport.parse({ stopReason: 'cve index: 0 of 0 files' })))).toBeNull()
  })

  test('another type, or no report: nothing to say', () => {
    const old = IngestionReport.parse({ kept: 0 })
    expect(cveIndexHint(archive(old, { resourceType: 'github-repo' }))).toBeNull()
    expect(cveIndexHint(archive(old, { forcedType: 'github-repo' }))).toBeNull()
    expect(cveIndexHint(archive(old, { resourceType: 'github-repo', forcedType: 'cve-poc-db' }))).toBe('refresh')
    expect(cveIndexHint(archive(null))).toBeNull()
  })

  test('a partial report (a test fixture, an older row) reads as one with no index', () => {
    expect(cveIndexHint(archive({ kept: 0 } as never))).toBe('refresh')
  })
})

/**
 * The card reads "no `cve index:` stop reason and no code" as a report from before the index, so every
 * stop reason a CVE archive's map can carry must start with the prefix: each one `build_cve` or
 * `index_cve` writes, as `result.report_stop = …` or as `MapResult(…, report_stop=…)`. Each is read to
 * its text from a module constant, a literal, an f-string led by a constant, or the joined `words`
 * list; a form this test cannot read comes out empty and fails, never passes. An exit that writes no
 * stop reason at all cannot be seen in the source: FIX-CVEIDX's Python test holds that every exit of
 * `index_cve` writes one. A missing builders.py fails here, it is never skipped.
 */
describe('the agent writes the words the card reads', () => {
  const found = existsSync(BUILDERS_PY)
  const src = found ? readFileSync(BUILDERS_PY, 'utf8') : ''

  const constantExpr = (name: string): string => {
    const m = new RegExp(`^${name}\\s*=\\s*(.+)$`, 'm').exec(src)
    expect(m, `${name} not found in ingest/builders.py`).toBeTruthy()
    return m![1].trim()
  }
  const body = (fn: string): string => {
    const m = new RegExp(`\\n(?:async )?def ${fn}\\([\\s\\S]*?\\n(?=\\S)`).exec(src)
    expect(m, `${fn} not found in ingest/builders.py`).toBeTruthy()
    return m![0]
  }
  /** A Python expression up to its end on the line: a top-level comma or closing parenthesis, or a comment. */
  const expression = (rest: string): string => {
    let depth = 0
    let quote = ''
    for (let i = 0; i < rest.length; i++) {
      const c = rest[i]
      if (quote) { if (c === '\\') i++; else if (c === quote) quote = ''; continue }
      if (c === '"' || c === "'") quote = c
      else if ('([{'.includes(c)) depth++
      else if (')]}'.includes(c)) { if (depth === 0) return rest.slice(0, i).trim(); depth-- }
      else if ((c === ',' && depth === 0) || c === '#') return rest.slice(0, i).trim()
    }
    return rest.trim()
  }
  const text = (expr: string, scope: string, depth = 0): string => {
    if (depth > 4) return ''
    const joined = /^""\.join\((\w+)\)/.exec(expr)
    if (joined) return text(expression(new RegExp(`\\n\\s*${joined[1]} = \\[(.+)`).exec(scope)?.[1] ?? ''), scope, depth + 1)
    if (/^[A-Z][A-Z0-9_]*$/.test(expr)) return text(expression(constantExpr(expr)), scope, depth + 1)
    const led = /^f"\{([A-Z][A-Z0-9_]*)\}([^"{]*)/.exec(expr)
    if (led) return text(expression(constantExpr(led[1])), scope, depth + 1) + led[2]
    return /^f?"([^"{]*)/.exec(expr)?.[1] ?? ''
  }

  test('ingest/builders.py is where the card reads its words from', () => {
    expect(found, `${BUILDERS_PY} is missing: the card's words have no source to be held to`).toBe(true)
  })

  test('the no-token code', () => {
    expect(CVE_INDEX_NEEDS_TOKEN).toBe(text('CVE_NEEDS_TOKEN', ''))
  })

  test('every stop reason build_cve and index_cve write starts with the prefix', () => {
    const stops = ['build_cve', 'index_cve'].flatMap(fn => {
      const scope = body(fn)
      return [...scope.matchAll(/\breport_stop\s*=(?!=)([^\n]*)/g)].map(m => ({ fn, expr: expression(m[1]), scope }))
    })
    // The no-token reason and the index's own count are two of them, whatever else is added.
    expect(stops.filter(s => s.fn === 'index_cve').map(s => s.expr))
      .toEqual(expect.arrayContaining(['NEEDS_TOKEN_STOP', '"".join(words)[:64]']))
    for (const { fn, expr, scope } of stops) {
      expect(text(expr, scope), `${fn}'s stop reason ${expr}`).toMatch(new RegExp(`^${CVE_INDEX_STOP_PREFIX}`))
    }
  })
})
