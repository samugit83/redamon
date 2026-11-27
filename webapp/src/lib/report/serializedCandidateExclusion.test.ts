import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'

/**
 * §12-D: an UNCONFIRMED serialized_scan candidate must not reach the two
 * deliverable surfaces (the client report and the Insights analytics), while a
 * confirmed one (CONFIRMS edge) must. Full Cypher behaviour needs a graph; here
 * we guard that every general :Vulnerability query on those surfaces carries the
 * pending exclusion, and that the report labels the source.
 */

const REPORT = readFileSync(join(__dirname, 'reportData.ts'), 'utf8')
const ANALYTICS = readFileSync(
  join(__dirname, '../../app/api/analytics/vulnerabilities/route.ts'), 'utf8')

function vulnQueries(src: string): string[] {
  // GENERAL :Vulnerability queries: MATCH (v:Vulnerability {project_id: $pid})
  // (or the {${tm}} tenant form) with no source scoping. A source-scoped query (inline {source:'x'} or a
  // `WHERE v.source IN/=` clause) can never surface a serialized_scan candidate,
  // so §12-D's pending exclusion is only required on the general ones.
  return [...src.matchAll(/`([^`]*\bMATCH \(v:Vulnerability \{(?:\$\{[^}]+\}|project_id: \$p(?:id|rojectId))\}\)[^`]*)`/g)]
    .map(m => m[1])
    .filter(q => !/v\.source\s+(IN|=)/.test(q))
}

describe('serialized_scan pending exclusion on deliverable surfaces', () => {
  test('every general :Vulnerability query in the report excludes pending candidates', () => {
    const qs = vulnQueries(REPORT)
    expect(qs.length).toBeGreaterThan(0)
    const offenders = qs.filter(q => !q.includes('agentCandidateConfirmedOrNA'))
    expect(offenders, `report vuln queries missing the pending exclusion`).toEqual([])
  })

  test('the report labels serialized_scan as Insecure Deserialization', () => {
    expect(REPORT).toContain("WHEN v.source = 'serialized_scan' THEN 'Insecure Deserialization'")
  })

  test('every general :Vulnerability query in analytics excludes pending candidates', () => {
    const qs = vulnQueries(ANALYTICS)
    expect(qs.length).toBeGreaterThan(0)
    const offenders = qs.filter(q => !q.includes('agentCandidateConfirmedOrNA'))
    expect(offenders, `analytics vuln queries missing the pending exclusion`).toEqual([])
  })
})
