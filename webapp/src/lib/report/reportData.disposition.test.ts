/** @vitest-environment node */
/**
 * Plan 10.2: the report leads with disposition, and its severity breakdown is
 * the scanners' claim about reportable and candidate findings only.
 *
 * The breakdown query is proven here against its Cypher; the CASE itself is
 * proven on a real graph in lib/triage/disposition.integration.test.ts.
 *
 * Run: npx vitest run src/lib/report/reportData.disposition.test.ts
 */
import { describe, test, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { queryVulnerabilities } from './reportData'
import { inSeverityBreakdown } from '@/lib/triage/disposition'
import { reportCountable } from '@/lib/triage/reportable'

function fakeSession() {
  const queries: string[] = []
  return {
    queries,
    run: vi.fn(async (cypher: string) => {
      queries.push(cypher)
      if (cypher.includes('RETURN v.severity AS severity, count(v) AS count')) {
        return { records: [{ get: (k: string) => ({ severity: 'high', count: { low: 4, high: 0 } })[k] }] }
      }
      return { records: [] }
    }),
  }
}

describe('queryVulnerabilities', () => {
  test('the severity breakdown counts reportable and candidate findings only', async () => {
    const s = fakeSession()
    const v = await queryVulnerabilities(s, 'p1')
    const sev = s.queries.find(q => q.includes('RETURN v.severity AS severity, count(v) AS count'))!
    expect(sev).toContain(inSeverityBreakdown('v'))
    // Excluded findings were already out; the predicate is ANDed with it.
    expect(sev).toContain(reportCountable('v'))
    expect(v.severityDistribution).toEqual([{ severity: 'high', count: 4 }])
  })

  test('the findings list still names every counted finding, info included', async () => {
    const s = fakeSession()
    await queryVulnerabilities(s, 'p1')
    const list = s.queries.find(q => q.includes('v.cvss_score AS cvssScore'))!
    expect(list).toContain(reportCountable('v'))
    expect(list).not.toContain(inSeverityBreakdown('v'))
  })
})

describe('gatherReportData', () => {
  const SRC = readFileSync(join(__dirname, 'reportData.ts'), 'utf8')

  test('reads the disposition summary and returns it with the report', () => {
    expect(SRC).toMatch(/withSession\(s => queryDispositionSummary\(s, projectId, uid\)\)\s*\n\s*\.catch\(\(\) => null\)/)
    expect(SRC).toMatch(/\n\s+disposition,\n/)
  })
})
