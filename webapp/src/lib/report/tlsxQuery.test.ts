/** @vitest-environment node */
/**
 * Regression G3: the TLS report query must be bounded in Cypher.
 *
 * queryTlsx pulled EVERY Certificate row in the project and sliced 50 in JS, so
 * report generation scaled with the certificate population -- the very
 * population tlsx exists to grow, and the reason a tenant index was added for
 * it. Every other query in reportData.ts bounds itself in Cypher; this one did
 * not. Counts must still be exact, so the fix is an aggregate + a bounded list,
 * not a bare LIMIT on one query.
 *
 * Run: npx vitest run src/lib/report/tlsxQuery.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { queryTlsx } from './reportData'

/** The neo4j driver's Integer shape, which reportData's toNum unwraps. */
function int(n: number) { return { low: n, high: 0 } }

/** Fake session recording every Cypher it is handed. */
function fakeSession() {
  const queries: string[] = []
  return {
    queries,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    run: vi.fn(async (cypher: string, _params: any) => {
      queries.push(cypher)
      if (cypher.includes('AS total')) {
        return { records: [{ get: (k: string) => int({
          total: 1200, expired: 12, selfSigned: 3, mismatched: 2,
          wildcard: 40, expiringSoon: 7 }[k] ?? 0) }] }
      }
      if (cypher.includes('AS issuer')) {
        return { records: [{ get: (k: string) => k === 'issuer' ? "CN=R3" : int(900) }] }
      }
      // the bounded list
      const row = {
        subjectCn: 'mail.acme.test', issuer: 'CN=R3', san: ['a', 'b'],
        notAfter: '2027-01-01T00:00:00Z', source: 'tlsx',
        expired: true, selfSigned: false, mismatched: false, wildcard: false,
      }
      return { records: [{ get: (k: string) => (row as Record<string, unknown>)[k] }] }
    }),
  }
}

describe('queryTlsx — bounded in Cypher', () => {
  test('the certificate LIST query carries a LIMIT', async () => {
    const s = fakeSession()
    await queryTlsx(s, 'p1')
    const list = s.queries.find(q => q.includes('AS subjectCn'))
    expect(list, 'no certificate list query was issued').toBeDefined()
    expect(list).toMatch(/LIMIT\s+50/)
  })

  test('totals come from a Cypher aggregate, not from counting rows in JS', async () => {
    const s = fakeSession()
    const out = await queryTlsx(s, 'p1')
    // 1200 certificates, but only the capped list is materialised.
    expect(out.totalCertificates).toBe(1200)
    expect(out.expired).toBe(12)
    expect(out.findings.length).toBeLessThanOrEqual(50)
  })

  test('top issuers are aggregated and bounded in Cypher', async () => {
    const s = fakeSession()
    await queryTlsx(s, 'p1')
    const issuers = s.queries.find(q => q.includes('AS issuer'))
    expect(issuers).toMatch(/LIMIT\s+10/)
    expect(issuers).toMatch(/ORDER BY count DESC/)
  })

  test('posture problems are ordered first so the cap keeps the useful rows', async () => {
    const s = fakeSession()
    await queryTlsx(s, 'p1')
    const list = s.queries.find(q => q.includes('AS subjectCn'))!
    expect(list).toMatch(/ORDER BY notable DESC/)
  })

  test('every query reads the FIXED anchors, not BaseURL alone', async () => {
    const s = fakeSession()
    await queryTlsx(s, 'p1')
    for (const q of s.queries) {
      expect(q).toContain(':BaseURL {project_id: $pid})-[:HAS_CERTIFICATE]->(c)')
      expect(q).toContain(':IP {project_id: $pid})-[:HAS_CERTIFICATE]->(c)')
    }
  })

  test('every query is scoped to the project', async () => {
    const s = fakeSession()
    await queryTlsx(s, 'p1')
    expect(s.queries.length).toBeGreaterThanOrEqual(3)
    for (const q of s.queries) expect(q).toContain('project_id: $pid')
  })
})
