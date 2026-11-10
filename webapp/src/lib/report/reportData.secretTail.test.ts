/** @vitest-environment node */
/**
 * A report leaves the operator's hands: a secret appears in it as its last
 * four characters, never whole, even though the graph keeps the full value.
 *
 * Run: npx vitest run src/lib/report/reportData.secretTail.test.ts
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { querySecrets } from './reportData'

function rec(values: Record<string, unknown>) {
  return { get: (k: string) => values[k] }
}

const KEY = 'ak9Q2w8E3r7T4y6U1i0O5pLz'

function session(row: Record<string, unknown>) {
  return {
    run: vi.fn(async (cypher: string) => {
      if (cypher.includes('AS secretValue')) return { records: [rec(row)] }
      return { records: [] }
    }),
  }
}

describe('querySecrets in the report', () => {
  test('a kept value is shown as its last four characters only', async () => {
    const out = await querySecrets(session({
      secretType: 'api_key', severity: 'high', source: 'urlscan', sourceUrl: null,
      sample: null, secretValue: KEY,
    }), 'p1')
    expect(out.findings[0].sample).toBe('••••5pLz')
    expect(JSON.stringify(out)).not.toContain(KEY)
  })

  test('a node without a kept value keeps its stored sample', async () => {
    const out = await querySecrets(session({
      secretType: 'api_key', severity: 'high', source: 'trufflehog', sourceUrl: null,
      sample: 'ghp_ab...wxyz', secretValue: null,
    }), 'p1')
    expect(out.findings[0].sample).toBe('ghp_ab...wxyz')
  })
})
