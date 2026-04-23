/**
 * Unit tests for the Web Initial-Access grading rubric.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/webInitGrade.test.ts
 */
import { describe, test, expect } from 'vitest'
import {
  computeWebInitGrade,
  buildHeaderGrid,
  deriveWebInitGrade,
  WEB_INIT_HEADER_CHECKS,
} from './webInitGrade'

describe('computeWebInitGrade', () => {
  test('0 missing → A', () => {
    expect(computeWebInitGrade(0)).toBe('A')
  })

  test('1 missing → A (clean-ish)', () => {
    expect(computeWebInitGrade(1)).toBe('A')
  })

  test('2 missing → B', () => {
    expect(computeWebInitGrade(2)).toBe('B')
  })

  test('3 missing → C', () => {
    expect(computeWebInitGrade(3)).toBe('C')
  })

  test('4-5 missing → D', () => {
    expect(computeWebInitGrade(4)).toBe('D')
    expect(computeWebInitGrade(5)).toBe('D')
  })

  test('6+ missing → F', () => {
    expect(computeWebInitGrade(6)).toBe('F')
    expect(computeWebInitGrade(10)).toBe('F')
  })
})

describe('buildHeaderGrid', () => {
  test('empty list → all headers marked absent', () => {
    const grid = buildHeaderGrid([])
    for (const h of WEB_INIT_HEADER_CHECKS) expect(grid[h]).toBe(false)
  })

  test('full list → all headers marked present', () => {
    const grid = buildHeaderGrid([...WEB_INIT_HEADER_CHECKS])
    for (const h of WEB_INIT_HEADER_CHECKS) expect(grid[h]).toBe(true)
  })

  test('case-insensitive matching of header names', () => {
    const grid = buildHeaderGrid(['content-security-policy', 'STRICT-TRANSPORT-SECURITY'])
    expect(grid['Content-Security-Policy']).toBe(true)
    expect(grid['Strict-Transport-Security']).toBe(true)
    expect(grid['X-Frame-Options']).toBe(false)
  })

  test('ignores unknown headers', () => {
    const grid = buildHeaderGrid(['X-Custom-Thing', 'Content-Security-Policy'])
    expect(grid['Content-Security-Policy']).toBe(true)
    expect(grid['X-Frame-Options']).toBe(false)
  })

  test('handles null/undefined items defensively', () => {
    // @ts-expect-error - defensive against malformed Neo4j values
    const grid = buildHeaderGrid([null, 'Content-Security-Policy', undefined])
    expect(grid['Content-Security-Policy']).toBe(true)
  })
})

describe('deriveWebInitGrade', () => {
  test('all headers + no vulns → grade A', () => {
    const { grade, headerGrid, missingHeaderCount } = deriveWebInitGrade(
      [...WEB_INIT_HEADER_CHECKS],
      [],
    )
    expect(grade).toBe('A')
    expect(missingHeaderCount).toBe(0)
    expect(Object.values(headerGrid).every(v => v === true)).toBe(true)
  })

  test('no headers + no vulns → 6 missing → grade F', () => {
    const { grade, missingHeaderCount } = deriveWebInitGrade([], [])
    expect(missingHeaderCount).toBe(6)
    expect(grade).toBe('F')
  })

  test('4 headers present + 1 vuln → 2 missing + 1 vuln = 3 total → grade C', () => {
    const { grade } = deriveWebInitGrade(
      ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options'],
      ['login_no_https'],
    )
    expect(grade).toBe('C')
  })

  test('5 headers + 0 vulns → 1 missing = 1 total → grade A', () => {
    const { grade } = deriveWebInitGrade(
      ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy'],
      [],
    )
    expect(grade).toBe('A')
  })

  test('6 headers + 3 vulns → 0 missing + 3 vulns = 3 total → grade C', () => {
    const { grade } = deriveWebInitGrade(
      [...WEB_INIT_HEADER_CHECKS],
      ['login_no_https', 'session_no_secure', 'basic_auth_no_tls'],
    )
    expect(grade).toBe('C')
  })

  test('vuln-only weighting: 6 vulns + 0 headers present → 12 total → F', () => {
    const { grade } = deriveWebInitGrade(
      [],
      ['a', 'b', 'c', 'd', 'e', 'f'],
    )
    expect(grade).toBe('F')
  })
})
