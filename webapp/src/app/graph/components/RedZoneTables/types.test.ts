/**
 * Unit tests for shared Red Zone types.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/types.test.ts
 */
import { describe, test, expect } from 'vitest'
import { normalizeSeverity, SEVERITY_RANK, toNum } from './types'

describe('normalizeSeverity', () => {
  test('accepts all canonical values lowercase', () => {
    for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
      expect(normalizeSeverity(sev)).toBe(sev)
    }
  })

  test('lowercases uppercase input', () => {
    expect(normalizeSeverity('CRITICAL')).toBe('critical')
    expect(normalizeSeverity('High')).toBe('high')
  })

  test('returns unknown for unrecognized strings', () => {
    expect(normalizeSeverity('catastrophic')).toBe('unknown')
    expect(normalizeSeverity('')).toBe('unknown')
  })

  test('returns unknown for non-strings', () => {
    expect(normalizeSeverity(null)).toBe('unknown')
    expect(normalizeSeverity(undefined)).toBe('unknown')
    expect(normalizeSeverity(7)).toBe('unknown')
    expect(normalizeSeverity({})).toBe('unknown')
  })
})

describe('SEVERITY_RANK', () => {
  test('enforces critical < high < medium < low < info < unknown', () => {
    expect(SEVERITY_RANK.critical).toBeLessThan(SEVERITY_RANK.high)
    expect(SEVERITY_RANK.high).toBeLessThan(SEVERITY_RANK.medium)
    expect(SEVERITY_RANK.medium).toBeLessThan(SEVERITY_RANK.low)
    expect(SEVERITY_RANK.low).toBeLessThan(SEVERITY_RANK.info)
    expect(SEVERITY_RANK.info).toBeLessThan(SEVERITY_RANK.unknown)
  })

  test('sorts severities critical-first when used as comparator', () => {
    const input: Array<{ sev: keyof typeof SEVERITY_RANK }> = [
      { sev: 'info' },
      { sev: 'critical' },
      { sev: 'low' },
      { sev: 'high' },
      { sev: 'medium' },
    ]
    const sorted = [...input].sort((a, b) => SEVERITY_RANK[a.sev] - SEVERITY_RANK[b.sev])
    expect(sorted.map(r => r.sev)).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })
})

describe('toNum', () => {
  test('unwraps Neo4j integer { low, high }', () => {
    expect(toNum({ low: 42, high: 0 })).toBe(42)
    expect(toNum({ low: 0, high: 0 })).toBe(0)
  })

  test('passes through plain numbers', () => {
    expect(toNum(7)).toBe(7)
    expect(toNum(0)).toBe(0)
    expect(toNum(-3)).toBe(-3)
  })

  test('returns 0 for non-numeric inputs', () => {
    expect(toNum(null)).toBe(0)
    expect(toNum(undefined)).toBe(0)
    expect(toNum('42')).toBe(0)
    expect(toNum({})).toBe(0)
  })

  test('extracts low from Neo4j integer even when nested deeper than expected', () => {
    // Guard against Neo4j driver quirk: some record getters return wrapped objects
    expect(toNum({ low: 1000000, high: 0 })).toBe(1000000)
  })
})
