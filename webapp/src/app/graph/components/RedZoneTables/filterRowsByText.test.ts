/**
 * Unit tests for the client-side row filter.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/filterRowsByText.test.ts
 */
import { describe, test, expect } from 'vitest'
import { filterRowsByText } from './formatters'

describe('filterRowsByText', () => {
  const rows = [
    { host: 'api.example.com', severity: 'critical', port: 443, tags: ['prod', 'web'] },
    { host: 'admin.example.com', severity: 'high',     port: 8080, tags: ['admin'] },
    { host: 'cdn.acme.io',      severity: 'medium',   port: 80,   tags: ['edge'] },
    { host: 'dev.example.com',  severity: 'info',     port: 22,   tags: ['ssh'] },
  ]

  test('empty search returns all rows (reference equality preserved)', () => {
    expect(filterRowsByText(rows, '')).toBe(rows)
  })

  test('matches substring in string fields', () => {
    const out = filterRowsByText(rows, 'example')
    expect(out).toHaveLength(3)
    expect(out.map(r => r.host)).toEqual([
      'api.example.com',
      'admin.example.com',
      'dev.example.com',
    ])
  })

  test('match is case-insensitive', () => {
    expect(filterRowsByText(rows, 'API')).toHaveLength(1)
    expect(filterRowsByText(rows, 'ADMIN')).toHaveLength(1)
  })

  test('matches numeric field when coerced to string', () => {
    expect(filterRowsByText(rows, '443')).toHaveLength(1)
    expect(filterRowsByText(rows, '22')).toHaveLength(1)
  })

  test('matches inside string array', () => {
    expect(filterRowsByText(rows, 'prod')).toHaveLength(1)
    expect(filterRowsByText(rows, 'edge')).toHaveLength(1)
  })

  test('matches across severity and tags when search hits multiple columns', () => {
    const out = filterRowsByText(rows, 'admin')
    expect(out).toHaveLength(1)
    expect(out[0].host).toBe('admin.example.com')
  })

  test('matches nested object values (one level deep)', () => {
    const nested = [
      { id: 1, meta: { owner: 'security' } },
      { id: 2, meta: { owner: 'platform' } },
    ]
    expect(filterRowsByText(nested, 'security')).toHaveLength(1)
    expect(filterRowsByText(nested, 'platform')).toHaveLength(1)
  })

  test('ignores null/undefined values without throwing', () => {
    const withNulls = [
      { a: null, b: undefined, c: 'hit' },
      { a: null, b: undefined, c: 'miss' },
    ]
    const out = filterRowsByText(withNulls, 'hit')
    expect(out).toHaveLength(1)
  })

  test('returns empty array when nothing matches', () => {
    expect(filterRowsByText(rows, 'nonexistent-xyz-zzz')).toEqual([])
  })

  test('search term inside array chip not leaked into other rows', () => {
    const out = filterRowsByText(rows, 'ssh')
    expect(out).toHaveLength(1)
    expect(out[0].host).toBe('dev.example.com')
  })
})
