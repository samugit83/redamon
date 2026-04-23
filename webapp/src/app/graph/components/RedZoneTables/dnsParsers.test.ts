/**
 * Unit tests for DNS + email parsers used by the DNS Posture table.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/dnsParsers.test.ts
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  extractSpfRecord,
  isSpfStrict,
  extractDmarcRecord,
  parseDmarcPolicy,
  isDnssecEnabled,
  daysFromIso,
} from './dnsParsers'

describe('extractSpfRecord', () => {
  test('returns null for nullish input', () => {
    expect(extractSpfRecord(null)).toBeNull()
    expect(extractSpfRecord(undefined)).toBeNull()
    expect(extractSpfRecord([])).toBeNull()
  })

  test('finds the TXT record containing v=spf1 (case-insensitive)', () => {
    const records = [
      'google-site-verification=abc',
      'v=spf1 include:_spf.google.com ~all',
      'ms=ms12345',
    ]
    expect(extractSpfRecord(records)).toBe('v=spf1 include:_spf.google.com ~all')
  })

  test('returns null when no SPF TXT is present', () => {
    expect(extractSpfRecord(['foo', 'bar', 'ms=ms12345'])).toBeNull()
  })

  test('skips non-string entries defensively', () => {
    // @ts-expect-error - defensive test against malformed Neo4j record
    expect(extractSpfRecord([null, 42, 'v=spf1 -all'])).toBe('v=spf1 -all')
  })
})

describe('isSpfStrict', () => {
  test('returns true for -all (hard fail)', () => {
    expect(isSpfStrict('v=spf1 include:_spf.google.com -all')).toBe(true)
  })

  test('returns true for ~all (soft fail)', () => {
    expect(isSpfStrict('v=spf1 include:_spf.google.com ~all')).toBe(true)
  })

  test('returns false for ?all (neutral) and +all (pass)', () => {
    expect(isSpfStrict('v=spf1 +all')).toBe(false)
    expect(isSpfStrict('v=spf1 ?all')).toBe(false)
  })

  test('returns false for missing policy qualifier', () => {
    expect(isSpfStrict('v=spf1 include:example.com')).toBe(false)
  })

  test('returns false for null input', () => {
    expect(isSpfStrict(null)).toBe(false)
  })
})

describe('extractDmarcRecord', () => {
  test('finds DMARC TXT case-insensitively', () => {
    const records = ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']
    expect(extractDmarcRecord(records)).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')
  })

  test('lowercase v=dmarc1 also matches', () => {
    expect(extractDmarcRecord(['v=dmarc1; p=none'])).toBe('v=dmarc1; p=none')
  })

  test('returns null when no DMARC record present', () => {
    expect(extractDmarcRecord(['v=spf1 -all'])).toBeNull()
    expect(extractDmarcRecord(null)).toBeNull()
  })
})

describe('parseDmarcPolicy', () => {
  test('extracts p=reject', () => {
    expect(parseDmarcPolicy('v=DMARC1; p=reject; rua=mailto:x@y.com')).toBe('reject')
  })

  test('extracts p=quarantine', () => {
    expect(parseDmarcPolicy('v=DMARC1; p=quarantine')).toBe('quarantine')
  })

  test('extracts p=none', () => {
    expect(parseDmarcPolicy('v=DMARC1; p=none; sp=none')).toBe('none')
  })

  test('lowercases P=REJECT', () => {
    expect(parseDmarcPolicy('v=DMARC1; P=REJECT')).toBe('reject')
  })

  test('handles whitespace around =', () => {
    expect(parseDmarcPolicy('v=DMARC1; p  =  reject')).toBe('reject')
  })

  test('returns null for record without p= tag', () => {
    expect(parseDmarcPolicy('v=DMARC1; rua=mailto:x@y.com')).toBeNull()
  })

  test('returns null for null input', () => {
    expect(parseDmarcPolicy(null)).toBeNull()
  })
})

describe('isDnssecEnabled', () => {
  test('returns true for non-empty signed string', () => {
    expect(isDnssecEnabled('signedDelegation')).toBe(true)
    expect(isDnssecEnabled('SIGNED')).toBe(true)
    expect(isDnssecEnabled('on')).toBe(true)
  })

  test('returns false for common "unsigned" values', () => {
    expect(isDnssecEnabled('unsigned')).toBe(false)
    expect(isDnssecEnabled('UNSIGNED')).toBe(false)
    expect(isDnssecEnabled('not signed')).toBe(false)
    expect(isDnssecEnabled('none')).toBe(false)
    expect(isDnssecEnabled('off')).toBe(false)
    expect(isDnssecEnabled('false')).toBe(false)
  })

  test('returns false for empty/nullish', () => {
    expect(isDnssecEnabled(null)).toBe(false)
    expect(isDnssecEnabled(undefined)).toBe(false)
    expect(isDnssecEnabled('')).toBe(false)
    expect(isDnssecEnabled('   ')).toBe(false)
  })
})

describe('daysFromIso', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-04-21T00:00:00Z'))
  })

  afterEach(() => { vi.useRealTimers() })

  test('returns null for null / invalid dates', () => {
    expect(daysFromIso(null)).toBeNull()
    expect(daysFromIso(undefined)).toBeNull()
    expect(daysFromIso('not-a-date')).toBeNull()
    expect(daysFromIso('')).toBeNull()
  })

  test('returns 0 for same day', () => {
    expect(daysFromIso('2026-04-21T12:00:00Z')).toBe(0)
  })

  test('returns positive for future date', () => {
    expect(daysFromIso('2026-05-21T00:00:00Z')).toBe(30)
  })

  test('returns negative for past date (expired)', () => {
    expect(daysFromIso('2026-03-22T00:00:00Z')).toBe(-30)
  })

  test('truncates using floor (12h into the future day → 0, not 1)', () => {
    expect(daysFromIso('2026-04-21T23:59:59Z')).toBe(0)
  })
})
