/**
 * Unit tests for secret-value redaction.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/redact.test.ts
 */
import { describe, test, expect } from 'vitest'
import { redactSecret } from './redact'

describe('redactSecret', () => {
  test('returns dash for null/undefined/empty', () => {
    expect(redactSecret(null)).toBe('-')
    expect(redactSecret(undefined)).toBe('-')
    expect(redactSecret('')).toBe('-')
  })

  test('short values (<=8 chars): show first 2 + ***', () => {
    expect(redactSecret('a')).toBe('a***')
    expect(redactSecret('ab')).toBe('ab***')
    expect(redactSecret('abcdef')).toBe('ab***')
    expect(redactSecret('12345678')).toBe('12***')
  })

  test('long values (>8 chars): show first 4 + *** + last 4', () => {
    expect(redactSecret('123456789')).toBe('1234***6789')
    expect(redactSecret('AKIA5FAKE1234567890X')).toBe('AKIA***890X')
    expect(redactSecret('ghp_abcdefghijklmnopqrstuv')).toBe('ghp_***stuv')
  })

  test('never leaks middle characters', () => {
    const secret = 'SUPER_SECRET_MIDDLE_PART'
    const redacted = redactSecret(secret)
    expect(redacted).not.toContain('SECRET_MIDDLE')
    expect(redacted).not.toContain('MIDDLE')
  })

  test('never exceeds max reveal length (4 + 3 + 4 = 11 visible)', () => {
    const redacted = redactSecret('x'.repeat(500))
    // 4 x + 3 * + 4 x = 11 chars
    expect(redacted.length).toBe(11)
  })

  test('handles non-string input by coercing to string', () => {
    // Defensive: Secret.sample may arrive as number from Neo4j in rare cases
    // @ts-expect-error — explicit type bypass for defensive behaviour test
    expect(redactSecret(12345678901234)).toBe('1234***1234')
  })
})
