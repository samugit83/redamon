/**
 * Unit tests for formatTokenCount.
 *
 * Run: npx vitest run src/lib/formatTokens.test.ts
 */

import { describe, test, expect } from 'vitest'
import { formatTokenCount } from './formatTokens'

describe('formatTokenCount', () => {
  test('renders small numbers as-is', () => {
    expect(formatTokenCount(0)).toBe('0')
    expect(formatTokenCount(1)).toBe('1')
    expect(formatTokenCount(42)).toBe('42')
    expect(formatTokenCount(999)).toBe('999')
  })

  test('renders thousands with k suffix (no decimals)', () => {
    expect(formatTokenCount(1000)).toBe('1k')
    expect(formatTokenCount(1500)).toBe('2k') // round half up
    expect(formatTokenCount(44000)).toBe('44k')
    expect(formatTokenCount(44499)).toBe('44k')
    expect(formatTokenCount(44500)).toBe('45k')
    expect(formatTokenCount(999499)).toBe('999k')
  })

  test('renders millions with M suffix (one decimal below 10M)', () => {
    expect(formatTokenCount(1_000_000)).toBe('1.0M')
    expect(formatTokenCount(1_200_000)).toBe('1.2M')
    expect(formatTokenCount(9_949_999)).toBe('9.9M')
    expect(formatTokenCount(9_950_000)).toMatch(/^(9\.9|10)M$/)
  })

  test('renders 10M+ without decimals', () => {
    expect(formatTokenCount(10_000_000)).toBe('10M')
    expect(formatTokenCount(42_300_000)).toBe('42M')
  })

  test('rejects negatives and NaN gracefully', () => {
    expect(formatTokenCount(-5)).toBe('0')
    expect(formatTokenCount(Number.NaN)).toBe('0')
  })

  test('handles non-finite and fractional inputs', () => {
    // fractional → rounded
    expect(formatTokenCount(0.4)).toBe('0')
    expect(formatTokenCount(0.6)).toBe('1')
    expect(formatTokenCount(999.4)).toBe('999')
  })
})
