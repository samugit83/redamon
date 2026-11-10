/**
 * The Route Exposure snippet mask: personal data out, secrets kept.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/redact.test.ts
 */
import { describe, test, expect } from 'vitest'
import { maskSnippet } from './redact'

describe('maskSnippet', () => {
  test('masks e-mails and long digit runs', () => {
    expect(maskSnippet('mail a@b.co id 1234567')).toBe('mail <email> id <n>')
  })

  test('keeps a token whole: a secret in the snippet is the finding', () => {
    expect(maskSnippet('key: abcdefghijklmnopqrstuvwxyz')).toBe('key: abcdefghijklmnopqrstuvwxyz')
  })

  test('returns a dash for nothing', () => {
    expect(maskSnippet(null)).toBe('-')
    expect(maskSnippet('')).toBe('-')
  })
})
