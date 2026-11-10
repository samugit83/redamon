/**
 * The Route Exposure snippet mask: personal data and token-shaped values out.
 * Run: npx vitest run src/app/graph/components/RedZoneTables/redact.test.ts
 */
import { describe, test, expect } from 'vitest'
import { maskSnippet } from './redact'

describe('maskSnippet', () => {
  test('masks e-mails and long digit runs', () => {
    expect(maskSnippet('mail a@b.co id 1234567')).toBe('mail <email> id <n>')
  })

  test('masks a token: the secrets are shown in their own column', () => {
    expect(maskSnippet('key: abcdefghijklmnopqrstuvwxyz')).toBe('key: <tok>')
  })

  test('returns a dash for nothing', () => {
    expect(maskSnippet(null)).toBe('-')
    expect(maskSnippet('')).toBe('-')
  })
})
