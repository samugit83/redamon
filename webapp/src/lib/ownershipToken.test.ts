import { describe, test, expect } from 'vitest'
import {
  LEGACY_OWNERSHIP_TOKEN, generateOwnershipToken, isUnsetOwnershipToken, ownershipTokenForCreate,
} from './ownershipToken'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

describe('the ownership token a new project is created with', () => {
  test.each([
    ['missing', undefined],
    ['null', null],
    ['empty', ''],
    ['whitespace', '  '],
    ['the shared placeholder', LEGACY_OWNERSHIP_TOKEN],
    ['the shared placeholder padded', ` ${LEGACY_OWNERSHIP_TOKEN} `],
    ['not a string', 42],
  ])('%s counts as unset and is replaced', (_label, value) => {
    expect(isUnsetOwnershipToken(value)).toBe(true)
    expect(ownershipTokenForCreate(value)).toMatch(UUID)
  })

  test('a chosen token is kept as typed', () => {
    expect(isUnsetOwnershipToken('k7-mine')).toBe(false)
    expect(ownershipTokenForCreate('k7-mine')).toBe('k7-mine')
  })

  test('each generated token is new', () => {
    const tokens = new Set(Array.from({ length: 50 }, () => generateOwnershipToken()))
    expect(tokens.size).toBe(50)
  })

  test('the placeholder is the value every install shipped', () => {
    expect(LEGACY_OWNERSHIP_TOKEN).toBe('your-secret-token-here')
  })
})
