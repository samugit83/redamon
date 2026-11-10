/**
 * numericBoundsRefusal gives the verdict filterReconSettings gives, number by
 * number (R-7), and leaves non-numeric fields to their own routes' checks.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { numericBoundsRefusal } from './numericBounds'
import { filterReconSettings } from './filter'

describe('numericBoundsRefusal', () => {
  test.each([
    ['nucleiRateLimit', 0],
    ['nucleiRateLimit', 1],
    ['nucleiRateLimit', -1],
    ['graphqlRateLimit', 0],
    ['graphqlRateLimit', 100],
    ['graphqlRateLimit', 101],
    ['ffufRate', 0],
    ['katanaDepth', 2.5],
    ['katanaDepth', '3'],
  ])('%s = %s matches update_recon_settings', (key, value) => {
    const mcp = filterReconSettings({ [key]: value })
    const refusal = numericBoundsRefusal({ [key]: value })
    if (mcp.ok) expect(refusal).toBeNull()
    else expect(refusal).toEqual({ key, error: mcp.error })
  })

  test('the first offending key is named', () => {
    expect(numericBoundsRefusal({ katanaDepth: 2, nucleiRateLimit: 0, httpxRateLimit: 0 })?.key)
      .toBe('nucleiRateLimit')
  })

  test('a skipped key is not judged', () => {
    expect(numericBoundsRefusal({ nucleiRateLimit: 0 }, k => k === 'nucleiRateLimit')).toBeNull()
  })

  test('an optional number may be null; a required one may not', () => {
    expect(numericBoundsRefusal({ agentLport: null })).toBeNull()
    expect(numericBoundsRefusal({ nucleiRateLimit: null })?.error).toBe("'nucleiRateLimit' must be a number")
  })

  test('non-numeric and non-registry keys are left to their own checks', () => {
    expect(numericBoundsRefusal({ name: 42, nucleiTags: 'not-a-list', katanaEnabled: 'yes' })).toBeNull()
  })
})
