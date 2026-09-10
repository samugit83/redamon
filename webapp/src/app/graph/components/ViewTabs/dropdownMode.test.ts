/**
 * Regression: the table dropdown rendered a SECOND "Triage" tab.
 *
 * Found by driving the real page in a browser. Modes with their own top-level
 * tab must not also be advertised by the table dropdown, or the tab bar shows
 * two identical-looking tabs and only one of them is marked selected.
 *
 * The cause was duplicated logic, not a missing case: the fallback was written
 * out twice, once to pick the icon and once to pick the label, and only the icon
 * copy was updated when the Triage tab was added. Both now call one helper, and
 * this pins that they agree.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { dropdownMode } from './ViewTabs'

describe('the table dropdown never advertises a mode that has its own tab', () => {
  test.each(['reconDelta', 'scanSchedule', 'triage'] as const)(
    '%s falls back to the default label',
    mode => {
      expect(dropdownMode(mode)).toBe('all')
    },
  )

  test('an ordinary table mode is shown as itself', () => {
    expect(dropdownMode('secrets')).toBe('secrets')
    expect(dropdownMode('nodeDetails')).toBe('nodeDetails')
  })

  test('no mode falls back to the default label', () => {
    expect(dropdownMode(null)).toBe('all')
    expect(dropdownMode(undefined)).toBe('all')
  })

  test('the icon and the label are computed from the SAME helper', () => {
    // The actual defect: two copies of the fallback that drifted. Reintroducing
    // a second inline copy is what this catches.
    const src = readFileSync(join(__dirname, 'ViewTabs.tsx'), 'utf8')
    const inlineFallbacks = src.match(/tableViewMode === 'reconDelta' \|\| tableViewMode === 'scanSchedule'/g)
    expect(inlineFallbacks, 'the dropdown fallback was inlined again instead of using dropdownMode()')
      .toBeNull()
    expect(src.match(/dropdownMode\(tableViewMode\)/g)).toHaveLength(2)
  })
})
