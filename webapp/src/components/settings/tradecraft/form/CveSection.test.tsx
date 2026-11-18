/** CVE archive (§6.5): path patterns, branch, README fallback; the pattern Check URL found. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { CveSection } from './CveSection'
import { latest } from '../__testing__/formHarness'
import { open, renderSection, shownKeys, statusOf } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('CveSection', () => {
  test('its settings; Inherit with no override', () => {
    const { container } = renderSection(ctx => <CveSection ctx={ctx} foundPattern={null} />)
    expect(statusOf('CVE archive')).toBe('Inherit')
    open('CVE archive')
    expect(shownKeys(container)).toEqual(SECTION_KEYS.cve)
    expect(screen.getByText('Default: {year}/{cve}.md, {year}/{cve}/README.md')).toBeInTheDocument()
  })

  test('the pattern Check URL found is offered', () => {
    renderSection(ctx => <CveSection ctx={ctx} foundPattern="{year}/{cve}.json" />)
    open('CVE archive')
    fireEvent.click(screen.getByRole('button', { name: /Use the pattern Check URL found: \{year\}\/\{cve\}\.json/ }))
    expect(latest.overrides['type.cve.pathPatterns']).toEqual(['{year}/{cve}.json'])
  })
})
