/** Site type (§6.5): Auto with the detected type, or a forced one; detection thresholds under Auto. */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { SiteTypeSection, siteTypeStatus } from './SiteTypeSection'
import { open, renderSection, shownKeys, statusOf } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('SiteTypeSection', () => {
  test('the status says Auto and what was detected, or the forced type', () => {
    expect(siteTypeStatus('', '')).toBe('Auto')
    expect(siteTypeStatus('', 'agentic-crawl')).toBe('Auto (detected: Website)')
    expect(siteTypeStatus('pdf', 'agentic-crawl')).toBe('PDF')
  })

  test('picking a type calls back; under Auto the detection settings show, forced they do not', () => {
    const onForced = vi.fn()
    const auto = renderSection(ctx => <SiteTypeSection ctx={ctx} forcedType="" detectedType="mkdocs-wiki" onForcedType={onForced} />)
    expect(statusOf('Site type')).toBe('Auto (detected: Wiki (MkDocs/mdBook))')
    open('Site type')
    expect(shownKeys(auto.container)).toEqual(SECTION_KEYS.detection)
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'github-repo' } })
    expect(onForced).toHaveBeenCalledWith('github-repo')
    cleanup()
    const forced = renderSection(ctx => <SiteTypeSection ctx={ctx} forcedType="pdf" detectedType="" onForcedType={onForced} />)
    open('Site type')
    expect(shownKeys(forced.container)).toEqual([])
  })
})
