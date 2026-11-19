/** Website crawl (§6.5, §4.4): the site's own fields and every crawl setting, overridable. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { WebsiteSection } from './WebsiteSection'
import { latest } from '../__testing__/formHarness'
import { open, renderSection, shownKeys, statusOf } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('WebsiteSection', () => {
  test('its settings, the status with two overrides, the sitemap suggestion', () => {
    const { container } = renderSection(
      ctx => <WebsiteSection ctx={ctx} sitemapFound="https://blog.tc-fixture.test/sitemap.xml" />,
      { 'crawl.strategy': 'auto', 'type.website.followPagination': true },
    )
    expect(statusOf('Website crawl')).toBe('2 overrides')
    open('Website crawl')
    expect(shownKeys(container)).toEqual(SECTION_KEYS.website)
    fireEvent.click(screen.getByRole('button', { name: /Use the sitemap Check URL found/ }))
    expect(latest.overrides['type.website.sitemapUrls']).toEqual(['https://blog.tc-fixture.test/sitemap.xml'])
  })
})
