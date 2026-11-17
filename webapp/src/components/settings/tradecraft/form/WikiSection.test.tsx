/** Wiki and GitBook (§6.5): sitemap URLs, menu selector, language, map size; the sitemap Check URL found. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { WikiSection } from './WikiSection'
import { latest } from '../__testing__/formHarness'
import { open, renderSection, shownKeys } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('WikiSection', () => {
  test('the wiki and the GitBook variants show their own keys', () => {
    const wiki = renderSection(ctx => <WikiSection ctx={ctx} variant="wiki" sitemapFound={null} />)
    open('Wiki')
    expect(shownKeys(wiki.container)).toEqual(SECTION_KEYS.wiki)
    cleanup()
    const gitbook = renderSection(ctx => <WikiSection ctx={ctx} variant="gitbook" sitemapFound={null} />)
    open('GitBook')
    expect(shownKeys(gitbook.container)).toEqual(SECTION_KEYS.gitbook)
  })

  test('real_titles_override: "Use real page titles" and its fetch limit can be overridden on a wiki and a GitBook (T6.11)', () => {
    for (const variant of ['wiki', 'gitbook'] as const) {
      const { container } = renderSection(ctx => <WikiSection ctx={ctx} variant={variant} sitemapFound={null} />)
      open(variant === 'wiki' ? 'Wiki' : 'GitBook')
      expect(shownKeys(container)).toEqual(expect.arrayContaining(['knownTypes.realTitles', 'knownTypes.maxTitleFetches']))
      expect(screen.getAllByText('Use real page titles').length).toBeGreaterThan(0)
      cleanup()
    }
  })

  test('the sitemap Check URL found is offered', () => {
    renderSection(ctx => <WikiSection ctx={ctx} variant="wiki" sitemapFound="https://wiki.tc-fixture.test/en/sitemap.xml" />)
    open('Wiki')
    fireEvent.click(screen.getByRole('button', { name: /Use the sitemap Check URL found/ }))
    expect(latest.overrides['type.wiki.sitemapUrls']).toEqual(['https://wiki.tc-fixture.test/en/sitemap.xml'])
  })
})
