/** Docs site (§6.5): search index URL and map size; the index Check URL found. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { DocsSection } from './DocsSection'
import { latest } from '../__testing__/formHarness'
import { open, renderSection, shownKeys } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('DocsSection', () => {
  test('its settings, and the index Check URL found', () => {
    const { container } = renderSection(ctx => <DocsSection ctx={ctx} indexFound="https://docs.tc-fixture.test/en/latest/searchindex.js" />)
    open('Docs site')
    expect(shownKeys(container)).toEqual(SECTION_KEYS.docs)
    fireEvent.click(screen.getByRole('button', { name: /Use the index Check URL found/ }))
    expect(latest.overrides['type.docs.searchIndexUrl']).toBe('https://docs.tc-fixture.test/en/latest/searchindex.js')
  })
})
