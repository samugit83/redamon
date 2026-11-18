/** PDF (§6.5): page range, map by, skip pages, max pages; the page count Check URL found. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup } from '@testing-library/react'
import { PdfSection } from './PdfSection'
import { open, renderSection, shownKeys } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('PdfSection', () => {
  test('its settings and the page count', () => {
    const { container } = renderSection(ctx => <PdfSection ctx={ctx} pages={1234} />)
    open('PDF')
    expect(shownKeys(container)).toEqual(SECTION_KEYS.pdf)
    expect(screen.getByText('The document has 1,234 pages.')).toBeInTheDocument()
  })
})
