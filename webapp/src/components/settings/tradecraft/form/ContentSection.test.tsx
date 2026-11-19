/** Content (§6.8): body selector, removed elements, storage limits. */
import { describe, test, expect, afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import { ContentSection } from './ContentSection'
import { open, renderSection, shownKeys, statusOf } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('ContentSection', () => {
  test('its settings; Inherit', () => {
    const { container } = renderSection(ctx => <ContentSection ctx={ctx} />)
    expect(statusOf('Content')).toBe('Inherit')
    open('Content')
    expect(shownKeys(container)).toEqual(SECTION_KEYS.content)
  })
})
