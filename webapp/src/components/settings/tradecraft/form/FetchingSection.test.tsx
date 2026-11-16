/** Fetching (§6.7): every fetching setting; "Always use the browser" not offered with a login (§5). */
import { describe, test, expect, afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import { FetchingSection } from './FetchingSection'
import { open, renderSection, shownKeys } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

afterEach(cleanup)

describe('FetchingSection', () => {
  test('every fetching setting without a login; no browser-only option with one', () => {
    const plain = renderSection(ctx => <FetchingSection ctx={ctx} hasLogin={false} />)
    open('Fetching')
    expect(shownKeys(plain.container)).toEqual(SECTION_KEYS.fetching)
    cleanup()
    const login = renderSection(ctx => <FetchingSection ctx={ctx} hasLogin={true} />)
    open('Fetching')
    expect(shownKeys(login.container)).not.toContain('fetching.alwaysBrowser')
    expect(shownKeys(login.container)).toContain('fetching.waitForSelector')
  })
})
