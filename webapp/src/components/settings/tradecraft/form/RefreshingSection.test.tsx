/** Refreshing (§6.11): the failure policy override. */
import { describe, test, expect, afterEach } from 'vitest'
import { screen, cleanup, fireEvent } from '@testing-library/react'
import { RefreshingSection } from './RefreshingSection'
import { latest } from '../__testing__/formHarness'
import { open, renderSection, shownKeys } from '../__testing__/sectionTests'

afterEach(cleanup)

describe('RefreshingSection', () => {
  test('the failure policy, inherited then overridden (R-170)', () => {
    const { container } = renderSection(ctx => <RefreshingSection ctx={ctx} />)
    open('Refreshing')
    expect(shownKeys(container)).toEqual(['refreshing.onFailure'])
    expect(screen.getByText('Using your setting: Keep the previous version')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: /Override When a refresh fails/ }))
    fireEvent.change(screen.getByLabelText('When a refresh fails or comes back empty'), { target: { value: 'replace' } })
    expect(latest.overrides).toEqual({ 'refreshing.onFailure': 'replace' })
  })
})
