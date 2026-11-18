/** One per-resource setting: Inherit by default with the inherited value; Override unlocks it (§6.1, R-131). */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { settingDef } from '@/lib/tradecraft/settingsSpec'
import { OverrideField } from './OverrideField'
import { Harness, latest } from '../__testing__/formHarness'
import { inheritedOf } from './OverrideList'

afterEach(cleanup)

function field(key: string, initial: Record<string, unknown> = {}) {
  const def = settingDef(key)!
  return render(
    <Harness initial={initial}>
      {ctx => <OverrideField def={def} inherited={inheritedOf(ctx, def)} value={ctx.overrides[key]} onChange={v => ctx.setOverride(key, v)} userId="user-1" />}
    </Harness>,
  )
}

describe('OverrideField', () => {
  test('inherit_override: shows "Using your setting: 120 pages"; Override starts from it; off goes back', () => {
    field('crawl.maxPages')
    expect(screen.getByText('Using your setting: 120 pages')).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).toBeNull()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override Max pages visited' }))
    expect(latest.overrides).toEqual({ 'crawl.maxPages': 120 })
    fireEvent.change(screen.getByLabelText('Max pages visited'), { target: { value: '50' } })
    expect(latest.overrides).toEqual({ 'crawl.maxPages': '50' })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override Max pages visited' }))
    expect(latest.overrides).toEqual({})
    expect(screen.getByText('Using your setting: 120 pages')).toBeInTheDocument()
  })

  test('a resource-only setting inherits the default', () => {
    field('type.github.folderEntries')
    expect(screen.getByText('Default: off')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override One entry per folder' }))
    expect(latest.overrides).toEqual({ 'type.github.folderEntries': false })
    fireEvent.click(screen.getByLabelText('One entry per folder'))
    expect(latest.overrides).toEqual({ 'type.github.folderEntries': true })
  })

  test('an enum shows its words', () => {
    field('crawl.strategy', { 'crawl.strategy': 'auto' })
    expect((screen.getByLabelText('Crawl strategy') as HTMLSelectElement).value).toBe('auto')
    expect(screen.getByRole('option', { name: 'Rule-based' })).toBeInTheDocument()
  })

  test('an error shows under the field', () => {
    const def = settingDef('crawl.maxPages')!
    render(<OverrideField def={def} inherited={200} value="9000" onChange={() => undefined} userId="u" error="Must be an integer from 1 to 500" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Must be an integer from 1 to 500')
  })
})
