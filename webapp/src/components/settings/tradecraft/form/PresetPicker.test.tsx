/** Quick add (§6.12): Featured first, then by name; search covers both; a pick hands the preset over. */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { PresetPicker } from './PresetPicker'
import { ALL_PRESETS, FEATURED_PRESETS } from '@/lib/tradecraft/presets'

afterEach(cleanup)

describe('PresetPicker', () => {
  test('browse: the Featured group first, in order, then the rest; 105 in all', () => {
    render(<PresetPicker onPick={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Browse 105 presets' }))
    const items = within(screen.getByRole('listbox', { name: 'Presets' })).getAllByRole('button')
    expect(items).toHaveLength(ALL_PRESETS.length)
    expect(items.slice(0, 5).map(b => b.firstChild?.textContent)).toEqual(FEATURED_PRESETS.map(p => p.name))
  })

  test('search narrows both groups; a pick hands over the preset and closes the list', () => {
    const onPick = vi.fn()
    render(<PresetPicker onPick={onPick} />)
    fireEvent.change(screen.getByLabelText('Quick add'), { target: { value: 'sigma' } })
    const list = screen.getByRole('listbox', { name: 'Presets' })
    fireEvent.click(within(list).getByText('Sigma rules'))
    expect(onPick).toHaveBeenCalledWith(expect.objectContaining({ key: 'sigma-rules' }))
    expect(screen.queryByRole('listbox')).toBeNull()
  })

  test('nothing matches: says so', () => {
    render(<PresetPicker onPick={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('Quick add'), { target: { value: 'zzzz-no-such' } })
    expect(screen.getByText('No preset matches.')).toBeInTheDocument()
  })
})
