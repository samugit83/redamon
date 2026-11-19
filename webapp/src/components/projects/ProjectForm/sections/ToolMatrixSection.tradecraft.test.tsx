/**
 * The Tool Matrix's tradecraft row (Q3, T7.5; R-321, R-I5): one row, named by `tradecraft_lookup`,
 * which says it also governs `tradecraft_search` and `tradecraft_ask` when the project owner has
 * Tradecraft 2.0 on, and is as before with it off; no row of their own, so the phase map keys are
 * unchanged.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))
vi.mock('@/components/ui/WikiInfoButton', () => ({ WikiInfoButton: () => null }))

import { TOOL_ROW_NOTES, ToolMatrixSection } from './ToolMatrixSection'
import { field } from '@/lib/reconSettings/registry'

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(
    url.endsWith('/tradecraft-resources') ? [{ enabled: true }] : url.endsWith('/mcp') ? { servers: [] } : {},
  ), { status: 200 })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('the tradecraft row of the Tool Matrix', () => {
  test('matrix_row_text: it names the three tradecraft tools; the other two have no row', async () => {
    const updateField = vi.fn()
    render(<ToolMatrixSection data={{ agentToolPhaseMap: { tradecraft_lookup: ['informational'] } } as never} updateField={updateField} />)
    const note = await screen.findByTestId('tool-row-note-tradecraft_lookup')
    expect(note).toHaveTextContent(TOOL_ROW_NOTES.tradecraft_lookup)
    for (const tool of ['tradecraft_lookup', 'tradecraft_search', 'tradecraft_ask']) expect(note.parentElement).toHaveTextContent(tool)
    expect(screen.queryByTestId('tool-row-note-tradecraft_search')).toBeNull()
    const rows = [...document.querySelectorAll('[data-testid^="tool-row-note-"]')]
    expect(rows).toHaveLength(1)
    // Its phases are still the lookup's key.
    const row = note.closest('div')!
    fireEvent.click(row.querySelectorAll('input[type="checkbox"]')[1])
    expect(updateField).toHaveBeenCalledWith('agentToolPhaseMap', { tradecraft_lookup: ['informational', 'exploitation'] })
  })

  test('every account sees the note: the 2.0 switch left at the cut-over (T9.3)', async () => {
    render(<ToolMatrixSection data={{ agentToolPhaseMap: { tradecraft_lookup: ['informational'] } } as never} updateField={vi.fn()} />)
    expect(await screen.findByTestId('tool-row-note-tradecraft_lookup')).toHaveTextContent(TOOL_ROW_NOTES.tradecraft_lookup)
  })

  test('a new project shows the row ticked in all three phases (owner decision 2026-11-17)', async () => {
    // The Prisma default a new project stores; the agent's /defaults equals it (test_prisma_default_parity.py).
    const agentToolPhaseMap = JSON.parse(String(field('agentToolPhaseMap')!.default))
    render(<ToolMatrixSection data={{ agentToolPhaseMap } as never} updateField={vi.fn()} />)
    const row = (await screen.findByTestId('tool-row-note-tradecraft_lookup')).closest('div')!
    const ticks = [...row.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].map(box => box.checked)
    expect(ticks).toEqual([true, true, true])
  })
})
