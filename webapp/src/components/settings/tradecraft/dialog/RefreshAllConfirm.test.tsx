/** Save & refresh all's confirmation (§3.2, T6.10; R-026): every enabled resource, each ticked; unticked ones are left out. */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { BUDGET_NOTE, RefreshAllConfirm } from './RefreshAllConfirm'

afterEach(cleanup)
const RESOURCES = [{ id: 'r1', name: 'HackTricks' }, { id: 'r2', name: 'PayloadsAllTheThings' }, { id: 'r3', name: 'Blog' }]

describe('RefreshAllConfirm', () => {
  test('confirmation_lists_ticked: every resource listed and ticked; the budget stop said', () => {
    const onConfirm = vi.fn()
    render(<RefreshAllConfirm resources={RESOURCES} onConfirm={onConfirm} onCancel={vi.fn()} />)
    const list = within(screen.getByRole('list', { name: 'Resources to refresh' }))
    expect(list.getAllByRole('checkbox').map(c => (c as HTMLInputElement).checked)).toEqual([true, true, true])
    expect(list.getByText('PayloadsAllTheThings')).toBeInTheDocument()
    expect(screen.getByText(new RegExp(BUDGET_NOTE.slice(0, 40)))).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save & refresh 3' }))
    expect(onConfirm).toHaveBeenCalledWith(['r1', 'r2', 'r3'])
  })

  test('untick_excludes: an unticked resource is left out; none ticked cannot confirm', () => {
    const onConfirm = vi.fn()
    render(<RefreshAllConfirm resources={RESOURCES} onConfirm={onConfirm} onCancel={vi.fn()} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'PayloadsAllTheThings' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save & refresh 2' }))
    expect(onConfirm).toHaveBeenLastCalledWith(['r1', 'r3'])
    fireEvent.click(screen.getByRole('checkbox', { name: 'HackTricks' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Blog' }))
    expect(screen.getByRole('button', { name: 'Save & refresh 0' })).toBeDisabled()
  })

  test('Escape closes the confirmation only, not Configure ingestion behind it', () => {
    const onCancel = vi.fn()
    const outer = vi.fn()
    render(<div onKeyDown={outer}><RefreshAllConfirm resources={RESOURCES} onConfirm={vi.fn()} onCancel={onCancel} /></div>)
    fireEvent.keyDown(screen.getByRole('checkbox', { name: 'Blog' }), { key: 'Escape' })
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(outer).not.toHaveBeenCalled()
  })

  test('Cancel changes nothing; no enabled resource says so', () => {
    const onCancel = vi.fn()
    render(<RefreshAllConfirm resources={[]} onConfirm={vi.fn()} onCancel={onCancel} />)
    expect(screen.getByText(/No enabled resource to refresh/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onCancel).toHaveBeenCalled()
  })
})

describe('refreshAllText: what the tab says once the batch started', () => {
  test('how many run one at a time, and each skipped resource with why', async () => {
    const { refreshAllText } = await import('@/lib/tradecraft/client')
    expect(refreshAllText({ bulkId: 'b', started: [{ resourceId: 'r1', name: 'A', job: {} as never }], skipped: [] }))
      .toBe('Refreshing 1 resource one at a time.')
    expect(refreshAllText({
      bulkId: 'b', started: [],
      skipped: [{ resourceId: 'r2', name: 'KB', reason: 'use_site_logins' }, { resourceId: 'r3', name: 'Blog', reason: 'job_running' }],
    })).toBe('No resource is being refreshed. Skipped: KB (its site login is not used while acting as the account), Blog (already refreshing).')
  })
})
