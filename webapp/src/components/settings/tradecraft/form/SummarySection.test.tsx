/** Summary (§6.9, R-164): the editor saves at once, Regenerate starts a job, the settings below it. */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { SummarySection, summaryStatus } from './SummarySection'
import { RESOURCE } from '../__testing__/resourceView'
import { open, renderSection, shownKeys, statusOf } from '../__testing__/sectionTests'
import { SECTION_KEYS } from './sections'

const fetchMock = vi.fn()
const onResource = vi.fn()
const onJob = vi.fn()
beforeEach(() => { vi.clearAllMocks(); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const calls = () => fetchMock.mock.calls.map(c => [c[0], (c[1] as RequestInit).method, (c[1] as RequestInit).body])

describe('SummarySection', () => {
  test('the status: Generated or Written by me, locked, overrides', () => {
    expect(summaryStatus({ summarySource: 'generated', summaryLocked: false }, 'Inherit')).toBe('Generated')
    expect(summaryStatus({ summarySource: 'manual', summaryLocked: true }, '1 override')).toBe('Written by me · locked · 1 override')
  })

  test('summary_editor: writing and locking saves through the summary route, at once', async () => {
    fetchMock.mockResolvedValue(answer(200, { resource: { ...RESOURCE, summary: 'Mine.', summarySource: 'manual', summaryLocked: true } }))
    renderSection(ctx => <SummarySection ctx={ctx} resource={RESOURCE} onResource={onResource} onJob={onJob} />)
    expect(statusOf('Summary')).toBe('Generated')
    open('Summary')
    expect((screen.getByLabelText(/The summary the agent reads/) as HTMLTextAreaElement).value).toBe('s')
    fireEvent.change(screen.getByLabelText(/The summary the agent reads/), { target: { value: 'Mine.' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /Lock summary/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save summary' }))
    await waitFor(() => expect(onResource).toHaveBeenCalled())
    expect(calls()).toEqual([['/api/users/user-1/tradecraft-resources/r1/summary', 'PUT', JSON.stringify({ text: 'Mine.', locked: true })]])
    expect(screen.getByRole('status')).toHaveTextContent('Summary saved')
  })

  test('Regenerate starts the job; refused while locked or written by me', async () => {
    fetchMock.mockResolvedValue(answer(202, { job: { id: 'j1', kind: 'regenerate_summary', status: 'queued' } }))
    renderSection(ctx => <SummarySection ctx={ctx} resource={RESOURCE} onResource={onResource} onJob={onJob} />)
    open('Summary')
    fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }))
    await waitFor(() => expect(onJob).toHaveBeenCalled())
    expect(calls()[0].slice(0, 2)).toEqual(['/api/users/user-1/tradecraft-resources/r1/summary/regenerate', 'POST'])
    cleanup()
    renderSection(ctx => <SummarySection ctx={ctx} resource={{ ...RESOURCE, summarySource: 'manual' }} onResource={onResource} onJob={onJob} />)
    open('Summary')
    expect(screen.getByRole('button', { name: 'Regenerate' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Back to Generated' })).toBeInTheDocument()
  })

  test('a refusal says why with its code', async () => {
    fetchMock.mockResolvedValue(answer(409, { error: 'The summary is locked', code: 'summary_locked' }))
    renderSection(ctx => <SummarySection ctx={ctx} resource={RESOURCE} onResource={onResource} onJob={onJob} />)
    open('Summary')
    fireEvent.click(screen.getByRole('button', { name: 'Regenerate' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/summary_locked/)
  })

  test('a new resource has no editor, only the settings', () => {
    const { container } = renderSection(ctx => <SummarySection ctx={ctx} resource={null} onResource={onResource} onJob={onJob} />)
    open('Summary')
    expect(screen.queryByRole('group', { name: 'Summary editor' })).toBeNull()
    expect(shownKeys(container)).toEqual(SECTION_KEYS.summary)
  })
})
