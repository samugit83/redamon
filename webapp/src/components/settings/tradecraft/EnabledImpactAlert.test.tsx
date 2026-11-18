/**
 * The alert of a change of Enabled (§3.4, T4.9, R-062, R-140): its words, and Confirm saves while
 * Cancel changes nothing, on the card and in the Edit form.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

vi.mock('@/components/shared/ModelPicker', () => ({
  ModelPicker: ({ value, onChange }: { value: string; onChange: (v: string) => void }) =>
    <input aria-label="Model" value={value} onChange={e => onChange(e.target.value)} />,
}))
const alerts = vi.hoisted(() => ({ confirm: vi.fn(async () => true) }))
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useOptionalAlertModal: () => alerts,
  useAlertModal: () => alerts,
}))

import { ENABLED_ALERT_TITLE, enabledImpactText } from './EnabledImpactAlert'
import { ResourceCard } from './ResourceCard'
import { ResourceFormV2 } from './form/ResourceFormV2'
import { RESOURCE } from './__testing__/resourceView'

const fetchMock = vi.fn()
const onToggleEnabled = vi.fn()
const onSaved = vi.fn()
const IMPACT = '/api/users/user-1/tradecraft-resources/r1/enabled-impact'
beforeEach(() => {
  vi.clearAllMocks()
  alerts.confirm.mockResolvedValue(true)
  fetchMock.mockImplementation(async (url: string) => {
    if (url.startsWith(IMPACT)) return new Response(JSON.stringify({ next: url.endsWith('true'), projects: 7, turnedOffIn: 2 }), { status: 200 })
    return new Response(JSON.stringify({ resource: RESOURCE, job: null }), { status: 200 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const card = (enabled: boolean) => render(
  <ResourceCard userId="user-1" resource={{ ...RESOURCE, name: 'HackTricks', enabled }}
    onRefresh={vi.fn()} onCancel={vi.fn()} onEdit={vi.fn()} onDelete={vi.fn()} onToggleEnabled={onToggleEnabled} />,
)

describe('the words', () => {
  test('disable_text', () => {
    expect(enabledImpactText('HackTricks', false, { projects: 7, turnedOffIn: 2 })).toBe('HackTricks will be disabled in all your 7 projects.')
    expect(enabledImpactText('HackTricks', false, { projects: 1, turnedOffIn: 0 })).toBe('HackTricks will be disabled in your 1 project.')
  })

  test('enable_text_with_turned_off_count', () => {
    expect(enabledImpactText('HackTricks', true, { projects: 7, turnedOffIn: 2 }))
      .toBe('HackTricks will be enabled in all your 7 projects, including the 2 where it was turned off.')
    expect(enabledImpactText('HackTricks', true, { projects: 7, turnedOffIn: 0 })).toBe('HackTricks will be enabled in all your 7 projects.')
    expect(enabledImpactText('HackTricks', true, null)).toBe('HackTricks will be enabled in all your projects.')
  })
})

describe('on the card', () => {
  test('confirm_saves: the alert with the numbers, then the change', async () => {
    card(true)
    fireEvent.click(screen.getByRole('switch', { name: 'Enabled: HackTricks' }))
    await waitFor(() => expect(onToggleEnabled).toHaveBeenCalledWith(expect.objectContaining({ id: 'r1' }), false))
    expect(alerts.confirm).toHaveBeenCalledWith('HackTricks will be disabled in all your 7 projects.', ENABLED_ALERT_TITLE)
    expect(fetchMock.mock.calls[0][0]).toBe(`${IMPACT}?next=false`)
  })

  test('cancel_changes_nothing', async () => {
    alerts.confirm.mockResolvedValueOnce(false)
    card(false)
    fireEvent.click(screen.getByRole('switch', { name: 'Enabled: HackTricks' }))
    await waitFor(() => expect(alerts.confirm).toHaveBeenCalledWith(
      'HackTricks will be enabled in all your 7 projects, including the 2 where it was turned off.', ENABLED_ALERT_TITLE))
    expect(onToggleEnabled).not.toHaveBeenCalled()
  })

  test('numbers that cannot be read still ask, without them', async () => {
    fetchMock.mockImplementationOnce(async () => new Response('{}', { status: 500 }))
    card(true)
    fireEvent.click(screen.getByRole('switch', { name: 'Enabled: HackTricks' }))
    await waitFor(() => expect(alerts.confirm).toHaveBeenCalledWith('HackTricks will be disabled in all your projects.', ENABLED_ALERT_TITLE))
  })
})

describe('in the Edit form', () => {
  const draw = () => render(<ResourceFormV2 userId="user-1" resource={{ ...RESOURCE, name: 'HackTricks' }} onSaved={onSaved} onCancel={vi.fn()} />)
  const puts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT')

  test('confirm_saves: a change of Enabled asks first, then saves', async () => {
    draw()
    fireEvent.click(screen.getByRole('checkbox', { name: /Enabled \(the agent sees/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(alerts.confirm).toHaveBeenCalledWith('HackTricks will be disabled in all your 7 projects.', ENABLED_ALERT_TITLE)
    expect(JSON.parse(String((puts()[0][1] as RequestInit).body)).enabled).toBe(false)
  })

  test('cancel_changes_nothing: nothing is sent and the form stays open', async () => {
    alerts.confirm.mockResolvedValueOnce(false)
    draw()
    fireEvent.click(screen.getByRole('checkbox', { name: /Enabled \(the agent sees/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(alerts.confirm).toHaveBeenCalled())
    expect(puts()).toEqual([])
    expect(onSaved).not.toHaveBeenCalled()
  })

  test('a save that keeps Enabled as it was asks nothing', async () => {
    draw()
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Renamed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(alerts.confirm).not.toHaveBeenCalled()
  })
})
