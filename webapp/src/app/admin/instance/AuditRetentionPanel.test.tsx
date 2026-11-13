/**
 * The audit retention panel of the Instance page (step 6.6; AU-04, OQ-40; E2E P6-05's Root half;
 * DV-06, DV-19): every administrator reads the retention in force and a change waiting its date, read
 * only with "Only Root changes these settings."; the confirmed Root asks for a new one (forever, or
 * days from the 90-day floor up, refused below it before anything is sent) with its password, and may
 * cancel a waiting change. The route decides; the panel sends `auditRetentionDays` with the password.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/AuditRetentionPanel.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { AuditRetentionPanel, retentionOf } from './AuditRetentionPanel'
import type { InstanceSettingsView } from './instanceView'

const RETENTION = { days: null, pending: null, minDays: 90, delayDays: 7 }
const PENDING = { days: 120, requestedAt: '2026-11-13T12:00:00.000Z', effectiveAt: '2026-11-20T12:00:00.000Z' }

let fetchMock: ReturnType<typeof vi.fn>
let answer: (body: Record<string, unknown>) => Response
const onSaved = vi.fn()

beforeEach(() => {
  onSaved.mockReset()
  answer = (body) => new Response(JSON.stringify({
    securityPolicy: {}, canManageAuditRetention: true,
    auditRetention: body.auditRetentionDays === null ? RETENTION : { ...RETENTION, pending: { ...PENDING, days: body.auditRetentionDays } },
  }), { status: 200 })
  fetchMock = vi.fn(async (_url: string, init?: RequestInit) => answer(JSON.parse(String(init?.body))))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPanel(settings: InstanceSettingsView, unconfirmedRoot = false) {
  return render(<ToastProvider><AuditRetentionPanel settings={settings} unconfirmedRoot={unconfirmedRoot} onSaved={onSaved} /></ToastProvider>)
}

const sent = () => JSON.parse(String(fetchMock.mock.calls.at(-1)![1]!.body))

async function confirmWithPassword(password = 'root-password') {
  fireEvent.change(await screen.findByLabelText('Your password'), { target: { value: password } })
  const submit = within(screen.getByRole('dialog')).getAllByRole('button').find((b) => b.getAttribute('type') === 'submit')!
  fireEvent.click(submit)
}

describe('what an administrator reads', () => {
  test('the retention in force and a waiting change with its date, read only, with why', () => {
    renderPanel({ auditRetention: { ...RETENTION, days: 365, pending: PENDING }, canManageAuditRetention: false })
    const panel = screen.getByRole('region', { name: 'Audit retention' })
    expect(within(panel).getByText('Deleted after 365 days')).toBeInTheDocument()
    expect(within(panel).getByRole('status')).toHaveTextContent(/Change waiting: deleted after 120 days from/)
    expect(within(panel).getByRole('note')).toHaveTextContent('Only Root changes these settings.')
    expect(within(panel).queryByRole('button')).toBeNull()
    expect(within(panel).queryByRole('textbox')).toBeNull()
  })

  test('an unconfirmed Root is told how it becomes able to change it', () => {
    renderPanel({ auditRetention: RETENTION, canManageAuditRetention: false }, true)
    expect(screen.getByRole('note')).toHaveTextContent(/chosen automatically/)
    expect(screen.getByText('Kept forever')).toBeInTheDocument()
  })

  test('without the retention in the settings (switch off) the panel renders nothing', () => {
    const { container } = renderPanel({ securityPolicy: {} })
    expect(container).toBeEmptyDOMElement()
    expect(retentionOf(null)).toBeNull()
    expect(retentionOf({ auditRetention: { days: 5 } })).toBeNull()
  })
})

describe('retention floor (P6-05: 30 refused before anything is sent)', () => {
  test('under 90 days, a fraction or empty: the field says why and Ask stays disabled', () => {
    renderPanel({ auditRetention: RETENTION, canManageAuditRetention: true })
    fireEvent.click(screen.getByLabelText('For a number of days'))
    const field = screen.getByLabelText('Days to keep audit rows')
    const ask = screen.getByRole('button', { name: 'Ask for this retention' })
    for (const value of ['30', '89', '120.5', '']) {
      fireEvent.change(field, { target: { value } })
      expect(field).toHaveAttribute('aria-invalid', 'true')
      expect(screen.getByText(/A whole number of days from 90/)).toBeInTheDocument()
      expect(ask).toBeDisabled()
    }
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('pending change applies after 7 days (P6-05: Root asks for 120)', () => {
  test('Root asks for 120 days with its password: the panel sends it and shows the change waiting', async () => {
    renderPanel({ auditRetention: RETENTION, canManageAuditRetention: true })
    fireEvent.click(screen.getByLabelText('For a number of days'))
    fireEvent.change(screen.getByLabelText('Days to keep audit rows'), { target: { value: '120' } })
    fireEvent.click(screen.getByRole('button', { name: 'Ask for this retention' }))
    expect(await screen.findByText(/from 7 days after now; until then nothing changes and you can cancel/)).toBeInTheDocument()
    await confirmWithPassword()
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1))
    expect(sent()).toEqual({ auditRetentionDays: 120, stepUpPassword: 'root-password' })
    expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/instance-settings')
    expect(onSaved.mock.calls[0][0].auditRetention.pending).toMatchObject({ days: 120 })
  })

  test('back to forever is sent as null', async () => {
    renderPanel({ auditRetention: { ...RETENTION, days: 365 }, canManageAuditRetention: true })
    fireEvent.click(screen.getByLabelText('Forever'))
    fireEvent.click(screen.getByRole('button', { name: 'Ask for this retention' }))
    await confirmWithPassword()
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(sent()).toEqual({ auditRetentionDays: null, stepUpPassword: 'root-password' })
  })

  test('a waiting change: Cancel sends the value in force; asking again for the waiting value is not offered', async () => {
    renderPanel({ auditRetention: { ...RETENTION, days: 365, pending: PENDING }, canManageAuditRetention: true })
    fireEvent.change(screen.getByLabelText('Days to keep audit rows'), { target: { value: '120' } })
    expect(screen.getByRole('button', { name: 'Ask for this retention' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel the waiting change' }))
    expect(await screen.findByText(/stays deleted after 365 days/)).toBeInTheDocument()
    await confirmWithPassword()
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(sent()).toEqual({ auditRetentionDays: 365, stepUpPassword: 'root-password' })
  })

  test("the route's refusal stays in the dialog with its reason; nothing is shown as saved", async () => {
    answer = () => new Response(JSON.stringify({ error: 'Password is incorrect', code: 'step_up_failed' }), { status: 403 })
    renderPanel({ auditRetention: RETENTION, canManageAuditRetention: true })
    fireEvent.click(screen.getByLabelText('For a number of days'))
    fireEvent.change(screen.getByLabelText('Days to keep audit rows'), { target: { value: '120' } })
    fireEvent.click(screen.getByRole('button', { name: 'Ask for this retention' }))
    await confirmWithPassword('wrong')
    expect(await screen.findByText(/Password is incorrect/)).toBeInTheDocument()
    expect(onSaved).not.toHaveBeenCalled()
  })
})

describe('labels and keyboard', () => {
  test('the choice is a labelled group of radios, the days field has its hint; nothing leaves the tab order', () => {
    const { container } = renderPanel({ auditRetention: RETENTION, canManageAuditRetention: true })
    expect(screen.getByRole('group', { name: 'Keep audit rows' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Forever' })).toBeChecked()
    fireEvent.click(screen.getByRole('radio', { name: 'For a number of days' }))
    expect(screen.getByLabelText('Days to keep audit rows')).toHaveAttribute('aria-describedby', 'retention-days-hint')
    expect(container.querySelectorAll('[tabindex="-1"]')).toHaveLength(0)
  })
})
