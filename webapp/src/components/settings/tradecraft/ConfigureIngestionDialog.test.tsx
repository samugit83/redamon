/**
 * Configure ingestion (§3.2, T3.5): sections from the spec, changed markers, resets, inline and
 * server validation, the unsaved-changes guard and the live estimate (R-022 - R-025, R-076).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'

vi.mock('@/components/shared/ModelPicker', () => ({
  ModelPicker: ({ value, onChange }: { value: string; onChange: (v: string) => void }) =>
    <input aria-label="Default model for new resources" value={value} onChange={e => onChange(e.target.value)} />,
}))
const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}), alertError: vi.fn(async () => {}), alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true), dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui', async orig => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alertSpies }))

import { ConfigureIngestionDialog, DIALOG_SECTIONS, HIDDEN_KEYS, APPLIES_TEXT } from './ConfigureIngestionDialog'
import { SECTIONS, SETTINGS } from '@/lib/tradecraft/settingsSpec'
import { estimateText, estimateWebsite } from '@/lib/tradecraft/estimate'

const URL = '/api/users/user-1/tradecraft-settings'
const USER_DEFS = SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource')
const DEFAULTS = Object.fromEntries(USER_DEFS.map(s => [s.key, s.default]))
const view = (values: Record<string, unknown> = {}) => ({
  values: { ...DEFAULTS, ...values },
  changed: Object.keys(values),
  defaults: { ...DEFAULTS },
})

const fetchMock = vi.fn()
let getAnswer: { status: number; body: unknown }
let putAnswer: { status: number; body: unknown }
const onSaved = vi.fn()
const onClose = vi.fn()
const onDirtyChange = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  getAnswer = { status: 200, body: { v2Enabled: true, ingestion: view() } }
  putAnswer = { status: 200, body: { v2Enabled: true, ingestion: view({ 'crawl.maxPages': 120 }) } }
  fetchMock.mockImplementation(async (_url: string, init?: RequestInit) => {
    const a = init?.method === 'PUT' ? putAnswer : getAnswer
    return new Response(JSON.stringify(a.body), { status: a.status })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const renderDialog = () => render(
  <ConfigureIngestionDialog userId="user-1" onClose={onClose} onSaved={onSaved} onDirtyChange={onDirtyChange} />,
)
const nav = () => within(screen.getByRole('navigation', { name: 'Ingestion stages' }))
const open = (label: string) => fireEvent.click(nav().getByRole('button', { name: new RegExp(`^${label}`) }))
const field = (label: string) => screen.getByLabelText(label) as HTMLInputElement
const puts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT')
const sent = () => JSON.parse(String((puts()[0][1] as RequestInit).body))
const label = (id: string) => SECTIONS.find(s => s.id === id)!.label

describe('ConfigureIngestionDialog', () => {
  test('renders_every_section_from_spec: each stage, each of its user settings with label, help, default and range', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    expect(nav().getAllByRole('button').map(b => b.textContent)).toEqual(DIALOG_SECTIONS.map(label))
    for (const id of DIALOG_SECTIONS) {
      open(label(id))
      const pane = within(screen.getByRole('region', { name: label(id) }))
      for (const def of USER_DEFS.filter(d => d.section === id && !HIDDEN_KEYS.has(d.key))) {
        expect(pane.getAllByText(def.label).length).toBeGreaterThan(0)
        expect(pane.getAllByText(new RegExp(def.help.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).length).toBeGreaterThan(0)
      }
    }
    open('Website crawl')
    expect(screen.getByText(/Default: 200 pages\. Allowed: 1–500 pages\./)).toBeInTheDocument()
  })

  test('the focus defaults are the last section (T5.6); resource-only settings are not in the dialog', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    expect(nav().getAllByRole('button').at(-1)).toHaveTextContent('Ingestion focus')
    open('Website crawl')
    expect(screen.queryByText('Start pages')).toBeNull()
  })

  test('real_title_fields: "Use real page titles" and "Max title fetches" in Known site types, the limit used only when on (T6.10)', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    expect(HIDDEN_KEYS.size).toBe(0)
    open('Known site types')
    const pane = within(screen.getByRole('region', { name: 'Known site types' }))
    expect(pane.getByText('Real page titles')).toBeInTheDocument()
    const fetches = pane.getByLabelText('Max title fetches').closest('[data-setting]') as HTMLElement
    expect(within(fetches).getByText(/Used only when "Use real page titles" is on\./)).toBeInTheDocument()
    fireEvent.click(pane.getByLabelText('Use real page titles'))
    expect(within(fetches).queryByText(/Used only when "Use real page titles" is on\./)).toBeNull()
    fireEvent.change(pane.getByLabelText('Max title fetches'), { target: { value: '800' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(sent()).toEqual({ ingestion: { 'knownTypes.realTitles': true, 'knownTypes.maxTitleFetches': 800 } })
  })

  test('marks_changed: a field and its section are marked when the value differs from the default', async () => {
    getAnswer = { status: 200, body: { v2Enabled: true, ingestion: view({ 'summary.titles': 10 }) } }
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    expect(nav().getByRole('button', { name: /^Summary/ }).textContent).toContain('●')
    expect(nav().getByRole('button', { name: /^Website crawl/ }).textContent).not.toContain('●')
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '120' } })
    expect(nav().getByRole('button', { name: /^Website crawl/ }).textContent).toContain('●')
    const maxPages = field('Max pages visited').closest('[data-setting]')!
    expect(within(maxPages as HTMLElement).getByText('● changed')).toBeInTheDocument()
  })

  test('section_reset: the section goes back to its defaults, the others keep their edits, nothing is written', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '120' } })
    open('Summary')
    fireEvent.change(field('Page titles sent'), { target: { value: '10' } })
    open('Website crawl')
    fireEvent.click(screen.getByRole('button', { name: 'Reset Website crawl to defaults' }))
    expect(field('Max pages visited').value).toBe('200')
    open('Summary')
    expect(field('Page titles sent').value).toBe('10')
    expect(puts()).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: 'Reset to defaults' }))
    expect(field('Page titles sent').value).toBe('50')
  })

  test('save sends only the values that changed', async () => {
    getAnswer = { status: 200, body: { v2Enabled: true, ingestion: view({ 'summary.titles': 10 }) } }
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '120' } })
    fireEvent.change(field('Crawl strategy'), { target: { value: 'rules' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(sent()).toEqual({ ingestion: { 'crawl.maxPages': 120, 'crawl.strategy': 'rules' } })
  })

  test('validation_inline: an out-of-range value is named under its field and Save is disabled', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '9000' } })
    expect(screen.getByText('Must be an integer from 1 to 500')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(nav().getByRole('button', { name: /^Website crawl/ }).textContent).toContain('!')
    fireEvent.change(field('Max pages visited'), { target: { value: '' } })
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    fireEvent.change(field('Max pages visited'), { target: { value: '300' } })
    expect(screen.queryByText(/^Must be/)).toBeNull()
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  })

  test('server_error_on_field: the server\'s 400 shows on its field, in its section', async () => {
    putAnswer = {
      status: 400,
      body: {
        error: 'summary.titles must be an integer from 0 to 300', code: 'invalid_settings',
        errors: [{ key: 'summary.titles', code: 'bad_value', message: 'summary.titles must be an integer from 0 to 300' }],
      },
    }
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Summary')
    fireEvent.change(field('Page titles sent'), { target: { value: '20' } })
    open('Fetching')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('summary.titles must be an integer from 0 to 300')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Summary' })).toBeInTheDocument()
    expect(onSaved).not.toHaveBeenCalled()
    fireEvent.change(field('Page titles sent'), { target: { value: '21' } })
    expect(screen.queryByText('summary.titles must be an integer from 0 to 300')).toBeNull()
  })

  test('a failure that names no field shows in the footer with its code', async () => {
    putAnswer = { status: 500, body: { error: 'Failed to save the Tradecraft settings', code: 'P1001' } }
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '120' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/P1001/)).toBeInTheDocument()
    expect(onSaved).not.toHaveBeenCalled()
  })

  test('guards_unsaved: Cancel with edits asks first; declined keeps the dialog, confirmed closes it', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
    expect(alertSpies.confirm).not.toHaveBeenCalled()
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '120' } })
    await waitFor(() => expect(onDirtyChange).toHaveBeenLastCalledWith(true))
    alertSpies.confirm.mockResolvedValueOnce(false)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(alertSpies.confirm).toHaveBeenCalledTimes(1))
    expect(onClose).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Close modal' }))
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(2))
    expect(alertSpies.confirm).toHaveBeenCalledTimes(2)
  })

  test('estimate_updates: the headline and the binding limit follow the draft', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    const before = estimateText(estimateWebsite(DEFAULTS))
    expect(screen.getByTestId('ingestion-estimate').textContent).toBe(before.headline)
    expect(screen.getByText(before.stop)).toBeInTheDocument()
    open('Website crawl')
    fireEvent.change(field('Crawl strategy'), { target: { value: 'rules' } })
    const after = estimateText(estimateWebsite({ ...DEFAULTS, 'crawl.strategy': 'rules' }))
    expect(after.headline).not.toBe(before.headline)
    expect(screen.getByTestId('ingestion-estimate').textContent).toBe(after.headline)
    fireEvent.change(field('Max pages visited'), { target: { value: 'x' } })
    expect(screen.getByTestId('ingestion-estimate').textContent).toBe(after.headline)
  })

  test('a list setting adds and removes items; a setting used only with another one says so', async () => {
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Website crawl')
    fireEvent.change(field('Include paths'), { target: { value: '/writeups/*' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add to Include paths' }))
    expect(screen.getByRole('button', { name: 'Remove /writeups/*' })).toBeInTheDocument()
    expect(screen.getByText(/Used only when "When the LLM says stop"/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(sent()).toEqual({ ingestion: { 'crawl.includePaths': ['/writeups/*'] } })
  })
})

describe('Save & refresh all (§3.2, T6.10)', () => {
  const RES = [
    { id: 'r1', name: 'HackTricks', enabled: true }, { id: 'r2', name: 'Off', enabled: false }, { id: 'r3', name: 'Blog', enabled: true },
  ]
  const route = (refresh: { status: number; body: unknown }) => fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/users/user-1/tradecraft-resources') return new Response(JSON.stringify(RES), { status: 200 })
    if (url === '/api/users/user-1/tradecraft-resources/refresh-all') return new Response(JSON.stringify(refresh.body), { status: refresh.status })
    const a = init?.method === 'PUT' ? putAnswer : getAnswer
    return new Response(JSON.stringify(a.body), { status: a.status })
  })
  const STARTED = { bulkId: 'bulk-1', started: [{ resourceId: 'r1', name: 'HackTricks', job: { id: 'j1' } }], skipped: [{ resourceId: 'r3', name: 'Blog', reason: 'job_running' }] }

  test('confirmation_lists_ticked: the enabled resources; Confirm saves, then starts one batch of the ticked ones', async () => {
    route({ status: 202, body: STARTED })
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    open('Website crawl')
    fireEvent.change(field('Max pages visited'), { target: { value: '120' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save & refresh all' }))
    const confirm = within(await screen.findByRole('dialog', { name: 'Save & refresh all' }))
    expect(confirm.getAllByRole('checkbox').map(c => c.closest('label')!.textContent)).toEqual(['HackTricks', 'Blog'])
    expect(puts()).toEqual([])
    fireEvent.click(confirm.getByRole('checkbox', { name: 'Blog' }))
    fireEvent.click(confirm.getByRole('button', { name: 'Save & refresh 1' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(sent()).toEqual({ ingestion: { 'crawl.maxPages': 120 } })
    const post = fetchMock.mock.calls.find(c => c[0] === '/api/users/user-1/tradecraft-resources/refresh-all')!
    expect(JSON.parse(String((post[1] as RequestInit).body))).toEqual({ resourceIds: ['r1'] })
    expect(onSaved.mock.calls[0][1]).toEqual(STARTED)
  })

  test('Cancel in the confirmation saves nothing and starts nothing', async () => {
    route({ status: 202, body: STARTED })
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    fireEvent.click(screen.getByRole('button', { name: 'Save & refresh all' }))
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Save & refresh all' })).getByRole('button', { name: 'Cancel' }))
    expect(puts()).toEqual([])
    expect(fetchMock.mock.calls.some(c => String(c[0]).endsWith('/refresh-all'))).toBe(false)
  })

  test('a batch that does not start says the settings were saved and why', async () => {
    route({ status: 503, body: { error: 'The agent could not start the job', code: 'agent_unreachable' } })
    renderDialog()
    await screen.findByText(APPLIES_TEXT)
    fireEvent.click(screen.getByRole('button', { name: 'Save & refresh all' }))
    const confirm = within(await screen.findByRole('dialog', { name: 'Save & refresh all' }))
    fireEvent.click(confirm.getByRole('button', { name: 'Save & refresh 2' }))
    expect(await confirm.findByRole('alert')).toHaveTextContent(/Saved, but the refresh did not start: .*agent_unreachable/)
    expect(onSaved).not.toHaveBeenCalled()
  })
})
