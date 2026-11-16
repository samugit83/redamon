/**
 * Configure ingestion's "Ingestion focus" section (§4.8, T5.6; R-101): the default mode (Tag only
 * shown, disabled until content checks), the default strictness, Always skip, the content-check
 * limit, Tag every page, saved with the dialog's Save; and the account's recipes, renamed or
 * deleted at once.
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

import { ConfigureIngestionDialog } from '../ConfigureIngestionDialog'
import { TAG_ONLY_SOON } from '../form/FocusSection'
import { SETTINGS } from '@/lib/tradecraft/settingsSpec'

const USER_DEFS = SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource')
const DEFAULTS = Object.fromEntries(USER_DEFS.map(s => [s.key, s.default]))
const VIEW = { values: { ...DEFAULTS }, changed: [], defaults: { ...DEFAULTS } }
const RECIPES = [{ id: 'rcp1', name: 'My SQLi', topics: ['sql_injection'], kinds: ['poc'] }, { id: 'rcp2', name: 'Cloud', topics: ['cloud'], kinds: [] }]

const fetchMock = vi.fn()
const puts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT').map(c => JSON.parse(String((c[1] as RequestInit).body)))

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock.mockImplementation(async (_url: string, init?: RequestInit) => {
    if (init?.method !== 'PUT') return new Response(JSON.stringify({ v2Enabled: true, ingestion: VIEW, recipes: RECIPES }), { status: 200 })
    const body = JSON.parse(String(init.body))
    if (body.ingestion) return new Response(JSON.stringify({ v2Enabled: true, ingestion: { ...VIEW, values: { ...VIEW.values, ...body.ingestion } } }), { status: 200 })
    if (body.recipes?.rename) return new Response(JSON.stringify({ v2Enabled: true, recipes: [{ ...RECIPES[0], name: body.recipes.rename.name }, RECIPES[1]] }), { status: 200 })
    if (body.recipes?.delete) return new Response(JSON.stringify({ v2Enabled: true, recipes: RECIPES.filter(r => r.id !== body.recipes.delete) }), { status: 200 })
    return new Response('{}', { status: 400 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function openFocus() {
  render(<ConfigureIngestionDialog userId="user-1" onClose={vi.fn()} onSaved={vi.fn()} />)
  const nav = within(await screen.findByRole('navigation', { name: 'Ingestion stages' }))
  fireEvent.click(nav.getByRole('button', { name: /^Ingestion focus/ }))
  return within(screen.getByRole('region', { name: 'Ingestion focus' }))
}

describe('FocusDefaultsSection', () => {
  test('defaults_section: the five defaults with their help, Tag only disabled; a change saved with the dialog', async () => {
    const pane = await openFocus()
    for (const key of ['focus.defaultMode', 'focus.defaultStrictness', 'focus.alwaysSkip', 'focus.maxContentChecks', 'focus.tagEveryPage']) {
      expect(pane.getAllByText(USER_DEFS.find(d => d.key === key)!.label).length, key).toBeGreaterThan(0)
    }
    expect(pane.getByLabelText('Tag only')).toBeDisabled()
    expect(pane.getByText(TAG_ONLY_SOON)).toBeInTheDocument()
    expect((pane.getByLabelText('Everything') as HTMLInputElement).checked).toBe(true)
    fireEvent.click(pane.getByLabelText('Focused'))
    fireEvent.change(pane.getByLabelText('Always skip'), { target: { value: 'news, job posts' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(puts()[0]).toEqual({ ingestion: { 'focus.defaultMode': 'focused', 'focus.alwaysSkip': 'news, job posts' } })
  })

  test('my recipes: listed with their chips; renamed and deleted at once, outside the dialog\'s Save', async () => {
    const pane = await openFocus()
    const list = within(pane.getByRole('list', { name: 'My recipes' }))
    expect(list.getByText('My SQLi')).toBeInTheDocument()
    expect(list.getByText('SQL injection · PoC / exploit code')).toBeInTheDocument()
    fireEvent.click(list.getAllByRole('button', { name: 'Rename' })[0])
    fireEvent.change(list.getByLabelText('New name of My SQLi'), { target: { value: 'SQLi exploits' } })
    fireEvent.click(list.getByRole('button', { name: 'Save name' }))
    expect(await list.findByText('SQLi exploits')).toBeInTheDocument()
    fireEvent.click(list.getAllByRole('button', { name: 'Delete' })[1])
    await waitFor(() => expect(list.queryByText('Cloud')).toBeNull())
    expect(puts()).toEqual([{ recipes: { rename: { id: 'rcp1', name: 'SQLi exploits' } } }, { recipes: { delete: 'rcp2' } }])
  })

  test('no recipe yet: says how to make one', async () => {
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({ v2Enabled: true, ingestion: VIEW, recipes: [] }), { status: 200 }))
    const pane = await openFocus()
    expect(pane.getByText(/Save one from a resource's Focus section/)).toBeInTheDocument()
  })
})
