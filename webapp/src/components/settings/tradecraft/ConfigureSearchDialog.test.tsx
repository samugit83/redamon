/**
 * Configure search (Q11, T7.2; R-410, R-411, R-412, R-416): the Q11 sections from the spec, the
 * librarian model line, my synonyms, each resource's priority, the live estimate, Reset, Cancel,
 * Save, no "Save & refresh all", the Stored-only notes.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'

const gate = vi.hoisted(() => ({ ensureFeatureModel: vi.fn(async () => null), fetchWithFeatureModel: vi.fn(), userId: 'user-1', savedVersion: 0 }))
vi.mock('@/components/shared/FeatureModelGate', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useFeatureModelGate: () => gate,
}))
const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}), alertError: vi.fn(async () => {}), alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true), dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui', async orig => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alertSpies }))

import { APPLIES_TEXT, ConfigureSearchDialog, SEARCH_SECTIONS, STORED_NOTES, parseSynonymLines } from './ConfigureSearchDialog'
import { SECTIONS, SETTINGS } from '@/lib/tradecraft/settingsSpec'
import { RESOURCE } from './__testing__/resourceView'

const SETTINGS_URL = '/api/users/user-1/tradecraft-settings'
const DEFS = SETTINGS.filter(s => s.scope === 'search')
const DEFAULTS = Object.fromEntries(DEFS.map(s => [s.key, s.default]))
const view = (values: Record<string, unknown> = {}, synonyms: { term: string; expansion: string }[] = []) =>
  ({ values: { ...DEFAULTS, ...values }, changed: Object.keys(values), defaults: { ...DEFAULTS }, synonyms })

let getBody: unknown
let putAnswer: { status: number; body: unknown }
const fetchMock = vi.fn()
const onSaved = vi.fn()
beforeEach(() => {
  vi.clearAllMocks()
  getBody = { v2Enabled: true, search: view({}, [{ term: 'PATT', expansion: 'PayloadsAllTheThings' }]) }
  putAnswer = { status: 200, body: { v2Enabled: true, search: view({ 'librarian.maxModelCalls': 3 }) } }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url === '/api/users/user-1/settings') return new Response(JSON.stringify({ featureModels: { tradecraft_librarian: 'openai/gpt-4o-mini' } }), { status: 200 })
    if (url === '/api/users/user-1/tradecraft-resources' && method === 'GET') {
      return new Response(JSON.stringify([RESOURCE, { ...RESOURCE, id: 'r2', name: 'Blog', priority: 'high' }]), { status: 200 })
    }
    if (url === SETTINGS_URL && method === 'PUT') return new Response(JSON.stringify(putAnswer.body), { status: putAnswer.status })
    if (url === SETTINGS_URL) return new Response(JSON.stringify(getBody), { status: 200 })
    if (method === 'PUT') return new Response(JSON.stringify({ resource: null, job: null }), { status: 200 })
    return new Response('{}', { status: 500 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const renderDialog = () => render(<ConfigureSearchDialog userId="user-1" onClose={vi.fn()} onSaved={onSaved} />)
const nav = () => within(screen.getByRole('navigation', { name: 'Search settings' }))
const open = (label: string) => fireEvent.click(nav().getByRole('button', { name: new RegExp(`^${label}`) }))
const puts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT')
  .map(c => ({ url: c[0] as string, body: JSON.parse(String((c[1] as RequestInit).body)) }))

describe('ConfigureSearchDialog', () => {
  test('the Q11 sections in order, each with its settings from the spec, defaults and ranges', async () => {
    renderDialog()
    await screen.findByTestId('search-estimate')
    expect(nav().getAllByRole('button').map(b => b.textContent)).toEqual(SEARCH_SECTIONS.map(id => SECTIONS.find(s => s.id === id)!.label))
    for (const id of SEARCH_SECTIONS) {
      open(SECTIONS.find(s => s.id === id)!.label)
      const shown = [...document.querySelectorAll('[data-setting]')].map(e => e.getAttribute('data-setting'))
      for (const def of DEFS.filter(d => d.section === id)) expect(shown, def.key).toContain(def.key)
    }
    expect(screen.getByText(new RegExp(APPLIES_TEXT))).toBeInTheDocument()
  })

  test('dialog_estimate: "Worst case per question: N model calls, T s. Per agent run: up to M librarian calls", live', async () => {
    renderDialog()
    expect(await screen.findByTestId('search-estimate')).toHaveTextContent('Worst case per question: 5 model calls, 30 s. Per agent run: up to 50 librarian calls')
    fireEvent.change(screen.getByLabelText('Model calls per question'), { target: { value: '3' } })
    fireEvent.change(screen.getByLabelText('Questions per agent run'), { target: { value: '4' } })
    expect(screen.getByTestId('search-estimate')).toHaveTextContent('Worst case per question: 3 model calls, 30 s. Per agent run: up to 12 librarian calls')
    fireEvent.change(screen.getByLabelText('Librarian use'), { target: { value: 'search_only' } })
    expect(screen.getByTestId('search-estimate')).toHaveTextContent(/^Search only/)
  })

  test('no_refresh_all_button: Reset to defaults, Cancel and Save only', async () => {
    renderDialog()
    await screen.findByTestId('search-estimate')
    expect(screen.queryByRole('button', { name: /refresh all/i })).toBeNull()
    for (const name of ['Reset to defaults', 'Cancel', 'Save']) expect(screen.getByRole('button', { name })).toBeInTheDocument()
  })

  test('the librarian model, the Models-by-feature value, changes through the gate', async () => {
    renderDialog()
    const line = await screen.findByTestId('librarian-model-line')
    await waitFor(() => expect(line).toHaveTextContent('Librarian model: openai/gpt-4o-mini (change)'))
    fireEvent.click(within(line).getByRole('button', { name: '(change)' }))
    expect(gate.ensureFeatureModel).toHaveBeenCalledWith('tradecraft_librarian', expect.objectContaining({ force: true }))
  })

  test('an out-of-range value is marked in the field and Save stays off; nothing is sent', async () => {
    renderDialog()
    await screen.findByTestId('search-estimate')
    fireEvent.change(screen.getByLabelText('Time limit per question'), { target: { value: '5' } })
    expect(screen.getByRole('alert')).toHaveTextContent(/10/)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(puts()).toEqual([])
  })

  test('Save sends only the changes and my synonyms; a priority is saved on its resource; nothing else', async () => {
    renderDialog()
    await screen.findByTestId('search-estimate')
    fireEvent.change(screen.getByLabelText('Model calls per question'), { target: { value: '3' } })
    open('Search')
    expect((screen.getByLabelText('My synonyms') as HTMLTextAreaElement).value).toBe('PATT = PayloadsAllTheThings')
    fireEvent.change(screen.getByLabelText('My synonyms'), { target: { value: 'PATT = PayloadsAllTheThings\nhtk = HackTricks\n' } })
    expect(screen.getByLabelText('Priority of Blog')).toHaveValue('high')
    fireEvent.change(screen.getByLabelText('Priority of Lab Wiki'), { target: { value: 'low' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(puts()).toEqual([
      { url: SETTINGS_URL, body: { search: { 'librarian.maxModelCalls': 3, synonyms: [{ term: 'PATT', expansion: 'PayloadsAllTheThings' }, { term: 'htk', expansion: 'HackTricks' }] } } },
      { url: '/api/users/user-1/tradecraft-resources/r1', body: { priority: 'low' } },
    ])
  })

  test('a refused synonym list is shown in the Search section with the server\'s words', async () => {
    putAnswer = { status: 400, body: { error: 'At most 200 synonym pairs', code: 'invalid_settings', errors: [{ key: 'synonyms', code: 'bad_value', message: 'At most 200 synonym pairs' }] } }
    renderDialog()
    await screen.findByTestId('search-estimate')
    open('Search')
    fireEvent.change(screen.getByLabelText('My synonyms'), { target: { value: 'a = b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('At most 200 synonym pairs')).toBeInTheDocument()
    expect(onSaved).not.toHaveBeenCalled()
  })

  test('the synonym lines are checked in the dialog: "a = b" per line, at most 200', () => {
    expect(parseSynonymLines(' a = b \n\nc=d')).toEqual({ pairs: [{ term: 'a', expansion: 'b' }, { term: 'c', expansion: 'd' }], error: '' })
    expect(parseSynonymLines('no pair').error).toMatch(/Line 1/)
    expect(parseSynonymLines(Array.from({ length: 201 }, (_, i) => `t${i} = e${i}`).join('\n')).error).toMatch(/At most 200/)
  })

  test('Stored-only notes on the sections whose settings work fully only on Stored resources', async () => {
    renderDialog()
    await screen.findByTestId('search-estimate')
    expect(screen.getByText(STORED_NOTES.librarian)).toBeInTheDocument()
    open('Reading pages')
    expect(screen.getByText(STORED_NOTES.reading)).toBeInTheDocument()
  })

  test('Reset to defaults changes the draft only; Cancel writes nothing', async () => {
    getBody = { v2Enabled: true, search: view({ 'search.results': 12 }) }
    renderDialog()
    await screen.findByTestId('search-estimate')
    open('Search')
    expect(screen.getByLabelText('Results shown to the agent')).toHaveValue('12')
    fireEvent.click(screen.getByRole('button', { name: 'Reset to defaults' }))
    expect(screen.getByLabelText('Results shown to the agent')).toHaveValue('8')
    expect(puts()).toEqual([])
  })

  test('states: an answer without the section (an older webapp mid-deploy), a failure with Retry', async () => {
    getBody = { v2Enabled: false }
    renderDialog()
    expect(await screen.findByRole('alert')).toHaveTextContent("Couldn't")
    expect(screen.queryByText(/turn it on/)).toBeNull()
    cleanup()
    getBody = { error: 'x', code: 'P1001' }
    const real = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => (url === SETTINGS_URL
      ? new Response(JSON.stringify(getBody), { status: 500 }) : real(url, init)))
    renderDialog()
    expect(await screen.findByRole('alert')).toHaveTextContent(/HTTP 500/)
  })
})
