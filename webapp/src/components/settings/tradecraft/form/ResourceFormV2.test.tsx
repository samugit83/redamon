/**
 * The basic 2.0 form (§6.4): storage choice with its notes, the corrected model help, no cache TTL.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

vi.mock('@/components/shared/ModelPicker', () => ({
  ModelPicker: ({ value, onChange }: { value: string; onChange: (v: string) => void }) =>
    <input aria-label="Model" value={value} onChange={e => onChange(e.target.value)} />,
}))

import { AlertProvider } from '@/components/ui'
import { LIVE_NOTE, MODEL_HELP, ResourceFormV2, STORED_NOTE } from './ResourceFormV2'
import { RESOURCE } from '../__testing__/resourceView'

const fetchMock = vi.fn()
const onSaved = vi.fn()
const BASE = '/api/users/user-1/tradecraft-resources'

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ resource: null, job: { id: 'j1' } }), { status: 201 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const renderForm = (resource = null as typeof RESOURCE | null) =>
  render(<AlertProvider><ResourceFormV2 userId="user-1" resource={resource} onSaved={onSaved} onCancel={vi.fn()} /></AlertProvider>)
const fill = () => {
  fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Lab Wiki' } })
  fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://wiki.tc-fixture.test/' } })
  fireEvent.change(screen.getByLabelText('Model'), { target: { value: 'gpt-4o' } })
}
const sent = () => JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))

describe('ResourceFormV2', () => {
  test('storage_choice: Live by default, Stored when picked, sent with the add', async () => {
    renderForm()
    fill()
    expect(screen.getByRole('radio', { name: /Live/ })).toBeChecked()
    fireEvent.click(screen.getByRole('radio', { name: /Stored/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][0]).toBe(BASE)
    expect(sent()).toEqual({ name: 'Lab Wiki', url: 'https://wiki.tc-fixture.test/', llmModel: 'gpt-4o', enabled: true, storageMode: 'stored' })
  })

  test('stored_note: the note next to Stored, and what Live costs (OQ-23, §4.5)', () => {
    renderForm()
    expect(screen.getByText(new RegExp(STORED_NOTE.replace(/[.']/g, '.')))).toBeInTheDocument()
    expect(STORED_NOTE).toBe("Stored keeps a copy of each page in your RedAmon database. Respect the site's terms of use.")
    expect(screen.getByText(LIVE_NOTE)).toBeInTheDocument()
  })

  test('model_help_text: the model ingests, it is not used while the agent runs (R-198)', () => {
    renderForm()
    expect(screen.getByText(MODEL_HELP)).toBeInTheDocument()
    expect(MODEL_HELP).toBe('Used to ingest this resource: crawl decisions, page triage and the summary. It is not used while the agent runs.')
    expect(document.body.textContent).not.toMatch(/agent runtime/i)
  })

  test('no_cache_ttl: no cache lifetime field, none sent (R-143)', async () => {
    renderForm()
    expect(screen.queryByText(/cache/i)).toBeNull()
    expect(screen.queryByLabelText(/TTL/i)).toBeNull()
    fill()
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(sent()).not.toHaveProperty('cacheTtlSec')
  })

  test('edit: a new URL says it re-ingests; the token is sent only when typed', async () => {
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({ resource: null, job: null }), { status: 200 }))
    renderForm({ ...RESOURCE, githubTokenOverride: 'set' })
    expect(screen.getByPlaceholderText(/A token is set/)).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://wiki2.tc-fixture.test/' } })
    expect(screen.getByText('Saving a new URL ingests the resource again.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save & re-ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/r1`)
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('PUT')
    expect(sent()).not.toHaveProperty('githubTokenOverride')
  })

  test('Stored → Live warns that the stored pages go now', () => {
    renderForm({ ...RESOURCE, storageMode: 'stored' })
    fireEvent.click(screen.getByRole('radio', { name: /Live/ }))
    expect(screen.getByRole('note')).toHaveTextContent('Saving deletes the stored pages now.')
  })

  test('a refusal stays in the form with its reason and code', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'A job is running for this resource', code: 'job_running' }), { status: 409 }))
    renderForm(RESOURCE)
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://wiki2.tc-fixture.test/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save & re-ingest' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/job_running/)
    expect(onSaved).not.toHaveBeenCalled()
  })
})
