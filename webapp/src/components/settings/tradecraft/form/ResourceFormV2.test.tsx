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
import { ACCOUNT } from '../__testing__/formHarness'
import { settingDef } from '@/lib/tradecraft/settingsSpec'
import type { IngestionSettingsView } from '@/lib/tradecraft/client'

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
    // The token override sits in the Access section (§6.4, §6.6, T6.11).
    fireEvent.click(screen.getByRole('button', { name: /^Access/ }))
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

describe('the full form (T4.6)', () => {
  const SETTINGS: IngestionSettingsView = { values: { ...ACCOUNT, 'summary.defaultModel': 'claude-small', 'storage.defaultMode': 'recommended' }, changed: [], defaults: ACCOUNT }
  const CHECK = '/api/users/user-1/tradecraft-resources/check-url'
  type Route = (url: string, init?: RequestInit) => Response | undefined
  function routes(...rs: Route[]) {
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      for (const r of rs) { const a = r(url, init); if (a) return a }
      return new Response(JSON.stringify({ resource: null, job: { id: 'j1' } }), { status: 201 })
    })
  }
  const checkAnswers = (result: Record<string, unknown>): Route => url => (url === CHECK
    ? new Response(JSON.stringify({ result: { ok: true, error_code: '', recommended_storage: 'live', estimated_bytes: 0, ...result } }), { status: 200 })
    : undefined)
  const renderFull = (resource = null as typeof RESOURCE | null, settings: IngestionSettingsView | null = SETTINGS) =>
    render(<AlertProvider><ResourceFormV2 userId="user-1" resource={resource} settings={settings} onSaved={onSaved} onCancel={vi.fn()} /></AlertProvider>)
  const sectionNames = () => screen.getAllByRole('region').map(r => r.getAttribute('aria-label'))
  const openAll = () => {
    for (const b of screen.getAllByRole('button', { expanded: false })) fireEvent.click(b)
  }
  const shown = () => [...document.querySelectorAll('[data-setting]')].map(e => e.getAttribute('data-setting')!)
  const bodyOf = (method: string, url: string) => {
    const call = fetchMock.mock.calls.find(c => c[0] === url && (c[1] as RequestInit | undefined)?.method === method)
    return call ? JSON.parse(String((call[1] as RequestInit).body)) : undefined
  }

  test('sections_by_type: no type section until the type is known; then the section of that type only', () => {
    renderFull()
    expect(sectionNames()).toEqual(['Site type', 'Focus', 'Access', 'Fetching', 'Content', 'Summary', 'Refreshing'])
    expect(screen.getByText(/Pick a type, or run Check URL/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^Site type/ }))
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'github-repo' } })
    expect(sectionNames()).toEqual(['Site type', 'Focus', 'GitHub repository', 'Access', 'Fetching', 'Content', 'Summary', 'Refreshing'])
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'pdf' } })
    expect(sectionNames()).toContain('PDF')
    expect(sectionNames()).not.toContain('GitHub repository')
    // A PDF is always Stored.
    expect(screen.getByRole('radio', { name: /Stored/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /Live/ })).toBeDisabled()
  })

  test('an edited resource shows the section of its detected type', () => {
    renderFull({ ...RESOURCE, resourceType: 'mkdocs-wiki' })
    expect(sectionNames()).toContain('Wiki')
  })

  test('no_user_only_fields: every section open, no user-only setting anywhere (R-133)', () => {
    for (const type of ['github-repo', 'cve-poc-db', 'mkdocs-wiki', 'gitbook', 'sphinx-docs', 'pdf', 'agentic-crawl']) {
      cleanup()
      renderFull({ ...RESOURCE, resourceType: type })
      openAll()
      const keys = shown()
      expect(keys.length, type).toBeGreaterThan(10)
      expect(keys.filter(k => settingDef(k)?.level === 'user'), type).toEqual([])
    }
  })

  test('prefills_default_model: the model and the storage default come from the account (R-139)', () => {
    renderFull(null, { ...SETTINGS, values: { ...SETTINGS.values, 'storage.defaultMode': 'stored' } })
    expect((screen.getByLabelText('Model') as HTMLInputElement).value).toBe('claude-small')
    expect(screen.getByRole('radio', { name: /Stored/ })).toBeChecked()
    cleanup()
    renderFull(null, null)
    expect((screen.getByLabelText('Model') as HTMLInputElement).value).toBe('')
    expect(screen.getByRole('radio', { name: /Live/ })).toBeChecked()
  })

  test('the Resource ID follows the name until edited, and is sent only when chosen', async () => {
    renderFull()
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'My Research Blog' } })
    expect((screen.getByLabelText('Resource ID') as HTMLInputElement).value).toBe('my-research-blog')
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://blog.tc-fixture.test/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(bodyOf('POST', BASE)).not.toHaveProperty('slug')
    cleanup()
    vi.clearAllMocks()
    renderFull()
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Blog' } })
    fireEvent.change(screen.getByLabelText('Resource ID'), { target: { value: 'Research' } })
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://blog.tc-fixture.test/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(bodyOf('POST', BASE)).toMatchObject({ slug: 'research', llmModel: 'claude-small' })
    cleanup()
    renderFull(RESOURCE)
    expect(screen.getByLabelText('Resource ID')).toHaveAttribute('readonly')
  })

  test('inherit_override: an override set in a section is sent; turning it off sends none', async () => {
    renderFull()
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Blog' } })
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://blog.tc-fixture.test/' } })
    fireEvent.click(screen.getByRole('button', { name: /^Fetching/ }))
    expect(screen.getByText('Using your setting: RedAmon-Tradecraft/1.0')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override Request timeout' }))
    fireEvent.change(screen.getByLabelText('Request timeout'), { target: { value: '60' } })
    expect(screen.getByRole('button', { name: /^Fetching/ })).toHaveTextContent('1 override')
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(bodyOf('POST', BASE).overrides).toEqual({ 'fetching.requestTimeoutSec': 60 })
  })

  test('an override out of range blocks the save, named under its field', async () => {
    renderFull()
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Blog' } })
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://blog.tc-fixture.test/' } })
    fireEvent.click(screen.getByRole('button', { name: /^Fetching/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Override Request timeout' }))
    fireEvent.change(screen.getByLabelText('Request timeout'), { target: { value: '900' } })
    expect(screen.getByText('Must be an integer from 5 to 120')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    expect(await screen.findByText('Some settings are out of range: see the marked fields')).toBeInTheDocument()
    expect(bodyOf('POST', BASE)).toBeUndefined()
  })

  test('check_url_prefills: the detected type\'s section appears, the CVE pattern is filled, the recommended storage taken', async () => {
    routes(checkAnswers({
      detected_type: 'cve-poc-db', cve_pattern: '{year}/{cve}.json', recommended_storage: 'live',
      index: { kind: 'github_tree', url: '', count: 9000 },
    }))
    renderFull()
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://github.com/org/cves' } })
    fireEvent.click(screen.getByRole('button', { name: /Check URL/ }))
    expect(await screen.findByRole('status')).toHaveTextContent(/CVE archive · 9,000 files/)
    expect(sectionNames()).toContain('CVE archive')
    expect(screen.getByRole('button', { name: /^CVE archive/ })).toHaveTextContent('1 override')
    expect(screen.getByRole('button', { name: /^Site type/ })).toHaveTextContent('Auto (detected: CVE archive)')
    expect(screen.getByRole('radio', { name: /Live/ })).toBeChecked()
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'CVEs' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(bodyOf('POST', BASE).overrides).toEqual({ 'type.cve.pathPatterns': ['{year}/{cve}.json'] })
  })

  test('preset_applies_settings: a pick fills the fields and its settings, records the preset, runs Check URL', async () => {
    routes(checkAnswers({ detected_type: 'agentic-crawl', recommended_storage: 'stored', index: { kind: 'sitemap', url: 'https://hexbrainai.com/sitemap.xml', count: 70 } }))
    renderFull()
    fireEvent.change(screen.getByLabelText('Quick add'), { target: { value: 'hexbrain' } })
    fireEvent.click(screen.getByText('HexBrain payloads'))
    expect((screen.getByPlaceholderText('HackTricks') as HTMLInputElement).value).toBe('HexBrain payloads')
    expect((screen.getByPlaceholderText('https://book.hacktricks.wiki') as HTMLInputElement).value).toBe('https://hexbrainai.com/payloads')
    await waitFor(() => expect(bodyOf('POST', CHECK)).toEqual({
      url: 'https://hexbrainai.com/payloads', forcedType: 'agentic-crawl',
      overrides: { 'crawl.strategy': 'auto', 'crawl.includePaths': { mode: 'add', items: ['/payloads/*'] }, 'crawl.stayInFolder': true },
    }))
    expect(screen.getByRole('button', { name: /^Website crawl/ })).toHaveTextContent('3 overrides')
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(bodyOf('POST', BASE)).toMatchObject({
      name: 'HexBrain payloads', presetKey: 'hexbrain-payloads', forcedType: 'agentic-crawl', storageMode: 'stored',
      overrides: { 'crawl.strategy': 'auto', 'crawl.includePaths': { mode: 'add', items: ['/payloads/*'] }, 'crawl.stayInFolder': true },
    })
  })

  test('save_and_reingest: Save writes the edit only; Save & re-ingest writes it, then refreshes', async () => {
    routes((url, init) => (init?.method === 'PUT' ? new Response(JSON.stringify({ resource: RESOURCE, job: null }), { status: 200 }) : undefined),
      url => (url.endsWith('/refresh') ? new Response(JSON.stringify({ job: { id: 'j9', kind: 'refresh', status: 'queued' } }), { status: 202 }) : undefined))
    renderFull({ ...RESOURCE, resourceType: 'agentic-crawl', overrides: { 'crawl.maxPages': 40 } })
    expect(screen.getByRole('button', { name: /^Website crawl/ })).toHaveTextContent('1 override')
    fireEvent.click(screen.getByRole('button', { name: /^Refreshing/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /Override When a refresh fails/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1))
    expect(bodyOf('PUT', `${BASE}/r1`)).toMatchObject({ forcedType: '', overrides: { 'crawl.maxPages': 40, 'refreshing.onFailure': 'keep' } })
    expect(fetchMock.mock.calls.some(c => String(c[0]).endsWith('/refresh'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Save & re-ingest' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(2))
    expect(onSaved).toHaveBeenLastCalledWith(expect.objectContaining({ job: expect.objectContaining({ id: 'j9' }) }))
  })

  test('states: without the account\'s settings the defaults show as inherited', () => {
    renderFull(null, null)
    fireEvent.click(screen.getByRole('button', { name: /^Fetching/ }))
    expect(screen.getAllByText('Using your setting: 30 s')).toHaveLength(2)
    expect(screen.getByText('Using your setting: 40,000 chars')).toBeInTheDocument()
  })

  describe('the focus (§6.14, T5.6)', () => {
    test('a new resource starts on the account\'s default mode; a focus is sent with the add', async () => {
      routes(url => (url.endsWith('/tradecraft-settings') ? new Response(JSON.stringify({ v2Enabled: true, recipes: [] }), { status: 200 }) : undefined),
        url => (url.endsWith('/attack-skills') ? new Response('[]', { status: 200 }) : undefined))
      renderFull(null, { ...SETTINGS, values: { ...SETTINGS.values, 'focus.defaultMode': 'focused', 'focus.defaultStrictness': 'strict' } })
      fill()
      fireEvent.click(screen.getByRole('button', { name: /^Focus/ }))
      expect((screen.getByLabelText('Focused') as HTMLInputElement).checked).toBe(true)
      fireEvent.click(screen.getByRole('button', { name: 'XSS' }))
      fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
      await waitFor(() => expect(onSaved).toHaveBeenCalled())
      expect(bodyOf('POST', BASE).focus).toEqual({ mode: 'focused', topics: ['xss'], kinds: [], keep: 'Pages about XSS.', skip: '', skipMode: 'add', strictness: 'strict' })
    })

    test('an edit sends the saved focus back; Everything sends none', async () => {
      routes((url, init) => (init?.method === 'PUT' ? new Response(JSON.stringify({ resource: RESOURCE, job: null }), { status: 200 }) : undefined),
        url => (url.endsWith('/tradecraft-settings') ? new Response(JSON.stringify({ v2Enabled: true, recipes: [] }), { status: 200 }) : undefined),
        url => (url.endsWith('/attack-skills') ? new Response('[]', { status: 200 }) : undefined))
      const saved = { mode: 'focused', topics: ['ssrf'], kinds: ['poc'], keep: 'k', skip: '', skipMode: 'add', strictness: 'balanced' }
      renderFull({ ...RESOURCE, resourceType: 'agentic-crawl', focus: saved })
      expect(screen.getByRole('button', { name: /^Focus/ })).toHaveTextContent('Focused: 1 topic, 1 content type')
      fireEvent.click(screen.getByRole('button', { name: /^Focus/ }))
      fireEvent.click(screen.getByLabelText('Everything'))
      fireEvent.click(screen.getByRole('button', { name: 'Save' }))
      await waitFor(() => expect(onSaved).toHaveBeenCalled())
      expect(bodyOf('PUT', `${BASE}/r1`).focus).toEqual({})
    })

    test('a resource being added previews the entries Check URL found, with the model picked in the form', async () => {
      routes(checkAnswers({ detected_type: 'agentic-crawl', index: { kind: 'sitemap', url: 'https://wiki.tc-fixture.test/sitemap.xml', count: 250 },
        sample_entries: [{ url: 'https://wiki.tc-fixture.test/a', title: 'A' }, { url: 'https://wiki.tc-fixture.test/b', title: 'B' }] }),
      url => (url.endsWith('/focus-preview')
        ? new Response(JSON.stringify({ result: { kept: 1, maybe: 0, dropped: 1, examples: [], llm_calls: 1, error_code: '' } }), { status: 200 })
        : undefined),
      url => (url.endsWith('/tradecraft-settings') ? new Response(JSON.stringify({ v2Enabled: true, recipes: [] }), { status: 200 }) : undefined),
      url => (url.endsWith('/attack-skills') ? new Response('[]', { status: 200 }) : undefined))
      renderFull()
      fill()
      fireEvent.click(screen.getByRole('button', { name: /Check URL/ }))
      await screen.findByRole('status')
      fireEvent.click(screen.getByRole('button', { name: /^Focus/ }))
      fireEvent.click(screen.getByLabelText('Focused'))
      fireEvent.click(screen.getByRole('button', { name: 'XSS' }))
      expect(screen.getByText('Estimated cost: title triage ≈ 3 small LLM calls · content checks up to 100 calls')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /Preview on 100 pages/ }))
      expect(await screen.findByText('Would keep 1, drop 1 of 2 pages')).toBeInTheDocument()
      expect(bodyOf('POST', `${BASE}/focus-preview`)).toMatchObject({
        llmModel: 'gpt-4o', entries: [{ url: 'https://wiki.tc-fixture.test/a', title: 'A' }, { url: 'https://wiki.tc-fixture.test/b', title: 'B' }],
      })
    })

    test('hidden_for_cve: a CVE archive shows no Focus section and sends no focus', async () => {
      renderFull({ ...RESOURCE, resourceType: 'cve-poc-db', focus: { mode: 'focused', topics: ['xss'] } })
      expect(sectionNames()).not.toContain('Focus')
    })

    test('the preview samples the saved map with the form\'s model', async () => {
      routes(url => (url.endsWith('/focus-preview')
        ? new Response(JSON.stringify({ result: { kept: 3, maybe: 0, dropped: 9, examples: [], llm_calls: 1, error_code: '' } }), { status: 200 })
        : undefined),
      url => (url.endsWith('/tradecraft-settings') ? new Response(JSON.stringify({ v2Enabled: true, recipes: [] }), { status: 200 }) : undefined),
      url => (url.endsWith('/attack-skills') ? new Response('[]', { status: 200 }) : undefined))
      renderFull({ ...RESOURCE, resourceType: 'agentic-crawl', entryCount: 12, focus: { mode: 'focused', topics: ['xss'] } })
      fireEvent.click(screen.getByRole('button', { name: /^Focus/ }))
      expect(screen.getByText('Estimated cost: title triage ≈ 1 small LLM call · content checks up to 12 calls')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /Preview on 100 pages/ }))
      expect(await screen.findByText('Would keep 3, drop 9 of 12 pages')).toBeInTheDocument()
      expect(bodyOf('POST', `${BASE}/focus-preview`)).toMatchObject({ resourceId: 'r1', llmModel: 'm', focus: { mode: 'focused', topics: ['xss'] } })
    })
  })
})
