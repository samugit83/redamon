/**
 * The Focus section of the resource form (§6.14 "What the user sets", T5.6; R-175): the mode
 * (Tag only enabled by T6.11), the built-in and the owner's recipes, topic and
 * content-type chips (the owner's skills among the topics), Keep and Skip written by the chips and
 * editable up to 1,000 characters, Skip added to or replacing "Always skip", strictness, the
 * preview of 100 entries with its counts and reasons, the cost estimate, Save as recipe. Hidden
 * for a CVE archive.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { useState } from 'react'
import { FocusSection, TAG_ONLY_NOTE } from './FocusSection'
import { EMPTY_FOCUS, type Focus } from '@/lib/tradecraft/focus'

const fetchMock = vi.fn()
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const latest: { focus: Focus | null } = { focus: null }
const RECIPES = [{ id: 'rcp1', name: 'My SQLi', topics: ['sql_injection'], kinds: ['poc'] }]
const PREVIEW = {
  kept: 1, maybe: 0, dropped: 1, llm_calls: 1, error_code: '',
  examples: [
    { url: 'https://wiki.tc-fixture.test/sqli', title: 'SQL injection payloads', decision: 'keep', reason: 'payloads for the focus', topics: ['sql_injection'], kinds: ['payloads'] },
    { url: 'https://wiki.tc-fixture.test/news', title: 'Company news', decision: 'drop', reason: 'news', topics: [], kinds: [] },
  ],
}

function routes(url: string, init?: RequestInit) {
  if (url.endsWith('/tradecraft-settings') && (!init || !init.method || init.method === 'GET')) {
    return answer(200, { v2Enabled: true, recipes: RECIPES })
  }
  if (url.endsWith('/tradecraft-settings') && init?.method === 'PUT') {
    const edit = JSON.parse(String(init.body)).recipes
    return answer(200, { v2Enabled: true, recipes: [...RECIPES, { id: 'rcp2', ...edit.add }] })
  }
  if (url.endsWith('/attack-skills')) return answer(200, [{ id: 's1', name: 'GraphQL abuse' }])
  if (url.endsWith('/focus-preview')) return answer(200, { result: PREVIEW })
  return answer(404, { error: 'no' })
}

function Host({ initial = { ...EMPTY_FOCUS, topics: [], kinds: [] }, siteType = 'agentic-crawl', entryCount = 4800, preview = { resourceId: 'r1' } as never }: {
  initial?: Focus; siteType?: string; entryCount?: number | null; preview?: never
}) {
  const [focus, setFocus] = useState<Focus>(initial)
  latest.focus = focus
  return (
    <FocusSection
      userId="user-1" focus={focus} onChange={setFocus} siteType={siteType} alwaysSkip="marketing" maxContentChecks={100}
      entryCount={entryCount} preview={preview}
    />
  )
}

const openSection = () => fireEvent.click(screen.getByRole('button', { name: /^Focus/ }))
const chip = (name: string) => screen.getByRole('button', { name })
const keep = () => screen.getByLabelText('Keep') as HTMLTextAreaElement
const skip = () => screen.getByLabelText('Skip') as HTMLTextAreaElement
const focused = async () => {
  openSection()
  fireEvent.click(screen.getByLabelText('Focused'))
  await screen.findByRole('button', { name: 'My SQLi' })
}

beforeEach(() => {
  vi.clearAllMocks()
  latest.focus = null
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => routes(url, init))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('FocusSection', () => {
  test('the mode: Everything shows nothing else', () => {
    render(<Host />)
    expect(screen.getByRole('button', { name: /^Focus/ })).toHaveTextContent('Everything')
    openSection()
    expect((screen.getByLabelText('Everything') as HTMLInputElement).checked).toBe(true)
    expect(screen.queryByLabelText('Keep')).toBeNull()
    expect(screen.queryByText(TAG_ONLY_NOTE)).toBeNull()
  })

  test('tag_only_enabled: Tag only can be chosen (T6.11, AC-12), with its words; it is saved as tagOnly', () => {
    render(<Host />)
    openSection()
    expect(screen.getByLabelText('Tag only')).toBeEnabled()
    fireEvent.click(screen.getByLabelText('Tag only'))
    expect(latest.focus).toMatchObject({ mode: 'tagOnly' })
    expect(screen.getByText(TAG_ONLY_NOTE)).toBeInTheDocument()
  })

  test('chips_write_keep_skip: the chips write Keep; an edited Keep stays the person\'s', async () => {
    render(<Host />)
    await focused()
    fireEvent.click(chip('SQL injection'))
    fireEvent.click(chip('Payloads & cheat sheets'))
    expect(chip('SQL injection')).toHaveAttribute('aria-pressed', 'true')
    expect(keep().value).toBe('Pages about SQL injection: payloads & cheat sheets.')
    fireEvent.change(keep(), { target: { value: 'Blind SQL injection only' } })
    fireEvent.click(chip('XSS'))
    expect(keep().value).toBe('Blind SQL injection only')
    expect(latest.focus).toMatchObject({ mode: 'focused', topics: ['sql_injection', 'xss'], kinds: ['payloads'], keep: 'Blind SQL injection only' })
    fireEvent.change(skip(), { target: { value: 'News' } })
    fireEvent.change(screen.getByLabelText('Skip mode'), { target: { value: 'replace' } })
    expect(latest.focus).toMatchObject({ skip: 'News', skipMode: 'replace' })
  })

  test('recipe_fills_chips: a built-in recipe and one of the owner\'s fill the chips, which stay editable', async () => {
    render(<Host />)
    await focused()
    fireEvent.click(chip('Web payload library'))
    expect(latest.focus).toMatchObject({ recipe: 'web_payload_library', topics: ['sql_injection', 'xss', 'ssrf', 'xxe'], kinds: ['payloads', 'bypasses'] })
    fireEvent.click(chip('My SQLi'))
    expect(latest.focus).toMatchObject({ recipe: 'rcp1', topics: ['sql_injection'], kinds: ['poc'] })
    fireEvent.click(chip('SQL injection'))
    expect(latest.focus!.topics).toEqual([])
  })

  test('the owner\'s skills are topics too', async () => {
    render(<Host />)
    await focused()
    fireEvent.click(await screen.findByRole('button', { name: 'GraphQL abuse' }))
    expect(latest.focus!.topics).toEqual(['user_skill:s1'])
    expect(keep().value).toBe('Pages about GraphQL abuse.')
  })

  test('a deleted skill still in the focus is shown, pressed, and removable (review E)', async () => {
    render(<Host initial={{ ...EMPTY_FOCUS, mode: 'focused', topics: ['xss', 'user_skill:gone', 'user_skill:s1'], kinds: [] }} />)
    openSection()
    const stale = await screen.findByRole('button', { name: 'Deleted skill (gone)' })
    expect(stale).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'GraphQL abuse' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(stale)
    expect(latest.focus!.topics).toEqual(['xss', 'user_skill:s1'])
    expect(screen.queryByRole('button', { name: 'Deleted skill (gone)' })).toBeNull()
  })

  test('limits_1000: Keep and Skip stop at 1,000 characters, with a counter', async () => {
    render(<Host />)
    await focused()
    fireEvent.change(keep(), { target: { value: 'k'.repeat(1200) } })
    expect(latest.focus!.keep).toHaveLength(1000)
    expect(screen.getByText('1000 / 1000')).toBeInTheDocument()
    fireEvent.change(skip(), { target: { value: 's'.repeat(1001) } })
    expect(latest.focus!.skip).toHaveLength(1000)
  })

  test('hidden_for_cve: no Focus section for a CVE archive', () => {
    render(<Host siteType="cve-poc-db" />)
    expect(screen.queryByRole('button', { name: /^Focus/ })).toBeNull()
  })

  test('preview_shows_counts: Preview on 100 sends the focus with the sample and shows counts, examples and reasons', async () => {
    render(<Host />)
    await focused()
    fireEvent.click(chip('SQL injection'))
    fireEvent.click(screen.getByRole('button', { name: /Preview on 100 pages/ }))
    expect(await screen.findByText('Would keep 1, drop 1 of 2 pages')).toBeInTheDocument()
    const list = within(screen.getByRole('list', { name: 'Preview examples' }))
    expect(list.getByText(/SQL injection payloads/)).toHaveTextContent('keep')
    expect(list.getByText(/Company news/)).toHaveTextContent('drop: news')
    const call = fetchMock.mock.calls.find(c => String(c[0]).endsWith('/focus-preview'))!
    expect(JSON.parse(String((call[1] as RequestInit).body))).toEqual({
      resourceId: 'r1', focus: { mode: 'focused', topics: ['sql_injection'], kinds: [], keep: 'Pages about SQL injection.', skip: '', skipMode: 'add', strictness: 'balanced' },
    })
  })

  test('the preview is offered only once there is a page list to sample', async () => {
    render(<Host preview={null as never} entryCount={null} />)
    await focused()
    expect(screen.getByRole('button', { name: /Preview on 100 pages/ })).toBeDisabled()
    expect(screen.getByText(/Run Check URL first/)).toBeInTheDocument()
  })

  test('a failed preview says why', async () => {
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => (String(url).endsWith('/focus-preview')
      ? answer(504, { error: 'The preview took too long', code: 'timeout' })
      : routes(url, init)))
    render(<Host />)
    await focused()
    fireEvent.click(screen.getByRole('button', { name: /Preview on 100 pages/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/timeout · HTTP 504/)
  })

  test('cost_estimate: the title triage and the content checks for the page count', async () => {
    render(<Host />)
    await focused()
    expect(screen.getByText('Estimated cost: title triage ≈ 48 small LLM calls · content checks up to 100 calls')).toBeInTheDocument()
  })

  test('save_as_recipe: the chips are saved as one of the owner\'s recipes, offered at once', async () => {
    render(<Host />)
    await focused()
    fireEvent.click(chip('XSS'))
    fireEvent.click(chip('Bypasses & evasion'))
    fireEvent.change(screen.getByLabelText('Recipe name'), { target: { value: 'XSS bypasses' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save as recipe' }))
    expect(await screen.findByRole('button', { name: 'XSS bypasses' })).toBeInTheDocument()
    const put = fetchMock.mock.calls.find(c => (c[1] as RequestInit | undefined)?.method === 'PUT')!
    expect(JSON.parse(String((put[1] as RequestInit).body))).toEqual({ recipes: { add: { name: 'XSS bypasses', topics: ['xss'], kinds: ['bypasses'] } } })
  })

  test('the header names the mode and the chips; the account\'s Always skip is shown beside Skip', async () => {
    render(<Host initial={{ ...EMPTY_FOCUS, mode: 'focused', topics: ['xss', 'ssrf'], kinds: ['poc'] }} />)
    expect(screen.getByRole('button', { name: /^Focus/ })).toHaveTextContent('Focused: 2 topics, 1 content type')
    openSection()
    await waitFor(() => expect(screen.getByText(/Your Always skip: marketing/)).toBeInTheDocument())
  })
})
