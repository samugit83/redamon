/**
 * The panel's behaviour against its routes (plan §9.7, §9.8, §9.10, §9.14): a project switch ends
 * the answer in flight and shows that project's conversations, a delete asks first, the first send
 * goes through the feature-model gate, and each refusal offers its own action (Retry, Stop it,
 * the input back after the rate limit). fetch is a router over the Navigator routes.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const h = vi.hoisted(() => ({
  confirm: true,
  confirmCalls: [] as unknown[][],
  gateCalls: [] as string[],
  calls: [] as Array<{ method: string; url: string; body?: string; signal?: AbortSignal }>,
  send: null as null | ((body: string, signal?: AbortSignal) => Promise<Response>),
  threadFails: 0,
  threadsGate: null as null | Promise<void>,
}))

vi.mock('@/components/ui', async (orig) => ({
  ...(await orig<typeof import('@/components/ui')>()),
  useAlertModal: () => ({ dangerConfirm: async (...a: unknown[]) => { h.confirmCalls.push(a); return h.confirm } }),
}))
vi.mock('@/components/shared/FeatureModelGate', () => ({
  useFeatureModelGate: () => ({
    ensureFeatureModel: async () => true,
    fetchWithFeatureModel: (id: string, doFetch: () => Promise<Response>) => { h.gateCalls.push(id); return doFetch() },
  }),
}))

import { NavigatorPanel } from './NavigatorPanel'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const THREADS: Record<string, Array<{ id: string; title: string; lastMessageAt: string; createdAt: string }>> = {
  pA: [{ id: 'tA', title: 'About project A', lastMessageAt: '2026-11-01T10:00:00Z', createdAt: '2026-11-01T10:00:00Z' }],
  pB: [{ id: 'tB', title: 'About project B', lastMessageAt: '2026-11-01T10:00:00Z', createdAt: '2026-11-01T10:00:00Z' }],
}

async function router(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const url = String(input)
  const method = (init.method ?? 'GET').toUpperCase()
  h.calls.push({ method, url, body: typeof init.body === 'string' ? init.body : undefined, signal: init.signal ?? undefined })
  const m = /^\/api\/navigator\/projects\/(\w+)(\/.*)?$/.exec(url)
  if (!m) return json({ code: 'not_found' }, 404)
  const [, pid, rest = ''] = m
  if (rest === '/status') return json({ allowed: true, retentionDays: 30 })
  if (rest === '/threads') {
    if (h.threadsGate) await h.threadsGate
    return json({ threads: THREADS[pid] ?? [] })
  }
  if (rest === '/messages' && method === 'POST') return h.send ? h.send(String(init.body), init.signal ?? undefined) : json({ code: 'agent_unreachable' }, 502)
  const t = /^\/threads\/(\w+)(\/stop)?$/.exec(rest)
  if (t && t[2]) return json({ stopped: true })
  if (t && method === 'DELETE') return json({ deleted: true })
  if (t) {
    if (h.threadFails > 0) { h.threadFails -= 1; return json({ code: 'agent_unreachable' }, 502) }
    return json({ messages: [
      { id: `${t[1]}-q`, role: 'user', content: `question in ${t[1]}`, status: 'complete' },
      { id: `${t[1]}-a`, role: 'assistant', content: `answer in ${t[1]}`, status: 'complete' },
    ] })
  }
  return json({ code: 'not_found' }, 404)
}

function Panel({ projectId }: { projectId: string }) {
  return (
    <NavigatorPanel id="nav" open projectId={projectId} projectName={projectId} userId="alice" style={{}}
      onClose={() => {}} onOpenAgent={() => {}} agentAllowed onAnswerDone={() => {}} onResetPosition={() => {}} pagePath="/graph" />
  )
}

function mount(projectId = 'pA') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(<QueryClientProvider client={client}><Panel projectId={projectId} /></QueryClientProvider>)
  return {
    switchTo: (pid: string) => view.rerender(<QueryClientProvider client={client}><Panel projectId={pid} /></QueryClientProvider>),
  }
}

const input = () => screen.getByLabelText('Message AI Navigator') as HTMLTextAreaElement
async function typeAndSend(text: string) {
  await waitFor(() => expect(input().disabled).toBe(false))
  fireEvent.change(input(), { target: { value: text } })
  fireEvent.click(screen.getByRole('button', { name: 'Send' }))
}
const posts = (suffix: string) => h.calls.filter((c) => c.method === 'POST' && c.url.endsWith(suffix))

beforeEach(() => {
  h.confirm = true
  h.confirmCalls = []
  h.gateCalls = []
  h.calls = []
  h.send = null
  h.threadFails = 0
  h.threadsGate = null
  vi.stubGlobal('fetch', vi.fn(router))
  try { window.localStorage.clear() } catch { /* storage off */ }
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('project scoping', () => {
  test('opens the project\'s newest conversation; a switch shows the other project\'s', async () => {
    const { switchTo } = mount('pA')
    expect(await screen.findByText('answer in tA')).toBeTruthy()
    switchTo('pB')
    expect(await screen.findByText('answer in tB')).toBeTruthy()
    expect(screen.queryByText('answer in tA')).toBeNull()
  })

  test('a switch ends the answer in flight and tells the server to stop it', async () => {
    h.send = (_body, signal) => new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
    })
    const { switchTo } = mount('pA')
    await screen.findByText('answer in tA')
    await typeAndSend('a long question')
    await waitFor(() => expect(posts('/messages')).toHaveLength(1))
    const signal = posts('/messages')[0].signal!
    switchTo('pB')
    await waitFor(() => expect(signal.aborted).toBe(true))
    await waitFor(() => expect(posts('/threads/tA/stop')).toHaveLength(1))
    expect(await screen.findByText('answer in tB')).toBeTruthy()
  })
})

describe('sending', () => {
  test('a message sent before the conversation list arrives stays a new conversation, and its answer runs on', async () => {
    let release = () => {}
    h.threadsGate = new Promise<void>((r) => { release = r })
    let aborted = false
    h.send = (_body, signal) => new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => { aborted = true; reject(new DOMException('aborted', 'AbortError')) })
    })
    window.localStorage.setItem('redamon.navigator.last.v1.alice.pA', 'tA')
    mount('pA')
    await typeAndSend('a quick first question')
    await waitFor(() => expect(posts('/messages')).toHaveLength(1))
    expect(JSON.parse(posts('/messages')[0].body!)).toMatchObject({ threadId: null })
    release()
    await waitFor(() => expect(h.calls.some((c) => c.method === 'GET' && c.url.endsWith('/threads'))).toBe(true))
    await new Promise((r) => setTimeout(r, 200))
    expect(h.calls.some((c) => c.method === 'GET' && c.url.endsWith('/threads/tA'))).toBe(false)
    expect(aborted).toBe(false)
  })

  test('the first send goes through the feature-model gate for navigator', async () => {
    mount('pA')
    await screen.findByText('answer in tA')
    await typeAndSend('hello')
    await waitFor(() => expect(h.gateCalls).toEqual(['navigator']))
    expect(JSON.parse(posts('/messages')[0].body!)).toMatchObject({ threadId: 'tA', text: 'hello', pageContext: { path: '/graph' } })
  })

  test('refused before anything was saved (project_busy): Retry sends the same text again', async () => {
    h.send = async () => json({ code: 'project_busy' }, 409)
    mount('pA')
    await screen.findByText('answer in tA')
    await typeAndSend('what changed?')
    expect(await screen.findByText('This project is being restored or transferred. Try again in a minute.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(posts('/messages')).toHaveLength(2))
    expect(JSON.parse(posts('/messages')[1].body!)).toMatchObject({ text: 'what changed?' })
  })

  test('busy names the conversation being answered: Stop it stops that one, and it is not opened', async () => {
    h.send = async () => json({ code: 'busy', threadId: 'tOther' }, 409)
    mount('pA')
    await screen.findByText('answer in tA')
    await typeAndSend('hello')
    fireEvent.click(await screen.findByRole('button', { name: 'Stop it' }))
    await waitFor(() => expect(posts('/threads/tOther/stop')).toHaveLength(1))
    expect(h.calls.some((c) => c.method === 'GET' && c.url.endsWith('/threads/tOther'))).toBe(false)
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  test('rate_limited: the input comes back after retryAfterSeconds', async () => {
    h.send = async () => json({ code: 'rate_limited', retryAfterSeconds: 2 }, 429)
    mount('pA')
    await screen.findByText('answer in tA')
    await typeAndSend('hello')
    expect(await screen.findByText("You're sending messages too fast. Try again in 2 s.")).toBeTruthy()
    await waitFor(() => expect(input().disabled).toBe(true))
    await waitFor(() => expect(input().disabled).toBe(false), { timeout: 4000 })
    expect(screen.queryByText(/sending messages too fast/)).toBeNull()
  })

  test('a conversation that failed to load offers Retry, which reopens it', async () => {
    h.threadFails = 1
    mount('pA')
    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('answer in tA')).toBeTruthy()
  })
})

describe('history', () => {
  test('a delete asks first; declined deletes nothing; confirmed deletes and clears the open conversation', async () => {
    mount('pA')
    await screen.findByText('answer in tA')
    fireEvent.click(screen.getByRole('button', { name: 'History' }))
    h.confirm = false
    fireEvent.click(await screen.findByRole('button', { name: 'Delete About project A' }))
    await waitFor(() => expect(h.confirmCalls).toHaveLength(1))
    expect(h.confirmCalls[0][0]).toBe('Delete this conversation? This can’t be undone.')
    expect(h.calls.some((c) => c.method === 'DELETE')).toBe(false)

    h.confirm = true
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Delete About project A' })) })
    await waitFor(() => expect(h.calls.filter((c) => c.method === 'DELETE').map((c) => c.url))
      .toEqual(['/api/navigator/projects/pA/threads/tA']))
    // Still in History, where the person is tidying up.
    expect(screen.getByRole('button', { name: 'History' }).getAttribute('aria-pressed')).toBe('true')
  })
})
