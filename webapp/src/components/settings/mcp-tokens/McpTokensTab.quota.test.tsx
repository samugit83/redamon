/**
 * The token screen offers only what the account's token quotas allow (step 6.8, GV-13): with a
 * maxMcpTokenExpiryDays the mint and the edit drop the longer presets and "No expiry", the mint starts
 * on an allowed expiry, the date picker stops at the limit, and the screen says the limit and the
 * count of tokens in use. Without `tokenQuota` in the list (no token quota, or the governance switch
 * off) every choice is offered, as before. The server refuses the rest (route.quota.test.ts).
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'

vi.mock('@/components/ui', async importActual => ({
  ...(await importActual<typeof import('@/components/ui')>()),
  useAlertModal: () => ({ dangerConfirm: vi.fn(), alertError: vi.fn(), confirm: vi.fn(async () => true) }),
  WikiInfoButton: () => null,
  Modal: ({ isOpen, title, children }: { isOpen: boolean; title?: string; children?: ReactNode }) =>
    isOpen ? <div role="dialog" aria-label={title}>{children}</div> : null,
  ExternalLink: ({ href, children }: { href: string; children?: ReactNode }) => <a href={href}>{children}</a>,
}))
vi.mock('@/hooks/useUnsavedChangesGuard', () => ({ useUnsavedChangesGuard: () => ({ guardedNavigate: vi.fn() }) }))

import McpTokensTab from './McpTokensTab'

const TOKEN = {
  id: 't1', name: 'ci agent', tokenPrefix: 'rdmn_mcp_a3f9c21e', scopes: ['recon:read'], profile: null,
  lastUsedAt: null, expiresAt: null, revokedAt: null, createdAt: '2026-09-01T10:00:00.000Z',
}
function mockFetch(tokenQuota?: unknown) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    const u = String(url)
    const ok = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body })
    if (u.includes('/api/auth/me')) return ok({ id: 'owner', role: 'standard' })
    if (init?.method === 'POST') return ok({ plaintext: 'rdmn_mcp_' + 'a'.repeat(48), token: TOKEN }, 201)
    if (init?.method === 'PATCH') return ok({ token: TOKEN })
    return ok({ tokens: [TOKEN], ...(tokenQuota ? { tokenQuota } : {}) })
  })
}

const optionsOf = (label: string) =>
  Array.from((screen.getByLabelText(label) as HTMLSelectElement).options).map(o => o.textContent)

async function openForm(fetchMock: ReturnType<typeof mockFetch>) {
  vi.stubGlobal('fetch', fetchMock)
  render(<McpTokensTab userId="owner" />)
  await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
  await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
  fireEvent.click(screen.getByText('New token'))
}

async function openEdit(fetchMock: ReturnType<typeof mockFetch>) {
  vi.stubGlobal('fetch', fetchMock)
  render(<McpTokensTab userId="owner" />)
  await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
  fireEvent.click(screen.getByLabelText('Actions for ci agent'))
  fireEvent.click(screen.getByText('Edit'))
  await waitFor(() => expect(screen.getByText('Edit token')).toBeTruthy())
}

beforeEach(() => vi.clearAllMocks())
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('a token lifetime quota', () => {
  test('the mint offers only presets within it, starts on an allowed one, and says the limit and the count', async () => {
    const fetchMock = mockFetch({ maxMcpTokens: 3, maxMcpTokenExpiryDays: 60, active: 1 })
    await openForm(fetchMock)
    expect(optionsOf('Expires')).toEqual(['30 days', '60 days'])
    expect((screen.getByLabelText('Expires') as HTMLSelectElement).value).toBe('60')
    expect(screen.getByText(/limits MCP tokens to 60 days/)).toBeTruthy()
    expect(screen.getByText(/1 of 3 tokens in use/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'reader' } })
    fireEvent.change(screen.getByLabelText('Confirm your password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByText('Create token'))
    await waitFor(() => expect(fetchMock.mock.calls.some(c => c[1]?.method === 'POST')).toBe(true))
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')!
    expect(JSON.parse(String(post[1]!.body)).expiresInDays).toBe(60)
  })

  test('shorter than every preset: none offered, and the screen says to ask for more', async () => {
    await openForm(mockFetch({ maxMcpTokens: null, maxMcpTokenExpiryDays: 7, active: 0 }))
    expect(optionsOf('Expires')).toEqual([])
    expect(screen.getByText(/shorter than any choice here/)).toBeTruthy()
  })

  test('the edit drops the longer presets and "No expiry"; the date picker stops at the limit', async () => {
    await openEdit(mockFetch({ maxMcpTokens: null, maxMcpTokenExpiryDays: 90, active: 1 }))
    const options = optionsOf('Expires')
    expect(options).toContain('90 days from today')
    expect(options).toContain('Expire now')
    expect(options).toContain('Pick a date…')
    expect(options).not.toContain('1 year from today')
    expect(options).not.toContain('No expiry')
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'date' } })
    const max = (screen.getByLabelText('Expiry date') as HTMLInputElement).max
    expect(max).toBe(new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10))
  })
})

describe('no token quota (or the governance switch off)', () => {
  test('every expiry is offered and no limit is shown', async () => {
    await openForm(mockFetch())
    expect(optionsOf('Expires')).toEqual(['30 days', '60 days', '90 days', '1 year', 'No expiry'])
    expect((screen.getByLabelText('Expires') as HTMLSelectElement).value).toBe('90')
    expect(screen.queryByText(/limits MCP tokens/)).toBeNull()
  })
})
