/**
 * The token screen's opt-in to shared projects (step 4.10; SH-42): shown only while sharing is in
 * force (/api/auth/me `sharing.enabled`); the mint sends it with the password the mint always asks;
 * an edit that opens the token to more shared projects asks for the password, one that narrows does
 * not. With sharing off the screen and its requests are the ones before sharing.
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
const PROJECTS = [
  { id: 'P-own', name: 'mine', myAccess: { level: 'owner', via: 'owner', owner: { name: 'Bob', email: 'bob@example.test' } } },
  { id: 'P-alice', name: 'alice estate', myAccess: { level: 'read', via: 'share', owner: { name: 'Alice', email: 'alice@example.test' } } },
]

function mockFetch({ sharing, tokens = [TOKEN] }: { sharing: boolean; tokens?: unknown[] }) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    const u = String(url)
    const ok = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body })
    if (u.includes('/api/auth/me')) return ok({ id: 'owner', role: 'standard', ...(sharing ? { sharing: { enabled: true, maxLevel: 'read' } } : {}) })
    if (u === '/api/projects') return ok(PROJECTS)
    if (init?.method === 'POST') return ok({ plaintext: 'rdmn_mcp_' + 'a'.repeat(48), token: TOKEN }, 201)
    if (init?.method === 'PATCH') return ok({ token: TOKEN })
    return ok({ tokens })
  })
}

const bodyOf = (fetchMock: ReturnType<typeof mockFetch>, method: string) => {
  const call = fetchMock.mock.calls.find(c => c[1]?.method === method)
  return call ? JSON.parse(String(call[1]!.body)) : undefined
}

async function openForm(fetchMock: ReturnType<typeof mockFetch>) {
  vi.stubGlobal('fetch', fetchMock)
  render(<McpTokensTab userId="owner" />)
  await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
  fireEvent.click(screen.getByText('New token'))
}

async function openEdit(fetchMock: ReturnType<typeof mockFetch>) {
  vi.stubGlobal('fetch', fetchMock)
  render(<McpTokensTab userId="owner" />)
  await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
  await waitFor(() => expect(fetchMock.mock.calls.some(c => String(c[0]).includes('/api/auth/me'))).toBe(true))
  fireEvent.click(screen.getByLabelText('Actions for ci agent'))
  fireEvent.click(screen.getByText('Edit'))
  await waitFor(() => expect(screen.getByText('Edit token')).toBeTruthy())
}

beforeEach(() => vi.clearAllMocks())
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('sharing in force', () => {
  test('the mint offers the opt-in, lists only the projects shared with the user, and sends the choice', async () => {
    const fetchMock = mockFetch({ sharing: true })
    await openForm(fetchMock)
    const include = screen.getByLabelText(/Include projects shared with me/) as HTMLInputElement
    expect(include.checked).toBe(false)
    fireEvent.click(include)
    await waitFor(() => expect(screen.getByText('alice estate')).toBeTruthy())
    expect(screen.queryByText('mine')).toBeNull()
    expect(screen.getByText('Shared by Alice')).toBeTruthy()
    fireEvent.click(screen.getByLabelText(/alice estate/))

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'reader' } })
    fireEvent.change(screen.getByLabelText('Confirm your password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByText('Create token'))
    await waitFor(() => expect(bodyOf(fetchMock, 'POST')).toBeTruthy())
    expect(bodyOf(fetchMock, 'POST')).toMatchObject({ includeSharedProjects: true, projectAllowlist: ['P-alice'], password: 'pw' })
  })

  test('a mint that leaves it off says so', async () => {
    const fetchMock = mockFetch({ sharing: true })
    await openForm(fetchMock)
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci' } })
    fireEvent.change(screen.getByLabelText('Confirm your password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByText('Create token'))
    await waitFor(() => expect(bodyOf(fetchMock, 'POST')).toBeTruthy())
    expect(bodyOf(fetchMock, 'POST')).toMatchObject({ includeSharedProjects: false, projectAllowlist: [] })
  })

  test('opting in on an edit asks for the password', async () => {
    const fetchMock = mockFetch({ sharing: true, tokens: [{ ...TOKEN, includeSharedProjects: false, projectAllowlist: [] }] })
    await openEdit(fetchMock)
    expect(screen.queryByLabelText('Confirm your password')).toBeNull()
    fireEvent.click(screen.getByLabelText(/Include projects shared with me/))
    expect(screen.getByLabelText('Confirm your password')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Confirm your password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByText('Save changes'))
    await waitFor(() => expect(bodyOf(fetchMock, 'PATCH')).toBeTruthy())
    expect(bodyOf(fetchMock, 'PATCH')).toMatchObject({ includeSharedProjects: true, projectAllowlist: [], password: 'pw' })
  })

  test('opting out on an edit needs no password', async () => {
    const fetchMock = mockFetch({ sharing: true, tokens: [{ ...TOKEN, includeSharedProjects: true, projectAllowlist: ['P-alice'] }] })
    await openEdit(fetchMock)
    const include = screen.getByLabelText(/Include projects shared with me/) as HTMLInputElement
    expect(include.checked).toBe(true)
    fireEvent.click(include)
    expect(screen.queryByLabelText('Confirm your password')).toBeNull()
    fireEvent.click(screen.getByText('Save changes'))
    await waitFor(() => expect(bodyOf(fetchMock, 'PATCH')).toBeTruthy())
    const body = bodyOf(fetchMock, 'PATCH')
    expect(body).toMatchObject({ includeSharedProjects: false, projectAllowlist: [] })
    expect(body).not.toHaveProperty('password')
  })
})

describe('sharing not in force: the screen before sharing', () => {
  test('no opt-in on the mint, and the request carries none', async () => {
    const fetchMock = mockFetch({ sharing: false })
    await openForm(fetchMock)
    expect(screen.queryByLabelText(/Include projects shared with me/)).toBeNull()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci' } })
    fireEvent.change(screen.getByLabelText('Confirm your password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByText('Create token'))
    await waitFor(() => expect(bodyOf(fetchMock, 'POST')).toBeTruthy())
    expect(bodyOf(fetchMock, 'POST')).not.toHaveProperty('includeSharedProjects')
    expect(fetchMock.mock.calls.some(c => String(c[0]) === '/api/projects')).toBe(false)
  })

  test('no opt-in on the edit', async () => {
    await openEdit(mockFetch({ sharing: false }))
    expect(screen.queryByLabelText(/Include projects shared with me/)).toBeNull()
  })
})
