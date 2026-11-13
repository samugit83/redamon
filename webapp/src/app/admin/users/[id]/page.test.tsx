/**
 * One account in the admin console (step 6.2; GV-01, ID-27; DV-06, DV-19): the detail sections
 * (profile, permissions through the Users page's panel, own and shared projects, MCP tokens with
 * revocation, recent audit rows), each with its own refusal; the row's actions; and the page's
 * loading, error + Retry, denied and missing states. A token revoke goes to the existing route
 * (`mcp-token.delete` is audited there: route.permissions.test.ts) after the app's confirmation.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/admin/users/[id]/page.test.tsx"
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { AuthUser } from '@/providers/AuthProvider'
import { AlertProvider } from '@/components/ui'
import type { DirectoryRow, UserDetail } from '@/lib/authz/userDirectory'

const h = vi.hoisted(() => ({ id: 'm-1', push: vi.fn(), setUserId: vi.fn(async () => null) }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: h.push }),
  useParams: () => ({ id: h.id }),
  usePathname: () => `/admin/users/${h.id}`,
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ setUserId: h.setUserId }) }))
vi.mock('@/hooks/usePasswordPolicy', () => ({ usePasswordPolicy: () => null }))
vi.mock('@/components/admin/UserPermissionsPanel', () => ({
  UserPermissionsPanel: ({ user, selfId }: { user: { id: string }; selfId: string }) => <p>permissions panel of {user.id} for {selfId}</p>,
}))

import AdminUserDetailPage from './page'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }

function row(over: Partial<DirectoryRow> = {}): DirectoryRow {
  return {
    id: 'm-1', name: 'Marco', email: 'marco@e2e.local', accountType: 'member', status: 'active', mustChangePassword: false,
    lastLoginAt: '2026-11-12T09:30:00.000Z', createdAt: '2026-10-01T00:00:00.000Z',
    sets: [{ id: 'builtin:recon-operator', name: 'Recon operator' }], profile: null, projects: { owned: 1, shared: 1 },
    self: false, actions: ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions'], ...over,
  }
}

function detail(over: Partial<UserDetail> = {}): UserDetail {
  return {
    user: row(),
    owned: [{ id: 'p-1', name: 'Lab', createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-02T00:00:00.000Z' }],
    shared: { state: 'off' },
    audit: { denied: 'audit:read' },
    ...over,
  }
}

const TOKEN = {
  id: 't-1', name: 'ci agent', tokenPrefix: 'rdm_ab12', scopes: ['recon:read'], profile: null, lastUsedAt: null,
  expiresAt: null, revokedAt: null, createdAt: '2026-11-01T00:00:00.000Z',
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>
let answerDetail: () => Response
let answerTokens: () => Response

beforeEach(() => {
  h.id = 'm-1'
  h.push.mockReset()
  answerDetail = () => json(detail())
  answerTokens = () => json({ tokens: [TOKEN], features: { agentInTheLoop: false } })
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = String(input)
    if (init?.method === 'DELETE' || init?.method === 'PUT' || init?.method === 'POST') return json({ ok: true })
    if (url.startsWith('/api/admin/users/')) return answerDetail()
    if (url.endsWith('/mcp-tokens')) return answerTokens()
    // Step 6.8's quota section (its own test: components/quotas/QuotaUsage.test.tsx) stays hidden here.
    if (url.endsWith('/quota')) return json({ error: 'Not found' }, 404)
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage(over: Partial<AuthUser> = {}) {
  const base = fakeAuth(FLAGS_GOV, ['users:read'])
  const auth = { ...base, user: { ...base.user!, id: 'adm-a', name: 'Admin A', role: 'admin' as const, email: 'adm-a@e2e.local', accountType: 'admin' as const, ...over } }
  return render(
    <AuthContext.Provider value={auth}>
      <AlertProvider><AdminUserDetailPage /></AlertProvider>
    </AuthContext.Provider>,
  )
}

const section = (name: string) => within(screen.getByRole('region', { name }))

describe('detail sections', () => {
  test('profile: identity, type, status, sets, last sign-in, created; the row\'s actions in the header', async () => {
    renderPage()
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    expect(fetchMock).toHaveBeenCalledWith('/api/admin/users/m-1', expect.anything())
    const profile = section('Profile')
    expect(profile.getByRole('group', { name: 'Marco, marco@e2e.local, Member' })).toBeInTheDocument()
    expect(profile.getByText('Active')).toBeInTheDocument()
    expect(profile.getByText('Recon operator')).toBeInTheDocument()
    expect(profile.getByRole('time')).toHaveAttribute('dateTime', '2026-11-12T09:30:00.000Z')
    expect(profile.queryByRole('combobox')).toBeNull()
    expect(screen.getByRole('button', { name: 'Edit Marco' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Disable Marco' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Permissions of Marco' })).toBeNull()
    expect(screen.getByRole('link', { name: '← All users' })).toHaveAttribute('href', '/admin/users')
  })

  test('permissions: the panel for whoever may assign them; otherwise why not', async () => {
    renderPage()
    expect(await screen.findByText('permissions panel of m-1 for adm-a')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Permissions' })).toHaveAttribute('id', 'permissions')
    cleanup()

    answerDetail = () => json(detail({ user: row({ actions: [] }) }))
    renderPage()
    expect((await section2('Permissions')).getByRole('alert').textContent).toMatch(/users:assign_permissions/)
    cleanup()

    answerDetail = () => json(detail({ user: row({ id: 'root-1', accountType: 'root', sets: null, actions: [] }) }))
    renderPage()
    expect((await section2('Permissions')).getByText(/Root holds every permission/)).toBeInTheDocument()
    cleanup()

    answerDetail = () => json(detail({ user: row({ id: 'adm-a', self: true, actions: [] }) }))
    renderPage()
    expect((await section2('Permissions')).getByRole('link', { name: 'My account' })).toHaveAttribute('href', '/account')
  })

  test('projects: own ones by name and date, the scope only when the server gave it; shares off, hidden or listed', async () => {
    renderPage()
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    const projects = section('Projects')
    expect(projects.getByRole('table', { name: 'Owned projects' })).toBeInTheDocument()
    expect(projects.queryByRole('columnheader', { name: 'Scope' })).toBeNull()
    expect(projects.getByText('Sharing is not in force: no project is shared.')).toBeInTheDocument()
    cleanup()

    answerDetail = () => json(detail({
      owned: [{ id: 'p-1', name: 'Lab', createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-02T00:00:00.000Z', targetLabel: 'lab.example.test' }],
      shared: { state: 'hidden' },
    }))
    renderPage()
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    expect(section('Projects').getByRole('cell', { name: 'lab.example.test' })).toBeInTheDocument()
    expect(section('Projects').getByText(/does not show administrators the projects shared/)).toBeInTheDocument()
    cleanup()

    answerDetail = () => json(detail({
      owned: [],
      shared: { state: 'listed', projects: [{ id: 'p-9', name: 'Shared lab', owner: { id: 'm-9', name: 'Olga', email: 'olga@e2e.local' }, access: 'read', expiresAt: null, sharedAt: '2026-11-10T00:00:00.000Z' }] },
    }))
    renderPage()
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    expect(section('Projects').getByText('This account owns no project.')).toBeInTheDocument()
    const shared = within(section('Projects').getByRole('table', { name: 'Projects shared with this account' }))
    expect(shared.getByRole('group', { name: 'Olga, olga@e2e.local' })).toBeInTheDocument()
    expect(shared.getByRole('cell', { name: 'Read' })).toBeInTheDocument()
    expect(shared.getByRole('cell', { name: 'Never' })).toBeInTheDocument()
  })

  test('MCP tokens: listed; Revoke asks in the app\'s dialog and deletes through the token route, then reads them again', async () => {
    renderPage()
    const tokens = await waitFor(() => section('MCP tokens'))
    expect(await tokens.findByRole('cell', { name: 'ci agent' })).toBeInTheDocument()
    expect(tokens.getByRole('cell', { name: 'Active' })).toBeInTheDocument()
    fireEvent.click(tokens.getByRole('button', { name: 'Revoke the MCP token ci agent' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toMatch(/Revoke the MCP token "ci agent" \(rdm_ab12…\) of Marco\?/)
    answerTokens = () => json({ tokens: [] })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/users/m-1/mcp-tokens/t-1', expect.objectContaining({ method: 'DELETE' })))
    expect(await tokens.findByText('This account has no MCP token.')).toBeInTheDocument()
  })

  test('MCP tokens: no Revoke without users:revoke_sessions on the account; Root\'s refusal and an error are shown', async () => {
    answerDetail = () => json(detail({ user: row({ actions: ['edit'] }) }))
    renderPage()
    expect(await section2('MCP tokens').then((s) => s.findByRole('cell', { name: 'ci agent' }))).toBeInTheDocument()
    expect(section('MCP tokens').queryByRole('button', { name: /Revoke/ })).toBeNull()
    cleanup()

    answerTokens = () => json({ error: "Root's MCP tokens are Root's own.", code: 'root_protected' }, 403)
    renderPage()
    expect((await (await section2('MCP tokens')).findByRole('alert')).textContent).toMatch(/Root's MCP tokens/)
    cleanup()

    let fail = true
    answerTokens = () => (fail ? json({ error: 'Could not load tokens', code: 'P1001' }, 500) : json({ tokens: [] }))
    renderPage()
    const tokens = await section2('MCP tokens')
    expect((await tokens.findByRole('alert')).textContent).toMatch(/P1001/)
    fail = false
    fireEvent.click(tokens.getByRole('button', { name: 'Retry' }))
    expect(await tokens.findByText('This account has no MCP token.')).toBeInTheDocument()
  })

  test('recent activity: denied without audit:read; the rows with who, what and on what; empty', async () => {
    renderPage()
    expect((await section2('Recent activity')).getByRole('alert').textContent).toMatch(/audit:read/)
    cleanup()

    answerDetail = () => json(detail({ audit: { rows: [
      { id: 'a-1', action: 'user.disabled', createdAt: '2026-11-13T11:00:00.000Z', actorId: 'adm-a', actorEmail: 'adm-a@e2e.local', onBehalfOfUserId: null, targetType: 'user', targetId: 'm-1', projectId: null, permission: 'users:disable', source: 'api' },
      { id: 'a-2', action: 'project.create', createdAt: '2026-11-13T10:00:00.000Z', actorId: 'm-1', actorEmail: 'marco@e2e.local', onBehalfOfUserId: null, targetType: 'project', targetId: 'p-1', projectId: 'p-1', permission: null, source: 'api' },
      { id: 'a-3', action: 'user.update', createdAt: '2026-11-13T09:00:00.000Z', actorId: null, actorEmail: null, onBehalfOfUserId: null, targetType: 'user', targetId: 'm-1', projectId: null, permission: null, source: 'system' },
    ] } }))
    renderPage()
    const table = within((await section2('Recent activity')).getByRole('table', { name: 'Recent audit rows' }))
    const rows = table.getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('cell').slice(1).map((c) => c.textContent))
    expect(rows).toEqual([
      ['user.disabled', 'adm-a@e2e.local', 'This account'],
      ['project.create', 'This account', 'project'],
      ['user.update', 'The system', 'This account'],
    ])
    cleanup()

    answerDetail = () => json(detail({ audit: { rows: [] } }))
    renderPage()
    expect((await section2('Recent activity')).getByText('No audit row names this account yet.')).toBeInTheDocument()
  })

  test('the role control shows only to the confirmed Root, on another account that is not Root', async () => {
    renderPage({ accountType: 'root', rbac: { compat: false, legacyGrantsPending: 0, identity: true, root: { email: 'adm-a@e2e.local', confirmed: true, chosenAt: null } } })
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    expect(section('Profile').getByRole('combobox')).toBeInTheDocument()
    cleanup()
    renderPage({ accountType: 'root', rbac: { compat: false, legacyGrantsPending: 0, identity: true, root: { email: 'adm-a@e2e.local', confirmed: false, chosenAt: null } } })
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    expect(section('Profile').queryByRole('combobox')).toBeNull()
  })

  test('deleting the account goes back to the directory', async () => {
    answerDetail = () => json(detail({ user: row({ actions: ['delete'] }) }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Marco' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(h.push).toHaveBeenCalledWith('/admin/users'))
    expect(fetchMock).toHaveBeenCalledWith('/api/users/m-1', expect.objectContaining({ method: 'DELETE' }))
  })
})

/** A section once the account has been read. */
async function section2(name: string) {
  return within(await screen.findByRole('region', { name }))
}

describe('states', () => {
  test('loading, then the error with its code and Retry', async () => {
    let fail = true
    answerDetail = () => (fail ? json({ error: 'Could not read the account', code: 'P1001' }, 500) : json(detail()))
    renderPage()
    expect(screen.getByRole('status').textContent).toBe('Loading the account…')
    expect((await screen.findByRole('alert')).textContent).toMatch(/P1001/)
    fail = false
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
  })

  test('denied: the 403 names the permission; missing: the account is gone', async () => {
    answerDetail = () => json({ error: 'You do not hold the permission this action needs (users:read).', code: 'forbidden', permission: 'users:read' }, 403)
    renderPage()
    expect((await screen.findByRole('alert')).textContent).toMatch(/users:read/)
    cleanup()
    answerDetail = () => json({ error: 'User not found', code: 'user_not_found' }, 404)
    renderPage()
    expect((await screen.findByRole('alert')).textContent).toBe('This account does not exist; it may have been deleted.')
  })

  test('labelled sections and tables; every control in the tab order', async () => {
    renderPage()
    await screen.findByRole('heading', { level: 1, name: 'Marco' })
    await section('MCP tokens').findByRole('cell', { name: 'ci agent' })
    expect(screen.getAllByRole('region').map((r) => r.getAttribute('aria-labelledby'))).toEqual(
      ['user-profile', 'user-permissions', 'user-projects', 'user-tokens', 'user-devices', 'user-activity'])
    expect(screen.getAllByRole('heading', { level: 2 }).map((x) => x.textContent)).toEqual(
      ['Profile', 'Permissions', 'Projects', 'MCP tokens', 'Device sessions', 'Recent activity'])
    for (const el of [...screen.getAllByRole('button'), ...screen.getAllByRole('link')]) expect(el).not.toHaveAttribute('tabindex', '-1')
  })
})

describe('quota (step 6.8)', () => {
  test("the account's quota and use, read for this account", async () => {
    const base = fetchMock.getMockImplementation() as (input: string, init?: RequestInit) => Promise<Response>
    const sources = Object.fromEntries(['maxProjects', 'maxConcurrentScans', 'maxConcurrentAgentRuns', 'maxMcpTokens', 'maxMcpTokenExpiryDays', 'llmDailyCalls']
      .map((f) => [f, f === 'maxProjects' ? { kind: 'user' } : { kind: 'default' }]))
    const report = {
      enforced: true, sources, use: { maxProjects: 3, maxMcpTokens: 1 },
      quota: { maxProjects: 3, maxConcurrentScans: null, maxConcurrentAgentRuns: null, maxMcpTokens: null, maxMcpTokenExpiryDays: null, llmDailyCalls: null },
    }
    fetchMock.mockImplementation(async (input: string, init?: RequestInit) =>
      (String(input).endsWith('/quota') ? json(report) : base(input, init)))
    renderPage()
    const row = (await screen.findByRole('rowheader', { name: 'Projects owned' })).closest('tr')!
    expect(within(row).getAllByRole('cell').map((c) => c.textContent)).toEqual(['3 projects', '3', 'Set for this account'])
    expect(fetchMock.mock.calls.some(([u]) => String(u) === '/api/users/m-1/quota')).toBe(true)
  })
})
