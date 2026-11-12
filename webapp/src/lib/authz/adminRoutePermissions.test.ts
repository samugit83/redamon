/**
 * The administrator routes behind `requireAdmin` (an administrator account) also ask the permission
 * they exercise (authz/adminPermission.ts): invites `users:create`, disable and enable
 * `users:disable`, signing out `users:revoke_sessions`, a credentials reset
 * `users:reset_credentials`, the legacy access review and the update notes
 * `users:assign_permissions`, starting act-as `users:impersonate`, reloading the agent's MCP
 * servers `platform:agent_mcp`. With RBAC_PERMISSIONS_ENABLED on an admin whose profile lacks it is
 * refused 403 naming it, before the route reads its body or anything else; with it off every admin
 * passes as before. The Root transfer routes stay on the account type: Root's power and the
 * recipient's offer are checked inside them.
 *
 * Real routes and session helpers; the database is the in-memory accountDb; the agent is a fetch
 * double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from './__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import type { PermissionId } from './permissions'
import { POST as invite } from '@/app/api/users/invite/route'
import { POST as resendInvite } from '@/app/api/users/[id]/invite/resend/route'
import { POST as cancelInvite } from '@/app/api/users/[id]/invite/cancel/route'
import { POST as disable } from '@/app/api/users/[id]/disable/route'
import { POST as enable } from '@/app/api/users/[id]/enable/route'
import { POST as revoke } from '@/app/api/users/[id]/revoke-sessions/route'
import { POST as resetCredentials } from '@/app/api/users/[id]/reset-credentials/route'
import { GET as legacyGrants, POST as decideLegacyGrants } from '@/app/api/admin/legacy-grants/route'
import { GET as whatsNew } from '@/app/api/admin/whats-new/route'
import { POST as startActAs } from '@/app/api/auth/act-as/route'
import { POST as reloadMcp } from '@/app/api/mcp/reload/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()

function req(body: unknown = {}): NextRequest {
  return new NextRequest('http://redamon.test/api/x', {
    method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
const params = { params: Promise.resolve({ id: 'member-1' }) }

type Call = () => Promise<Response>
const ROUTES: Array<[string, PermissionId, Call]> = [
  ['invite', 'users:create', () => invite(req({ name: 'n', email: 'n@e2e.local' }))],
  ['resend an invite', 'users:create', () => resendInvite(req(), params)],
  ['cancel an invite', 'users:create', () => cancelInvite(req(), params)],
  ['disable', 'users:disable', () => disable(req(), params)],
  ['enable', 'users:disable', () => enable(req(), params)],
  ['sign out everywhere', 'users:revoke_sessions', () => revoke(req(), params)],
  ['reset credentials', 'users:reset_credentials', () => resetCredentials(req({ mode: 'link' }), params)],
  ['read the legacy access review', 'users:assign_permissions', () => legacyGrants()],
  ['decide a legacy grant', 'users:assign_permissions', () => decideLegacyGrants(req({ action: 'keep_all' }))],
  ['read the update notes', 'users:assign_permissions', () => whatsNew()],
  ['start acting as a member', 'users:impersonate', () => startActAs(req({ targetUserId: 'member-1' }))],
  ['reload the agent\'s MCP servers', 'platform:agent_mcp', () => reloadMcp()],
]

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-full', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'admin-po', role: 'admin', adminProfileId: 'builtin:platform-operator' },
    { id: 'admin-audit', role: 'admin', adminProfileId: 'builtin:security-auditor' },
    { id: 'member-1' },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
})

async function refusal(call: Call): Promise<Record<string, unknown> | null> {
  const res = await call()
  if (res.status !== 403) return null
  const body = await res.json() as Record<string, unknown>
  return body.code === 'forbidden' ? body : null
}

describe('an admin whose profile lacks the permission is refused, naming it (permissions switch on)', () => {
  test.each(ROUTES)('%s: %s', async (_name, permission, call) => {
    const lacking = permission.startsWith('platform:') ? 'admin-um' : 'admin-audit'
    await as(lacking)
    expect(await refusal(call)).toMatchObject({ code: 'forbidden', permission })
    expect(db().audit()).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('%s: a profile holding %s is not refused for it', async (_name, permission, call) => {
    // A User manager does not act as members (§4.5); a Full admin does.
    await as(permission.startsWith('platform:') ? 'admin-po' : permission === 'users:impersonate' ? 'admin-full' : 'admin-um')
    const body = await refusal(call)
    expect(body?.permission === permission ? body : null).toBeNull()
  })

  test('a member is refused as before (the administrator-account gate)', async () => {
    await as('member-1')
    for (const [, , call] of ROUTES) expect((await call()).status).toBe(403)
  })
})

describe('with the permissions switch off every admin passes the permission check', () => {
  test.each(ROUTES)('%s', async (_name, permission, call) => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-audit')
    const body = await refusal(call)
    expect(body?.permission === permission ? body : null).toBeNull()
  })
})
