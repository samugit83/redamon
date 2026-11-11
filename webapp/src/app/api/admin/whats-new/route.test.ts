/**
 * The facts of the one-time "What changed in this update" admin card (HD-32, OQ-48, step
 * 1.18): whether this admin dismissed it (an `rbac.whats_new_dismissed` audit row per
 * admin), whether anything changed for this install (a single-operator install sees no
 * card), and the members whose saved stdio MCP servers no longer load.
 *
 * Real session helpers and tokens; the database is the in-memory fakePrisma.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createFakePrisma } = await import('@/lib/plugins/__testing__/fakePrisma')
  h.db = createFakePrisma()
  return { default: h.db, prisma: h.db }
})

import type { FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { createToken } from '@/lib/auth'
import { LEGACY_GRANTS_CUTOFF_ACTION, resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { WHATS_NEW_DISMISSED_ACTION, WHATS_NEW_EDITION } from '@/lib/authz/updateReview'
import { GET, POST } from './route'

const db = () => h.db as FakePrisma
const PW = '$2a$12$hash'
const CUTOFF = new Date('2026-06-01T00:00:00.000Z')
const BEFORE = new Date('2026-01-01T00:00:00.000Z')
const AFTER = new Date('2026-07-01T00:00:00.000Z')

function account(id: string, role: string, opts: { password?: string; createdAt?: Date } = {}) {
  db().seed('user', [{
    id, name: id.toUpperCase(), email: `${id}@e2e.local`, role, password: opts.password ?? PW,
    createdAt: opts.createdAt ?? BEFORE, updatedAt: BEFORE, legacyGrants: [],
  }])
}
function servers(userId: string, list: unknown) {
  db().seed('userSettings', [{ id: `s-${userId}`, userId, mcpServers: list }])
}

async function signIn(userId: string, role = 'admin') {
  h.jar.auth = await createToken(userId, role)
}
function post(body: unknown, origin?: string) {
  return new NextRequest('http://redamon.test/api/admin/whats-new', {
    method: 'POST',
    headers: { host: 'redamon.test', 'content-type': 'application/json', ...(origin ? { origin } : {}) },
    body: JSON.stringify(body),
  })
}
const dismissals = () => db().rows('auditLog').filter(r => r.action === WHATS_NEW_DISMISSED_ACTION)

beforeEach(() => {
  for (const t of Object.values(db().tables)) t.clear()
  resetSharedToolsForTests()
  db().seed('auditLog', [{ action: LEGACY_GRANTS_CUTOFF_ACTION, targetType: 'system', source: 'system', createdAt: CUTOFF }])
  account('admin-1', 'admin')
  h.jar = {}
})

describe('who may read it', () => {
  test('no session 401, a member 403 coded', async () => {
    expect((await GET()).status).toBe(401)
    account('member-1', 'standard')
    await signIn('member-1', 'standard')
    const res = await GET()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:assign_permissions' })
    expect((await POST(post({ action: 'dismiss' }))).status).toBe(403)
    expect(dismissals()).toHaveLength(0)
  })
})

describe('single-operator install shows nothing', () => {
  test('one admin, no member: the card does not apply', async () => {
    await signIn('admin-1')
    expect(await (await GET()).json()).toEqual({ dismissed: false, applies: false, stdioMembers: [] })
  })

  test('accounts created after the upgrade do not make it apply', async () => {
    account('member-new', 'standard', { createdAt: AFTER })
    account('admin-new', 'admin', { createdAt: AFTER })
    await signIn('admin-1')
    expect((await (await GET()).json()).applies).toBe(false)
  })

  test('a passwordless managed account cannot sign in: it does not make it apply', async () => {
    account('managed', 'standard', { password: '' })
    await signIn('admin-1')
    expect((await (await GET()).json()).applies).toBe(false)
  })
})

describe('when it applies', () => {
  test('a second account that could sign in at the upgrade', async () => {
    account('member-1', 'standard')
    await signIn('admin-1')
    expect(await (await GET()).json()).toEqual({ dismissed: false, applies: true, stdioMembers: [] })
  })

  test('names the non-admin accounts whose stdio servers no longer load, with how many; never an admin\'s', async () => {
    account('member-1', 'standard')
    account('managed', 'standard', { password: '' })
    account('admin-2', 'admin')
    servers('member-1', [
      { id: 'a', name: 'local-tool', transport: 'stdio', command: 'node' },
      { id: 'b', name: 'remote', transport: 'http', url: 'https://mcp.example' },
      { id: 'c', name: 'second', transport: 'stdio', command: 'python3', enabled: false },
    ])
    servers('managed', [{ id: 'd', transport: 'stdio', command: 'uvx' }])
    servers('admin-2', [{ id: 'e', transport: 'stdio', command: 'node' }])
    await signIn('admin-1')
    const body = await (await GET()).json()
    expect(body.applies).toBe(true)
    expect(body.stdioMembers).toEqual([
      { id: 'managed', name: 'MANAGED', email: 'managed@e2e.local', servers: 1 },
      { id: 'member-1', name: 'MEMBER-1', email: 'member-1@e2e.local', servers: 2 },
    ])
    // Only names and counts: no command, URL or server name reaches the browser.
    expect(JSON.stringify(body)).not.toMatch(/node|uvx|python3|mcp\.example|local-tool/)
  })

  test('a stdio server of a passwordless member alone makes it apply', async () => {
    account('managed', 'standard', { password: '' })
    servers('managed', [{ id: 'd', transport: 'stdio', command: 'uvx' }])
    await signIn('admin-1')
    expect((await (await GET()).json()).applies).toBe(true)
  })

  test('without a cutoff row yet, every account counts', async () => {
    for (const r of db().rows('auditLog')) await db().auditLog.delete({ where: { id: r.id } })
    account('member-new', 'standard', { createdAt: AFTER })
    await signIn('admin-1')
    expect((await (await GET()).json()).applies).toBe(true)
  })
})

describe('dismissed card stays dismissed', () => {
  test('a dismissal is one audit row of this admin; the card then reads dismissed; a second writes nothing', async () => {
    account('member-1', 'standard')
    await signIn('admin-1')
    const res = await POST(post({ action: 'dismiss' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ dismissed: true, changed: true })
    expect(dismissals()).toEqual([
      expect.objectContaining({ actorId: 'admin-1', targetType: 'notice', targetId: WHATS_NEW_EDITION }),
    ])
    expect(await (await GET()).json()).toEqual({ dismissed: true, applies: false, stdioMembers: [] })
    expect(await (await POST(post({ action: 'dismiss' }))).json()).toEqual({ dismissed: true, changed: false })
    expect(dismissals()).toHaveLength(1)
  })

  test('one admin\'s dismissal does not dismiss it for another', async () => {
    account('admin-2', 'admin')
    await signIn('admin-1')
    await POST(post({ action: 'dismiss' }))
    await signIn('admin-2')
    expect((await (await GET()).json()).dismissed).toBe(false)
  })

  test('cross-origin or an unknown action is refused, nothing written', async () => {
    await signIn('admin-1')
    const cross = await POST(post({ action: 'dismiss' }, 'https://evil.example'))
    expect(cross.status).toBe(403)
    expect((await cross.json()).code).toBe('cross_origin')
    const bad = await POST(post({ action: 'undismiss' }))
    expect(bad.status).toBe(400)
    expect((await bad.json()).code).toBe('invalid_action')
    expect(dismissals()).toHaveLength(0)
  })
})
