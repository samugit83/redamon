/**
 * Unit tests for access.ts authorization guards (BOLA remediation).
 *
 * Run: npx vitest run src/lib/access.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const mockGetEffectiveUser = vi.fn()
vi.mock('./session', () => ({
  getEffectiveUser: () => mockGetEffectiveUser(),
}))

const mockProjectFindUnique = vi.fn()
const mockConversationFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (a: unknown) => mockProjectFindUnique(a) },
    conversation: { findUnique: (a: unknown) => mockConversationFindUnique(a) },
  },
}))

import {
  requireEffectiveUser,
  assertOwner,
  assertOwnerStrict,
  ownerScope,
  requireProjectAccess,
  requireConversationAccess,
  accessEnforced,
  guardProject,
  requireConversationAccessBySession,
  resetAccessEnforceWarningForTests,
} from './access'

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  resetAccessEnforceWarningForTests()
})
afterEach(() => {
  vi.restoreAllMocks()
  delete process.env.ACCESS_ENFORCE
})

describe('requireEffectiveUser', () => {
  test('401 when no effective user', async () => {
    mockGetEffectiveUser.mockResolvedValue(null)
    const r = await requireEffectiveUser()
    expect(r).toBeInstanceOf(NextResponse)
    expect((r as NextResponse).status).toBe(401)
  })
  test('returns the effective user', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'u1' })
    const r = await requireEffectiveUser()
    expect(r).toEqual({ userId: 'u1' })
  })
})

describe('assertOwnerStrict (always enforces)', () => {
  test('owner -> null', () => {
    expect(assertOwnerStrict({ userId: 'u1' }, 'u1')).toBeNull()
  })
  test('non-owner -> 403 even when ACCESS_ENFORCE is off', () => {
    delete process.env.ACCESS_ENFORCE
    const r = assertOwnerStrict({ userId: 'u1' }, 'u2')
    expect((r as NextResponse).status).toBe(403)
  })
})

describe('assertOwner (anti-enum 404)', () => {
  test('owner -> null', () => {
    expect(assertOwner({ userId: 'u1' }, 'u1')).toBeNull()
  })
  // By design (step 3.5, PE-24): this was the log-only allow under ACCESS_ENFORCE=0.
  test('non-owner, ACCESS_ENFORCE=0 -> 404 all the same (log-only is gone)', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    process.env.ACCESS_ENFORCE = '0'
    expect((assertOwner({ userId: 'u1' }, 'u2') as NextResponse).status).toBe(404)
  })
  test('non-owner, default (enforce) -> 404 (anti-enum)', () => {
    delete process.env.ACCESS_ENFORCE
    const r = assertOwner({ userId: 'u1' }, 'u2')
    expect((r as NextResponse).status).toBe(404)
  })
})

describe('accessEnforced', () => {
  test('ON by default (fail closed)', () => {
    delete process.env.ACCESS_ENFORCE
    expect(accessEnforced()).toBe(true)
  })
  // By design (step 3.5, PE-24): "0" and "false" used to opt out.
  test('always on: no value of ACCESS_ENFORCE opts out', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const v of ['0', 'false', '1', 'true', 'off', '']) {
      process.env.ACCESS_ENFORCE = v
      expect([v, accessEnforced()]).toEqual([v, true])
    }
  })
})

describe('no log-only (PE-24, step 3.5)', () => {
  test.each(['0', 'false'])('ACCESS_ENFORCE=%s: every ownership guard still blocks with 404', async (v) => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    process.env.ACCESS_ENFORCE = v
    mockGetEffectiveUser.mockResolvedValue({ userId: 'attacker' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'victim', projectId: 'p1' })
    const answers = [
      assertOwner({ userId: 'attacker' }, 'victim'),
      await requireProjectAccess({ userId: 'attacker' }, 'p1'),
      await guardProject('p1'),
      await requireConversationAccess({ userId: 'attacker' }, 'c1'),
      await requireConversationAccessBySession({ userId: 'attacker' }, 's1'),
    ]
    for (const r of answers) {
      expect(r).toBeInstanceOf(NextResponse)
      expect((r as NextResponse).status).toBe(404)
      expect(await (r as NextResponse).json()).toEqual({ error: 'Not found' })
    }
  })

  test('a set ACCESS_ENFORCE logs one [rbac] warning saying it is ignored, once per process', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    process.env.ACCESS_ENFORCE = '0'
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    await requireProjectAccess({ userId: 'attacker' }, 'p1')
    await requireProjectAccess({ userId: 'attacker' }, 'p1')
    expect(accessEnforced()).toBe(true)
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0][0])).toMatch(/^\[rbac\] access_enforce_ignored: ACCESS_ENFORCE is set but ignored/)
    // The [BOLA] would-block line of the log-only mode is never written.
    expect(warn.mock.calls.flat().join(' ')).not.toContain('[BOLA]')
  })

  // An operator who sets ACCESS_ENFORCE=0 must learn it is ignored when the guards load, not
  // only at the first cross-user request (which may never come).
  test.each(['0', 'false'])('ACCESS_ENFORCE=%s at load: one warning before any check runs, never repeated', async (v) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    process.env.ACCESS_ENFORCE = v
    vi.resetModules()
    const fresh = await import('./access')
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0][0])).toMatch(/^\[rbac\] access_enforce_ignored: ACCESS_ENFORCE is set but ignored/)
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    expect(((await fresh.requireProjectAccess({ userId: 'attacker' }, 'p1')) as NextResponse).status).toBe(404)
    expect(fresh.assertOwner({ userId: 'attacker' }, 'victim')).toBeInstanceOf(NextResponse)
    expect(fresh.accessEnforced()).toBe(true)
    expect(warn).toHaveBeenCalledTimes(1)
  })

  test('unset or empty at load: no warning at load', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const v of [undefined, '', '  ']) {
      if (v === undefined) delete process.env.ACCESS_ENFORCE
      else process.env.ACCESS_ENFORCE = v
      vi.resetModules()
      await import('./access')
    }
    expect(warn).not.toHaveBeenCalled()
  })

  test('no warning while ACCESS_ENFORCE is unset or empty', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    await requireProjectAccess({ userId: 'attacker' }, 'p1')
    process.env.ACCESS_ENFORCE = ''
    await requireProjectAccess({ userId: 'attacker' }, 'p1')
    expect(accessEnforced()).toBe(true)
    expect(warn).not.toHaveBeenCalled()
  })
})

describe('ownerScope', () => {
  test('scopes to the effective user id', () => {
    expect(ownerScope({ userId: 'u9' })).toEqual({ userId: 'u9' })
  })
  test('an effective user without an id lists nothing (never every user’s rows)', () => {
    expect(ownerScope({ userId: '' })).toEqual({ userId: { in: [] } })
    expect(ownerScope({} as { userId: string })).toEqual({ userId: { in: [] } })
  })
})

describe('requireProjectAccess', () => {
  test('missing project -> 404', async () => {
    mockProjectFindUnique.mockResolvedValue(null)
    const r = await requireProjectAccess({ userId: 'u1' }, 'p1')
    expect((r as NextResponse).status).toBe(404)
  })
  test('owner -> returns project', async () => {
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'u1' })
    const r = await requireProjectAccess({ userId: 'u1' }, 'p1')
    expect(r).toEqual({ project: { id: 'p1', userId: 'u1' } })
  })
  test('non-owner, default enforce -> 404 (anti-enum cross-user block)', async () => {
    delete process.env.ACCESS_ENFORCE
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    const r = await requireProjectAccess({ userId: 'attacker' }, 'p1')
    expect((r as NextResponse).status).toBe(404)
  })
  // By design (step 3.5, PE-24): this returned the project under ACCESS_ENFORCE=0 (log-only).
  test('non-owner, ACCESS_ENFORCE=0 -> 404 all the same (log-only is gone)', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    process.env.ACCESS_ENFORCE = '0'
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    const r = await requireProjectAccess({ userId: 'attacker' }, 'p1')
    expect((r as NextResponse).status).toBe(404)
  })
  test('empty projectId -> 400', async () => {
    const r = await requireProjectAccess({ userId: 'u1' }, '')
    expect((r as NextResponse).status).toBe(400)
  })
})

describe('guardProject (one-call scan/analytics guard)', () => {
  test('no session -> 401', async () => {
    mockGetEffectiveUser.mockResolvedValue(null)
    const r = await guardProject('p1')
    expect((r as NextResponse).status).toBe(401)
  })
  test('owner -> null (allow)', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'u1' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'u1' })
    expect(await guardProject('p1')).toBeNull()
  })
  test('non-owner, enforce -> 404', async () => {
    delete process.env.ACCESS_ENFORCE
    mockGetEffectiveUser.mockResolvedValue({ userId: 'attacker' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'victim' })
    const r = await guardProject('p1')
    expect((r as NextResponse).status).toBe(404)
  })
})

describe('requireConversationAccess', () => {
  test('missing -> 404', async () => {
    mockConversationFindUnique.mockResolvedValue(null)
    const r = await requireConversationAccess({ userId: 'u1' }, 'c1')
    expect((r as NextResponse).status).toBe(404)
  })
  test('owner -> returns conversation', async () => {
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'u1', projectId: 'p1' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'u1' })
    const r = await requireConversationAccess({ userId: 'u1' }, 'c1')
    expect(r).toEqual({ conversation: { id: 'c1', userId: 'u1', projectId: 'p1' } })
  })
  test('non-owner, default enforce -> 404 (anti-enum)', async () => {
    delete process.env.ACCESS_ENFORCE
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'victim', projectId: 'p1' })
    const r = await requireConversationAccess({ userId: 'attacker' }, 'c1')
    expect((r as NextResponse).status).toBe(404)
  })
})

// The author keeps a conversation only while they can still see its project: after a transfer or
// a revoked membership the project is gone for them, and so are its conversations.
describe.each([
  ['requireConversationAccess', (eff: { userId: string }) => requireConversationAccess(eff, 'c1')],
  ['requireConversationAccessBySession', (eff: { userId: string }) => requireConversationAccessBySession(eff, 's1')],
])('%s: the author AND the project', (_name, check) => {
  test('the author on a project they still see -> the conversation', async () => {
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'u1', projectId: 'p1' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'u1' })
    expect(await check({ userId: 'u1' })).toEqual({ conversation: { id: 'c1', userId: 'u1', projectId: 'p1' } })
    expect(mockProjectFindUnique).toHaveBeenCalledWith(expect.objectContaining({ where: { id: 'p1' } }))
  })
  test('the author on a project now someone else sees -> 404, as for a missing one', async () => {
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'u1', projectId: 'p1' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'new-owner' })
    const r = await check({ userId: 'u1' })
    expect((r as NextResponse).status).toBe(404)
    expect(await (r as NextResponse).json()).toEqual({ error: 'Not found' })
  })
  test("the author on a project that is gone -> 404", async () => {
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'u1', projectId: 'p1' })
    mockProjectFindUnique.mockResolvedValue(null)
    expect(((await check({ userId: 'u1' })) as NextResponse).status).toBe(404)
  })
  test('the project alone never opens another author’s conversation -> 404', async () => {
    mockConversationFindUnique.mockResolvedValue({ id: 'c1', userId: 'victim', projectId: 'p1' })
    mockProjectFindUnique.mockResolvedValue({ id: 'p1', userId: 'u1' })
    expect(((await check({ userId: 'u1' })) as NextResponse).status).toBe(404)
  })
})
