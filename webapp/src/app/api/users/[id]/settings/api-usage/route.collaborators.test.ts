/**
 * The owner's API usage report gains a by-collaborator breakdown (step 5.6, C1; GV-12): with write
 * sharing on, GET lists who spent the owner's credentials on the projects they own in the last 30
 * days (the `credits.used` audit rows, ownerCredentials.ts `collaboratorSpends`, real here); with the
 * switch off the answer is the one it was, and no audit row is read. A failed read leaves the
 * breakdown out and the rest of the answer stands.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  auditFind: vi.fn(),
  projectFind: vi.fn(),
}))

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  getEffectiveUser: async () => ({ userId: 'owner-1' }),
  getSession: async () => ({ userId: 'owner-1', role: 'standard' }),
  isInternalRequest: () => false,
  isScannerRequest: () => false,
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    apiUsageReport: { findUnique: async () => null },
    scanJob: { findMany: async () => [] },
    conversation: { findMany: async () => [] },
    project: { findMany: (...a: unknown[]) => h.projectFind(...a) },
    auditLog: { findMany: (...a: unknown[]) => h.auditFind(...a) },
    user: { findMany: async () => [{ id: 'collab-1', name: 'Bob', email: 'bob@example.test' }] },
  },
}))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'

const get = () => GET(new NextRequest('http://x/api/users/owner-1/settings/api-usage'), { params: Promise.resolve({ id: 'owner-1' }) })

beforeEach(() => {
  h.projectFind.mockReset().mockResolvedValue([{ id: 'P1', name: 'Owned' }])
  h.auditFind.mockReset().mockResolvedValue([
    { actorId: 'collab-1', projectId: 'P1', after: { feature: 'agent_session', actor: 'collab-1' }, createdAt: new Date('2026-11-13T10:00:00Z') },
    { actorId: 'collab-1', projectId: 'P1', after: { feature: 'scan', actor: 'collab-1' }, createdAt: new Date('2026-11-12T10:00:00Z') },
  ])
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('usage report breakdown', () => {
  test('with write sharing on: who spent the owner\'s credentials, by collaborator', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collaboratorSpends).toEqual({
      sinceDays: 30, truncated: false,
      people: [{
        userId: 'collab-1', name: 'Bob', email: 'bob@example.test', total: 2, byFeature: { agent_session: 1, scan: 1 },
        projects: [{ id: 'P1', name: 'Owned', count: 2 }], lastAt: '2026-11-13T10:00:00.000Z',
      }],
    })
    // Only the projects this account owns are counted.
    expect(h.projectFind).toHaveBeenCalledWith(expect.objectContaining({ where: { userId: 'owner-1' } }))
  })

  test('with the switch off the answer is unchanged and no audit row is read', async () => {
    for (const flags of [{}, { identity: true, permissions: true, sharing: true }]) {
      setFlagsForTests(flags)
      const body = await (await get()).json()
      expect('collaboratorSpends' in body).toBe(false)
      expect(body).toMatchObject({ report: null, activity: { runningScans: [], agentRuns: [] } })
    }
    expect(h.auditFind).not.toHaveBeenCalled()
  })

  test('a failed read leaves the breakdown out; the report still answers', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    h.auditFind.mockRejectedValueOnce(Object.assign(new Error('db down: secret-ish detail'), { code: 'P1001' }))
    const res = await get()
    expect(res.status).toBe(200)
    expect('collaboratorSpends' in (await res.json())).toBe(false)
    const line = vi.mocked(console.error).mock.calls.map(c => String(c[0])).find(l => l.includes('collaborator spends'))
    expect(line).toContain('P1001')
    expect(line).not.toContain('secret-ish')
  })
})
