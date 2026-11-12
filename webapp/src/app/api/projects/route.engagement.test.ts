/**
 * Strategy row 8 (L5): the engagement columns survive POST /api/projects.
 *
 * This route does not name `engagementKind` anywhere. It passes a field through
 * only if the GENERATED Prisma client lists it in `ProjectScalarFieldEnum`, so
 * a schema change that was never pushed, or a client that was never
 * regenerated, silently drops the column and the project is created as the
 * schema default `internal`. Nothing fails; the operator sets up a third-party
 * engagement in the form and gets an internal one, which is the project that
 * scans somebody else's estate with no ceiling required.
 *
 * That makes this a test of the generated client as much as of the handler,
 * which is why it asserts on the enum directly as well as through the route.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/api/projects/route.engagement.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()
const mockProjectUpdate = vi.fn()
const mockRun = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: {
      create: (...a: unknown[]) => mockProjectCreate(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: vi.fn() }),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { Prisma } from '@prisma/client'
import { NextRequest } from 'next/server'
import { POST } from './route'

function postReq(body: Record<string, unknown>) {
  return new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const createdData = () => mockProjectCreate.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  mockProjectCreate.mockResolvedValue({ id: 'p1', name: 'test' })
  mockProjectUpdate.mockResolvedValue({})
  mockRun.mockResolvedValue({ records: [] })
})

describe('row 8: the generated client knows the engagement columns', () => {
  test.each(['engagementKind', 'engagementIdentityHeader'])('%s is a Project scalar', name => {
    expect(Object.values(Prisma.ProjectScalarFieldEnum)).toContain(name)
  })

  test('ScanJob carries the settings fingerprint and the authorization it ran under', () => {
    for (const name of ['settingsHash', 'authorizationId']) {
      expect(Object.values(Prisma.ScanJobScalarFieldEnum), name).toContain(name)
    }
  })
})

describe('row 8: engagementKind is persisted, not defaulted', () => {
  test('third_party reaches the create call', async () => {
    const res = await POST(postReq({
      name: 'test', targetDomain: 'example.invalid', engagementKind: 'third_party',
      roeGlobalMaxRps: 3,
    }))
    expect(res.status).toBeLessThan(400)
    expect(createdData().engagementKind).toBe('third_party')
  })

  test('the ceiling that makes it usable is persisted with it', async () => {
    await POST(postReq({
      name: 'test', targetDomain: 'example.invalid', engagementKind: 'third_party',
      roeGlobalMaxRps: 3,
    }))
    // The DERIVED flag is dropped, not stored: a ceiling alone is what makes the
    // limits live, and a persisted copy could only ever disagree with it.
    expect(createdData()).not.toHaveProperty('roeEnabled')
    expect(createdData().roeGlobalMaxRps).toBe(3)
  })

  test('the identity header survives the form, which sends it as a string', async () => {
    await POST(postReq({
      name: 'test', targetDomain: 'example.invalid',
      engagementIdentityHeader: 'X-Bug-Bounty: researcher-7f3a',
    }))
    expect(createdData().engagementIdentityHeader).toBe('X-Bug-Bounty: researcher-7f3a')
  })

  test('omitting it leaves the column to its schema default', async () => {
    // Existing rows and ordinary projects read as internal; the route must not
    // write an explicit value it was not given.
    await POST(postReq({ name: 'test', targetDomain: 'example.invalid' }))
    expect(createdData()).not.toHaveProperty('engagementKind')
  })

  test('a string "true" from the multipart form is coerced, not stored as a string', async () => {
    await POST(postReq({
      name: 'test', targetDomain: 'example.invalid',
      engagementKind: 'third_party', roeEnabled: 'true', roeGlobalMaxRps: '3',
    }))
    // The DERIVED flag is dropped, not stored: a ceiling alone is what makes the
    // limits live, and a persisted copy could only ever disagree with it.
    expect(createdData()).not.toHaveProperty('roeEnabled')
    expect(createdData().roeGlobalMaxRps).toBe(3)
  })
})
