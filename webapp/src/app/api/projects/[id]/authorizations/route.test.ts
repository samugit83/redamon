/**
 * A failed read of the authorization records answers a code, so the panel can
 * show why it could not tell whether the engagement is authorized.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/projects/[id]/authorizations/route.test.ts"
 * @vitest-environment node
 */
import { test, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'

const findMany = vi.fn()

vi.mock('@/lib/prisma', () => ({ default: { engagementAuthorization: { findMany: (...a: unknown[]) => findMany(...a) } } }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'owner' }),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
}))

import { GET } from './route'

test('a database failure answers the fixed sentence and the Prisma code', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  findMany.mockRejectedValue(Object.assign(new Error('relation "EngagementAuthorization" does not exist'), { code: 'P2021' }))
  const res = await GET(new NextRequest('http://x/api/projects/p1/authorizations'), { params: Promise.resolve({ id: 'p1' }) })
  expect(res.status).toBe(500)
  expect(await res.json()).toEqual({ error: 'Failed to list engagement authorizations', code: 'P2021' })
})
