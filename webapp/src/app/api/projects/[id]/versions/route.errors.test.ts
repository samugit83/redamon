/**
 * The version routes answer a failure with a fixed sentence and a code, never
 * the exception's text (a Prisma or Neo4j message can quote query values), and
 * a throw before their try/catch is a readable 500 instead of Next's empty one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  requireEff: vi.fn(),
  queryRaw: vi.fn(),
  ensureCurrent: vi.fn(),
  capture: vi.fn(),
  isActivating: vi.fn(),
  requireVersion: vi.fn(),
  update: vi.fn(),
  remove: vi.fn(),
  findJob: vi.fn(),
  loadSnapshot: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.requireEff(),
  requireProjectAccess: async () => ({}),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: (...a: unknown[]) => h.queryRaw(...a),
    scanVersion: { update: (...a: unknown[]) => h.update(...a), delete: (...a: unknown[]) => h.remove(...a) },
    scanJob: { findFirst: (...a: unknown[]) => h.findJob(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.isActivating(...a) }))
vi.mock('@/lib/graphWriters', () => ({
  describeScanWriters: async () => null,
  describeSecondaryScanWriters: async () => null,
}))
vi.mock('@/lib/scanRetention', () => ({ applyRetentionSafe: vi.fn() }))
vi.mock('@/lib/scanTimeline', () => ({ rotateToNextVersion: vi.fn() }))
vi.mock('@/lib/scanVersionAccess', () => ({ requireVersionInProject: (...a: unknown[]) => h.requireVersion(...a) }))
vi.mock('@/lib/scanSnapshot', async orig => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  ensureCurrentVersion: (...a: unknown[]) => h.ensureCurrent(...a),
  captureGraphSnapshot: (...a: unknown[]) => h.capture(...a),
  storeSnapshot: vi.fn(),
  loadSnapshot: (...a: unknown[]) => h.loadSnapshot(...a),
}))
vi.mock('@/app/api/graph/liveRead', () => ({ readLiveGraph: vi.fn() }))

import { GET as list, POST as saveCurrent } from './route'
import { PATCH as rename, DELETE as remove } from './[versionId]/route'
import { GET as versionGraph } from './[versionId]/graph/route'

const withCode = (message: string, code: string) => Object.assign(new Error(message), { code })
const project = { params: Promise.resolve({ id: 'p1' }) }
const version = { params: Promise.resolve({ id: 'p1', versionId: 'v1' }) }
const req = (body?: unknown) => new NextRequest('http://x/api/projects/p1/versions', {
  method: 'POST', ...(body === undefined ? {} : { body: JSON.stringify(body) }),
})

beforeEach(() => {
  vi.resetAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.requireEff.mockResolvedValue({ userId: 'u1' })
  h.isActivating.mockResolvedValue(false)
  h.requireVersion.mockResolvedValue({ id: 'v1', label: 'Scan 1', pinned: false, isCurrent: false, seq: 1 })
  h.findJob.mockResolvedValue(null)
})

describe('versions routes', () => {
  test('a failed list answers its code, not the SQL', async () => {
    h.ensureCurrent.mockResolvedValue({ id: 'v1' })
    h.queryRaw.mockRejectedValue(withCode('Timed out fetching a new connection (SELECT sv.id ... p1)', 'P2024'))
    const res = await list(req(), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to list versions', code: 'P2024' })
  })

  test('a session read that throws before the try is readable, not an empty 500', async () => {
    h.requireEff.mockRejectedValue(withCode('session store down', 'ECONNREFUSED'))
    const res = await list(req(), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to list versions', code: 'ECONNREFUSED' })
  })

  test('a failed save-current answers its Neo4j code', async () => {
    h.capture.mockRejectedValue(withCode('MATCH (n) WHERE n.name = "alpha.test"', 'Neo.ClientError.Statement.SyntaxError'))
    const res = await saveCurrent(req({}), project)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'Failed to save the current graph as a version', code: 'Neo.ClientError.Statement.SyntaxError',
    })
  })

  test('a failed rename and a failed delete answer their codes', async () => {
    h.update.mockRejectedValue(withCode('Unique constraint failed on label "x"', 'P2002'))
    const renamed = await rename(new NextRequest('http://x', { method: 'PATCH', body: JSON.stringify({ label: 'New' }) }), version)
    expect(await renamed.json()).toEqual({ error: 'Failed to update version', code: 'P2002' })

    h.remove.mockRejectedValue(withCode('Record to delete does not exist.', 'P2025'))
    const removed = await remove(new NextRequest('http://x', { method: 'DELETE' }), version)
    expect(removed.status).toBe(500)
    expect(await removed.json()).toEqual({ error: 'Failed to delete version', code: 'P2025' })
  })

  test('a version graph that cannot be read answers its code', async () => {
    h.loadSnapshot.mockRejectedValue(new RangeError('Invalid array length while decoding alpha.test'))
    const res = await versionGraph(new NextRequest('http://x'), version)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to read version graph', code: 'RangeError' })
  })
})
