/**
 * Scan Timeline activation and the hostname policy (design §6.3, P4).
 *
 * A version captured before a narrowing holds hostnames still marked
 * `scanned` that the project's CURRENT policy no longer admits. Every reader
 * already re-applies the current policy, so they drop them either way; the
 * activation also re-runs the narrowing marker after its restore so the graph
 * (the drawer, the preview) agrees, and says whether that worked as
 * `hostnamePolicyMarked`. The marker is best-effort: its failure never fails
 * the activation, whose restore and pointer move already committed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  order: [] as string[],
  findProject: vi.fn(),
  mark: vi.fn(),
  txUpdate: vi.fn(),
  txUpdateMany: vi.fn(),
  invalidate: vi.fn(),
}))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'operator' }),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
}))
vi.mock('@/lib/scanVersionAccess', () => ({
  requireVersionInProject: async () => ({
    id: 'v1', projectId: 'p1', seq: 1, label: 'Scan 1', isCurrent: false, pinned: false,
    nodeCount: 3, linkCount: 2, createdAt: new Date(), hasSnapshot: true,
  }),
}))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: async () => null }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/lib/activationLock', () => ({
  acquireActivationLock: async () => ({ acquired: true }),
  releaseActivationLock: async () => undefined,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: {
    $transaction: async (fn: (tx: unknown) => unknown) => {
      h.order.push('pointer')
      return fn({ scanVersion: { update: h.txUpdate, updateMany: h.txUpdateMany } })
    },
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
  },
}))
vi.mock('@/lib/scanSnapshot', async orig => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  captureGraphSnapshot: async () => ({ nodes: [{}], relationships: [], nodeCount: 7, linkCount: 3, summary: {} }),
  storeSnapshot: async () => ({ bytes: 100 }),
  loadSnapshot: async () => ({ nodes: [{ labels: ['Subdomain'], properties: {}, _exportId: 'n1' }], relationships: [] }),
  ensureCurrentVersion: async () => ({ id: 'v2', seq: 2, label: 'Scan 2' }),
}))
vi.mock('@/lib/graphRestore', () => ({
  clearProjectGraph: async () => { h.order.push('clear') },
  restoreGraph: async () => { h.order.push('restore'); return { nodes: 1, relationships: 0 } },
  sweepOrphanReferenceNodes: async () => undefined,
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: (...a: unknown[]) => { h.order.push('invalidate'); h.invalidate(...a) } }))
vi.mock('@/lib/ipHostnamePolicy', () => ({
  markOutOfPolicy: async (...a: unknown[]) => { h.order.push('mark'); return h.mark(...a) },
}))

import { POST } from './route'

const ROW = { userId: 'owner', ipMode: true, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'],
  ipHostnameExclude: ['old.example.com'] }
const activate = () => POST(new NextRequest('http://x/api/projects/p1/versions/v1/activate', { method: 'POST' }),
  { params: Promise.resolve({ id: 'p1', versionId: 'v1' }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.order = []
  h.findProject.mockResolvedValue(ROW)
  h.mark.mockResolvedValue(true)
})

describe('activation re-runs the hostname policy marker', () => {
  test('after the restore and the pointer move, for the project\'s current policy and owner', async () => {
    const res = await activate()
    expect(res.status).toBe(200)
    expect((await res.json()).hostnamePolicyMarked).toBe(true)
    expect(h.order).toEqual(['clear', 'restore', 'pointer', 'mark', 'invalidate'])
    expect(h.mark).toHaveBeenCalledWith('p1', 'owner', ROW)
    const query = h.findProject.mock.calls[0][0]
    expect(query.where).toEqual({ id: 'p1' })
    expect(query.select).toMatchObject({ userId: true, ipMode: true, ipHostnameMode: true,
      ipHostnameInclude: true, ipHostnameExclude: true })
  })

  test('a marker that fails keeps the activation and says so', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    h.mark.mockRejectedValue(new Error('neo4j down'))
    const res = await activate()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(true)
    expect(body.hostnamePolicyMarked).toBe(false)
    expect(h.txUpdate).toHaveBeenCalled()
  })

  test('a project row that cannot be read is reported, never a failed activation', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    h.findProject.mockResolvedValue(null)
    expect((await (await activate()).json()).hostnamePolicyMarked).toBe(false)
    h.findProject.mockRejectedValue(new Error('pg down'))
    expect((await (await activate()).json()).hostnamePolicyMarked).toBe(false)
    expect(h.mark).not.toHaveBeenCalled()
  })
})
