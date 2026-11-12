/**
 * The superseded RoE documents are the owner's, like the current one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  ownerId: 'owner', eff: { userId: 'owner' } as unknown,
  revisionFindFirst: vi.fn(), revisionFindMany: vi.fn(), audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => ({ id: 'proj-1', userId: h.ownerId }) },
    roeDocumentRevision: {
      findFirst: (...a: unknown[]) => h.revisionFindFirst(...a),
      findMany: (...a: unknown[]) => h.revisionFindMany(...a),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: async () => h.eff }
})

import { GET as LIST } from './route'
import { GET as DOWNLOAD } from './[revId]/download/route'

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  h.ownerId = 'owner'
  h.eff = { userId: 'owner' }
  h.revisionFindMany.mockResolvedValue([{ id: 'r1', documentName: 'A.pdf' }])
  h.revisionFindFirst.mockResolvedValue({ data: Buffer.from('A bytes'), documentName: 'A.pdf', mimeType: 'application/pdf' })
})

const list = () => LIST(new NextRequest('http://x/api/projects/proj-1/roe/revisions'), { params: Promise.resolve({ id: 'proj-1' }) })
const download = (revId = 'r1') =>
  DOWNLOAD(new NextRequest(`http://x/api/projects/proj-1/roe/revisions/${revId}/download`), {
    params: Promise.resolve({ id: 'proj-1', revId }),
  })

describe('revisions', () => {
  test('the owner lists metadata without the bytes', async () => {
    const res = await list()
    expect(res.status).toBe(200)
    expect((await res.json()).revisions).toEqual([{ id: 'r1', documentName: 'A.pdf' }])
    expect(h.revisionFindMany.mock.calls[0][0].select).not.toHaveProperty('data')
  })

  test('another user gets a 404 for both the list and a download', async () => {
    h.ownerId = 'victim'
    h.eff = { userId: 'attacker' }
    expect((await list()).status).toBe(404)
    expect((await download()).status).toBe(404)
    expect(h.revisionFindFirst).not.toHaveBeenCalled()
  })

  test('a download is scoped to the project, served safely and audited', async () => {
    const res = await download()
    expect(res.status).toBe(200)
    expect(h.revisionFindFirst.mock.calls[0][0].where).toEqual({ id: 'r1', projectId: 'proj-1' })
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'project.roe.download' }))
  })

  test('a revision of another project is not found', async () => {
    h.revisionFindFirst.mockResolvedValue(null)
    expect((await download('other-project-rev')).status).toBe(404)
  })
})

describe('a database failure names its code', () => {
  const prismaError = () => Object.assign(new Error('Can\'t reach database server at `db:5432`'), {
    code: 'P1001', name: 'PrismaClientInitializationError',
  })
  beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })

  test('the list', async () => {
    h.revisionFindMany.mockRejectedValue(prismaError())
    const res = await list()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to list RoE revisions', code: 'P1001' })
  })

  test('a revision download', async () => {
    h.revisionFindFirst.mockRejectedValue(prismaError())
    const res = await download()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to download the RoE revision', code: 'P1001' })
  })
})
