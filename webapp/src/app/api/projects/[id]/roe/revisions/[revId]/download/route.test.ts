/**
 * GET /api/projects/[id]/roe/revisions/[revId]/download: a superseded RoE document stays the
 * owner's on a shared project (OQ-53). The revision list is metadata and stays a read.
 *
 * The guard is doubled to grant the access level under test: until step 4.3 projectAccess() only
 * ever answers the owner, so a read collaborator exists here only as that level.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  level: 'owner' as string,
  revisionFindFirst: vi.fn(), revisionFindMany: vi.fn(), audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    roeDocumentRevision: {
      findFirst: (...a: unknown[]) => h.revisionFindFirst(...a),
      findMany: (...a: unknown[]) => h.revisionFindMany(...a),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/roe/actor', () => ({ actingAdminId: async () => null }))
vi.mock('@/lib/authz/guards', async () => {
  const real = await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')
  return {
    ...real,
    requirePermission: async (_r: Request, permission: string, opts: { projectId?: string } = {}) => ({
      session: { userId: 'caller-1', role: 'standard' },
      principal: { id: 'caller-1', role: 'standard' },
      actingAs: null,
      effective: { userId: 'caller-1' },
      permission,
      access: { project: { id: opts.projectId, userId: 'owner-1' }, level: h.level },
    }),
  }
})

import { GET as DOWNLOAD } from './route'
import { GET as LIST } from '../../route'

const BYTES = Buffer.from('%PDF-1.4 superseded synthetic')

beforeEach(() => {
  vi.clearAllMocks()
  h.level = 'owner'
  h.revisionFindFirst.mockResolvedValue({ data: BYTES, documentName: 'old.pdf', mimeType: 'application/pdf' })
  h.revisionFindMany.mockResolvedValue([{ id: 'r1', documentName: 'old.pdf' }])
})

const download = () =>
  DOWNLOAD(new NextRequest('http://x/api/projects/proj-1/roe/revisions/r1/download'), {
    params: Promise.resolve({ id: 'proj-1', revId: 'r1' }),
  })

describe('owner only (OQ-53)', () => {
  test('read collaborator 403', async () => {
    h.level = 'read'
    const res = await download()
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: "Only the project's owner can download the rules of engagement document.",
      code: 'owner_only',
      permission: 'roe:read',
    })
    expect(h.revisionFindFirst).not.toHaveBeenCalled()
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('owner unchanged', async () => {
    const res = await download()
    expect(res.status).toBe(200)
    expect(Buffer.from(await res.arrayBuffer()).equals(BYTES)).toBe(true)
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'project.roe.download', targetId: 'proj-1', actorId: 'caller-1',
    }))
  })

  test('a read collaborator still lists the revisions (metadata only)', async () => {
    h.level = 'read'
    const res = await LIST(new NextRequest('http://x/api/projects/proj-1/roe/revisions'), { params: Promise.resolve({ id: 'proj-1' }) })
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain('superseded synthetic')
  })
})
