/**
 * A bundle exported before L-17 still imports (L-17).
 *
 * katanaScope, jsReconStandaloneCrawlDepth, jsReconStandaloneCrawlScope and
 * aiSurfaceReconCacheEnabled are retired: nothing reads them and no surface
 * offers them, but the columns stay, so a bundle carrying them imports as
 * before and its values sit in columns the pipeline ignores.
 *
 * Same harness as route.bounds.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn(), findUser: vi.fn() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    user: { findUnique: (...a: unknown[]) => h.findUser(...a) },
    engagementAuthorization: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

const RETIRED = {
  katanaScope: 'dn',
  jsReconStandaloneCrawlDepth: 3,
  jsReconStandaloneCrawlScope: 'subdomain',
  aiSurfaceReconCacheEnabled: true,
}

async function bundle(project: Record<string, unknown>): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.invalid',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    ...project,
  }))
  const buf = await zip.generateAsync({ type: 'arraybuffer' })
  const fd = new FormData()
  fd.set('file', new File([buf], 'p.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.createProject.mockResolvedValue({ id: 'new', name: 'imported' })
  h.findUser.mockResolvedValue({ defaultAgentModel: null })
})

describe('import: the settings L-17 removed', () => {
  test('an older bundle carrying them imports, with the rest of its settings', async () => {
    const res = await POST(await bundle({ ...RETIRED, katanaDepth: 3 }))
    expect(res.status).toBe(200)
    const data = h.createProject.mock.calls[0][0].data as Record<string, unknown>
    expect(data.katanaDepth).toBe(3)
  })
})
