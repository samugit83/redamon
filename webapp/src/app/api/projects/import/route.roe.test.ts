/**
 * Import and the stored RoE parse: a bundle may not plant keys in it.
 *
 * The next RoE replace reads `roeParsedJson.applied` as what the previous
 * document set and may restore those keys, so a bundle carrying
 * `applied.targetDomain` would make scope writable through a document.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    engagementAuthorization: { create: vi.fn() },
    userLlmProvider: { count: async () => 0 },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'
import { digestScopeDocument } from '@/lib/engagement'

async function bundle(project: Record<string, unknown>): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'roe-e2e.example',
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
})

describe('importing a stored RoE parse', () => {
  test('a planted scope key is dropped and the text hash is recomputed', async () => {
    const res = await POST(await bundle({
      roeRawText: 'imported RoE text',
      roeParsedJson: { version: 2, applied: { targetDomain: 'evil.example', roeGlobalMaxRps: 5 }, textSha256: '0'.repeat(64) },
    }))
    expect(res.status).toBe(200)
    const parsed = h.createProject.mock.calls[0][0].data.roeParsedJson
    expect(parsed.applied).toEqual({ roeGlobalMaxRps: 5 })
    expect(parsed.textSha256).toBe(digestScopeDocument('imported RoE text'))
  })

  test('a parse from a later format is not imported at all', async () => {
    await POST(await bundle({ roeParsedJson: { version: 9, applied: { roeGlobalMaxRps: 5 } } }))
    expect(h.createProject.mock.calls[0][0].data).not.toHaveProperty('roeParsedJson')
  })
})
