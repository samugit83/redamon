/**
 * Project export leaves plugin rows out, and says so (OQ-18, X25). Even for a project that has
 * a project-scope skill version and project-owned plugin data, the archive holds no plugin file,
 * the route never reads the plugin tables, and the manifest names what it excluded and why.
 *
 * Runs the real export route; Prisma is a stand-in that answers every query with nothing (and
 * records which tables were touched), Neo4j an empty session.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ touched: new Set<string>() }))

const PROJECT = {
  id: 'p1',
  userId: 'u1',
  name: 'Example project',
  targetDomain: 'example.com',
  engagementKind: 'internal',
  createdAt: new Date('2026-01-01T00:00:00Z'),
  updatedAt: new Date('2026-01-01T00:00:00Z'),
}

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'u1' }),
  requireProjectAccess: async () => ({ ok: true }),
}))
vi.mock('@/lib/prisma', () => {
  const model = (name: string) =>
    new Proxy(
      {},
      {
        get: (_t, method: string) => async () => {
          h.touched.add(name)
          if (name === 'project' && (method === 'findUnique' || method === 'findFirst')) return PROJECT
          if (method === 'findMany') return []
          if (method === 'count') return 0
          return null
        },
      },
    )
  return { default: new Proxy({}, { get: (_t, name: string) => model(name) }) }
})
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: async () => ({ records: [] }), close: async () => {} }),
}))
vi.mock('@/lib/reconPresets/server', () => ({ projectPresetForRead: async () => null }))
vi.mock('fs', async (orig) => ({
  ...(await orig<typeof import('fs')>()),
  existsSync: () => false,
  readdirSync: () => [],
}))

import { GET } from './export/route'
import { PROJECT_EXPORT_EXCLUDED } from '@/lib/projectExport/pluginExclusion'

async function exportArchive(): Promise<JSZip> {
  const res = await GET(new Request('http://localhost:3000/api/projects/p1/export') as never, { params: Promise.resolve({ id: 'p1' }) })
  expect(res.status).toBe(200)
  return JSZip.loadAsync(await res.arrayBuffer())
}

beforeEach(() => h.touched.clear())

describe('plugin rows stay out of a project export', () => {
  test('the manifest names the excluded kinds and the reason', async () => {
    const zip = await exportArchive()
    const manifest = JSON.parse(await zip.file('manifest.json')!.async('string'))
    expect(manifest.excluded).toEqual([...PROJECT_EXPORT_EXCLUDED])
    expect(manifest.excludedReason).toMatch(/plugin installation/i)
  })

  test('the archive holds no plugin file', async () => {
    const zip = await exportArchive()
    const names = Object.keys(zip.files)
    expect(names.some((n) => /plugin/i.test(n))).toBe(false)
  })

  test('the route never reads the plugin tables', async () => {
    await exportArchive()
    expect(h.touched.has('pluginOverride')).toBe(false)
    expect(h.touched.has('pluginData')).toBe(false)
    expect(h.touched.has('pluginInstall')).toBe(false)
    // and it did read the project, so the stand-in was really in use
    expect(h.touched.has('project')).toBe(true)
  })
})
