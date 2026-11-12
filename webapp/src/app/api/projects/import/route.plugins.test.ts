/**
 * Project import never brings plugin rows in (OQ-18, X25). The import reads only the files it
 * names, so a plugin file added to an archive by hand is never read: no plugin table is
 * touched, and the result warns that plugin skill versions and data are not imported.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ touched: new Set<string>() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }) }))
vi.mock('@/lib/prisma', () => {
  const model = (name: string) =>
    new Proxy(
      {},
      {
        get: (_t, method: string) => async () => {
          h.touched.add(name)
          if (name === 'project' && method === 'create') return { id: 'new', name: 'imported' }
          if (method === 'findMany') return []
          if (method === 'count') return 0
          return null
        },
      },
    )
  return { default: new Proxy({}, { get: (_t, name: string) => model(name) }) }
})
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

async function bundle(extra: Record<string, string>): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1.0.0', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.com', engagementKind: 'internal',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  }))
  for (const [name, body] of Object.entries(extra)) zip.file(name, body)
  const buf = await zip.generateAsync({ type: 'arraybuffer' })
  const fd = new FormData()
  fd.set('file', new File([buf], 'p.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

const OVERRIDE_ROWS = JSON.stringify([
  { pluginId: 'skiller', extensionPoint: 'skill.text', scopeType: 'project', scopeId: 'old', targetGroup: 'ssrf', targetKey: 'ssrf/workflow', value: 'hand-added', status: 'active' },
])

beforeEach(() => h.touched.clear())

describe('plugin rows are never imported', () => {
  test('hand-added plugin files create no plugin rows; the result warns and says what is excluded', async () => {
    const res = await POST(await bundle({
      'plugins/overrides.json': OVERRIDE_ROWS,
      'plugins/data.json': JSON.stringify([{ pluginId: 'skiller', collection: 'c', key: 'k', value: {} }]),
    }))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.success).toBe(true)
    expect(h.touched.has('pluginOverride')).toBe(false)
    expect(h.touched.has('pluginData')).toBe(false)
    expect(h.touched.has('pluginInstall')).toBe(false)
    expect(body.warnings.some((w: string) => /plugin skill versions and plugin data are not imported/i.test(w))).toBe(true)
    expect(body.excluded).toEqual(['plugin_overrides', 'plugin_data'])
  })

  test('an ordinary archive imports without a plugin warning, still naming the excluded kinds', async () => {
    const res = await POST(await bundle({}))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.warnings.some((w: string) => /plugin/i.test(w))).toBe(false)
    expect(body.excluded).toEqual(['plugin_overrides', 'plugin_data'])
    expect(h.touched.has('pluginOverride')).toBe(false)
  })
})
