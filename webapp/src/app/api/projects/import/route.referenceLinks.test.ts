/**
 * Import hands the bundle's links to the global CVE / MitreData / Capec nodes
 * to the restore (plan 09.5), and a bundle exported before link records existed
 * imports exactly as before. The validation of each record (label allowlist,
 * key shape, MATCH only) is graphReferenceLinks.ts's, tested there.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ restoreGraph: vi.fn(), clearProjectGraph: vi.fn() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: vi.fn().mockResolvedValue({ id: 'newProject', name: 'src' }) },
    conversation: { create: vi.fn() },
    chatMessage: { createMany: vi.fn() },
    remediation: { createMany: vi.fn() },
    report: { create: vi.fn() },
    userProjectPreset: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/graphRestore', () => ({
  clearProjectGraph: (...a: unknown[]) => h.clearProjectGraph(...a),
  restoreGraph: (...a: unknown[]) => h.restoreGraph(...a),
}))

import { POST } from './route'
import { REFERENCE_LINKS_BUNDLE_PATH } from '@/lib/graphReferenceLinks'

const LINKS = [{
  startExportId: 'n1', endExportId: null, type: 'INCLUDES_CVE',
  refLabel: 'CVE', refKey: 'CVE-2021-23017', properties: {},
}]

async function bundle(withLinks: boolean): Promise<File> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: withLinks ? '1.1.0' : '1.0.0', projectName: 'src', stats: {} }))
  zip.file('project.json', JSON.stringify({ id: 'oldProject', userId: 'oldOwner', name: 'src', targetDomain: 'example.com' }))
  zip.file('neo4j/nodes.json', JSON.stringify([
    { labels: ['Vulnerability'], properties: { id: 'v1' }, _exportId: 'n1' }]))
  zip.file('neo4j/relationships.json', JSON.stringify([]))
  if (withLinks) zip.file(REFERENCE_LINKS_BUNDLE_PATH, JSON.stringify(LINKS))
  const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
  return new File([buf], 'export.zip', { type: 'application/zip' })
}

const req = (file: File) => {
  const fd = new FormData()
  fd.set('file', file)
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.restoreGraph.mockResolvedValue({ nodes: 1, relationships: 0, referenceLinks: { restored: 1, skipped: 0 } })
})

describe('import — links to the reference catalogue', () => {
  test('the link records reach the restore, and the counts reach the answer', async () => {
    const res = await POST(req(await bundle(true)))
    expect(res.status).toBe(200)
    const [, , , opts] = h.restoreGraph.mock.calls[0]
    expect(opts).toMatchObject({ projectId: 'newProject', userId: 'importer', referenceLinks: LINKS })
    const body = await res.json()
    expect(body.stats).toMatchObject({ neo4jReferenceLinks: 1, neo4jReferenceLinksSkipped: 0 })
  })

  test('a bundle from before link records restores as before', async () => {
    h.restoreGraph.mockResolvedValue({ nodes: 1, relationships: 0 })
    const res = await POST(req(await bundle(false)))
    expect(res.status).toBe(200)
    const [, , , opts] = h.restoreGraph.mock.calls[0]
    expect(opts.referenceLinks).toBeUndefined()
  })

  test('a link file that is not a list is ignored, not trusted', async () => {
    const zip = await JSZip.loadAsync(await (await bundle(true)).arrayBuffer())
    zip.file(REFERENCE_LINKS_BUNDLE_PATH, JSON.stringify({ refLabel: 'CVE' }))
    const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
    const res = await POST(req(new File([buf], 'export.zip')))
    expect(res.status).toBe(200)
    expect(h.restoreGraph.mock.calls[0][3].referenceLinks).toBeUndefined()
  })
})
