/**
 * Import and the Jev engine flags.
 *
 * Import keeps hook choices but strips account-scoped provider ids. Every
 * enabled hook warns about static fallback until the imported project selects
 * a provider, even when the importer already owns a Jev configuration.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn(), providerFind: vi.fn() }))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    engagementAuthorization: { create: vi.fn() },
    userLlmProvider: { findFirst: (...a: unknown[]) => h.providerFind(...a) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

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
  h.providerFind.mockResolvedValue(null)
})

describe('importing a bundle whose hooks run on Jev', () => {
  test('the engine choice is kept and each hook is named in a warning when the importer has no provider selection', async () => {
    const res = await POST(await bundle({ ffufAiUseJev: true, takeoverAiUseJev: true, jevProviderId: 'exported-selection' }))
    expect(res.status).toBe(200)
    const created = h.createProject.mock.calls[0][0].data
    expect(created.ffufAiUseJev).toBe(true)
    expect(created.takeoverAiUseJev).toBe(true)
    expect(created).not.toHaveProperty('jevProviderId')
    const { warnings } = await res.json()
    expect(warnings).toHaveLength(2)
    expect(warnings[0]).toContain('ffufAiUseJev')
    expect(warnings[1]).toContain('takeoverAiUseJev')
    expect(warnings.join(' ')).toContain('static fallback')
    expect(warnings.join(' ')).toContain('select a Jev provider')
    expect(h.providerFind).not.toHaveBeenCalled()
  })

  test('an account provider does not suppress warnings or restore exported selection ids', async () => {
    h.providerFind.mockResolvedValue({ id: 'jev-selected' })
    const res = await POST(await bundle({ wafAiUseJev: true, jevProviderId: 'jev-selected' }))
    expect(res.status).toBe(200)
    const { warnings } = await res.json()
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('wafAiUseJev (WAF classification)')
    expect(warnings[0]).toContain('static fallback')
    expect(h.createProject.mock.calls[0][0].data).not.toHaveProperty('jevProviderId')
    expect(h.providerFind).not.toHaveBeenCalled()
  })

  test('a provider lookup configured to fail is never attempted during import', async () => {
    h.providerFind.mockRejectedValue(new Error('db down'))
    const res = await POST(await bundle({ nucleiTagsAiUseJev: true }))
    expect(res.status).toBe(200)
    const { warnings } = await res.json()
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('nucleiTagsAiUseJev (Nuclei tag selection)')
    expect(h.createProject).toHaveBeenCalled()
    expect(h.providerFind).not.toHaveBeenCalled()
  })

  test('a bundle with no Jev hook still strips its selection without warning or lookup', async () => {
    const res = await POST(await bundle({ ffufAiUseJev: false, jevProviderId: 'exported-selection' }))
    expect(res.status).toBe(200)
    expect((await res.json()).warnings).toEqual([])
    expect(h.createProject.mock.calls[0][0].data).not.toHaveProperty('jevProviderId')
    expect(h.providerFind).not.toHaveBeenCalled()
  })
})

describe('importing a bundle with a Jev-only hook on', () => {
  test('the flag is kept and named in a warning when the importer has no provider selection', async () => {
    const res = await POST(await bundle({ hakrawlerJevSeedOrder: true }))
    expect(res.status).toBe(200)
    expect(h.createProject.mock.calls[0][0].data.hakrawlerJevSeedOrder).toBe(true)
    const { warnings } = await res.json()
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('hakrawlerJevSeedOrder (Hakrawler seed order)')
  })
})
