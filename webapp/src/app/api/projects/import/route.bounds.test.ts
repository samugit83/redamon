/**
 * Import is a second creation path, so a bundle's numbers get the registry
 * bounds create_project applies (R-7): refused in the same words, never
 * clamped. Before, `nucleiRateLimit: 0` imported fine and nuclei then ran at
 * its built-in rate under the engagement ceiling.
 *
 * Same harness as route.loopModel.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn(), findUser: vi.fn() }))

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
import { filterReconSettings } from '@/lib/reconSettings/filter'

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

const created = () => h.createProject.mock.calls[0][0].data as Record<string, unknown>

describe('a number outside its registry bound', () => {
  test('nucleiRateLimit: 0 refuses the bundle in create_project\'s words, and nothing is created', async () => {
    const res = await POST(await bundle({ nucleiRateLimit: 0, katanaDepth: 2 }))
    expect(res.status).toBe(400)
    const body = await res.json()
    const mcp = filterReconSettings({ nucleiRateLimit: 0 }, { mode: 'create' })
    expect(mcp.ok).toBe(false)
    expect(body.error).toBe(`${mcp.ok ? '' : mcp.error} The bundle was not imported.`)
    expect(body.key).toBe('nucleiRateLimit')
    expect(body.code).toBe('setting_rejected')
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('a rate above its maximum is refused, not clamped', async () => {
    const res = await POST(await bundle({ takeoverRateLimit: 501 }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/^'takeoverRateLimit' must be between 1 and 500\./)
    expect(h.createProject).not.toHaveBeenCalled()
  })
})

describe('numbers create_project accepts', () => {
  test('in-range values and a 0 that means unlimited are imported as written', async () => {
    const res = await POST(await bundle({ nucleiRateLimit: 5, graphqlRateLimit: 0, ffufRate: 0 }))
    expect(res.status).toBe(200)
    expect(created()).toMatchObject({ nucleiRateLimit: 5, graphqlRateLimit: 0, ffufRate: 0 })
    expect(filterReconSettings({ graphqlRateLimit: 0, ffufRate: 0 }, { mode: 'create' }).ok).toBe(true)
  })

  test('an optional number left empty imports', async () => {
    const res = await POST(await bundle({ agentLport: null }))
    expect(res.status).toBe(200)
    expect(created().agentLport).toBeNull()
  })
})
