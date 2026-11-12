/**
 * Import is a creation path, so a bundle without a real ownership token gets a
 * fresh one (L-16). A bundle exported before the fix carries the shared
 * placeholder every install shipped, and a TXT record published with it would
 * verify the imported project too. A token the exporting side chose is kept.
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

const LEGACY = 'your-secret-token-here'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

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

const tokenOf = (call: number) =>
  (h.createProject.mock.calls[call][0].data as Record<string, unknown>).ownershipToken

describe('import: the ownership token', () => {
  test.each([
    ['the old shared default', { ownershipToken: LEGACY }],
    ['an empty token', { ownershipToken: '' }],
    ['no token at all', {}],
  ])('a bundle with %s gets a fresh token', async (_label, fields) => {
    const res = await POST(await bundle({ verifyDomainOwnership: true, ...fields }))
    expect(res.status).toBe(200)
    expect(tokenOf(0)).toMatch(UUID)
  })

  test('two imports of the same legacy bundle get different tokens', async () => {
    await POST(await bundle({ ownershipToken: LEGACY }))
    await POST(await bundle({ ownershipToken: LEGACY }))
    expect(tokenOf(0)).not.toBe(tokenOf(1))
  })

  test('a token the exporting side chose is kept', async () => {
    await POST(await bundle({ verifyDomainOwnership: true, ownershipToken: 'k7-exported-token' }))
    expect(tokenOf(0)).toBe('k7-exported-token')
  })
})
