/**
 * Import refuses a scope the create routes refuse, BEFORE anything is written.
 *
 * normalizeImportedScope() is unit-tested on its own; this pins that the route
 * acts on its refusal: a bundle targeting a government domain creates no project.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const mockProjectCreate = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: 'new-owner' }) }))
vi.mock('@/lib/prisma', () => ({
  default: { project: { create: (...a: unknown[]) => mockProjectCreate(...a) } },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

async function bundle(project: Record<string, unknown>) {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'Imported' }))
  zip.file('project.json', JSON.stringify({ id: 'old-project', userId: 'old-owner', name: 'Imported', ...project }))
  const buf = await zip.generateAsync({ type: 'uint8array' })
  const fd = new FormData()
  fd.set('file', new File([buf as BlobPart], 'export.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectCreate.mockResolvedValue({ id: 'new-project', name: 'Imported' })
})

describe('import scope refusal', () => {
  test('a bundle targeting a government domain is refused and creates no project', async () => {
    const res = await POST(await bundle({ targetDomain: 'agency.gov.uk', subdomainList: [] }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('agency.gov.uk')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})

describe('import and the hostname policy (cross-field rules, B-25)', () => {
  const IP = { ipMode: true, targetIps: ['203.0.113.10'], targetDomain: '' }

  test.each([
    ['scan_all without its confirmation', { ipHostnameMode: 'scan_all' }, 'ipHostnameScanAllConfirmed'],
    ['record_filter without an include entry', { ipHostnameMode: 'record_filter' }, 'ipHostnameInclude'],
    ['an include entry that does not parse', {
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['203.0.113.9'],
    }, 'ipHostnameInclude'],
  ])('%s refuses the bundle', async (_name, policy, needle) => {
    const res = await POST(await bundle({ ...IP, ...policy }))
    expect(res.status).toBe(400)
    const { error } = await res.json()
    expect(error).toContain(needle)
    expect(error).toContain('The bundle was not imported.')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a hard-blocked include entry refuses the bundle', async () => {
    const res = await POST(await bundle({ ...IP, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.agency.gov.uk'] }))
    expect(res.status).toBe(403)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a valid policy is created, stored with canonical entries and no stray confirmation', async () => {
    const res = await POST(await bundle({
      ...IP, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*Example.com'], ipHostnameScanAllConfirmed: true,
    }))
    expect(res.status).toBeLessThan(300)
    const data = mockProjectCreate.mock.calls[0][0].data
    expect(data.ipHostnameInclude).toEqual(['*.example.com'])
    expect(data.ipHostnameScanAllConfirmed).toBe(false)
  })
})
