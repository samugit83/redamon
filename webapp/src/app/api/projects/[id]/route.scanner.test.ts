/**
 * HD-20 (step 1.16): the scanner key reads a project only beside the job credential of
 * a scan of that project. It sits in every target-facing scan container, so on its own
 * it used to read any project in full (auth profile, node filters, RoE). The master
 * key is unchanged.
 *
 * The real session and credential helpers run; Prisma is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const MASTER = 'internal-key-for-tests-0000000000000'
const SCANNER = 'scanner-key-for-tests-00000000000000'
vi.stubEnv('INTERNAL_API_KEY', MASTER)
vi.stubEnv('SCANNER_API_KEY', SCANNER)

const h = vi.hoisted(() => ({ reads: [] as string[] }))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async ({ where }: { where: { id: string } }) => {
        h.reads.push(where.id)
        return {
          id: where.id, userId: 'owner-1', name: where.id, targetDomain: 'example.test', ipMode: false,
          domainBatchMode: false, nucleiSelectedCustomTemplates: [], nucleiTemplates: [], nucleiCustomTemplates: [],
          user: { id: 'owner-1', name: 'o', email: 'o@e2e.local' },
          authProfile: { kind: 'header', authValue: 'Bearer SESSION-SECRET-0001' },
          nodeFilter: null, nodeFilterExemptions: [],
        }
      },
    },
    nucleiTemplate: { findMany: async () => [] },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/userSkillAgentPayload', () => ({ userSkillsForAgent: async () => [] }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => NextResponse.json({ error: 'Unauthorized' }, { status: 401 }),
  }
})

import { mintJobCredential } from '@/lib/authz/machineCredential'
import { GET } from './route'

function get(id: string, headers: Record<string, string>) {
  return GET(new NextRequest(`http://localhost/api/projects/${id}`, { headers }), { params: Promise.resolve({ id }) })
}

beforeEach(() => {
  h.reads = []
  vi.restoreAllMocks()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe("scanner key reads only the credential's project", () => {
  test('with a credential for this project it reads the full service view', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await get('proj-1', { 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.id).toBe('proj-1')
    expect(body.authProfile.authValue).toBe('Bearer SESSION-SECRET-0001')
  })

  test("a credential for another project reads nothing of this one", async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await get('proj-2', { 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'job_credential_required', reason: 'project_mismatch' })
    expect(h.reads).toEqual([])
    expect(console.warn).toHaveBeenCalledWith(
      '[rbac] job credential refused reason=project_mismatch route=/api/projects/proj-2')
  })

  test('the bare scanner key reads nothing', async () => {
    const res = await get('proj-1', { 'x-internal-key': SCANNER })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'job_credential_required', reason: 'missing' })
    expect(h.reads).toEqual([])
  })

  test('an expired credential reads nothing', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1', ttlSeconds: -1 })
    const res = await get('proj-1', { 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(403)
    expect((await res.json()).reason).toBe('expired')
  })

  test('a job credential without the scanner key is a browser request, refused', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await get('proj-1', { 'x-redamon-job': token })
    expect(res.status).toBe(401)
    expect(h.reads).toEqual([])
  })

  test('the master key reads any project without a credential, as before', async () => {
    const res = await get('proj-2', { 'x-internal-key': MASTER })
    expect(res.status).toBe(200)
    expect((await res.json()).authProfile.authValue).toBe('Bearer SESSION-SECRET-0001')
  })
})
