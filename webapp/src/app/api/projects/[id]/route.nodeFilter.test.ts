/**
 * Node filters on /api/projects/[id].
 *
 *  - PUT takes the WHOLE project row from the settings form and hands it to
 *    `prisma.project.update`. Prisma accepts nested relation writes, so a
 *    `nodeFilter` (or any other relation) in that body would bypass the
 *    node-filter routes' validation, revision check and audit (X8). Only scalar
 *    columns may pass.
 *  - GET hands the rules and the operator's exemptions to service callers only,
 *    because a scan's end-of-run sweep reads them from there.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProjectFindUnique = vi.fn()
const mockProjectUpdate = vi.fn()
const mockGetEffectiveUser = vi.fn()
const mockIsInternal = vi.fn()
const mockIsScanner = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockProjectFindUnique(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
  isScannerRequest: (...a: unknown[]) => mockIsScanner(...a),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { GET, PUT } from './route'
import { mintJobCredential } from '@/lib/authz/machineCredential'

// Step 1.16: a scan reads its project with the scanner key AND its job credential.
function scanJob(projectId = 'proj-1', tenant = 'owner'): Record<string, string> {
  vi.stubEnv('INTERNAL_API_KEY', 'internal-key-for-tests-0000000000000')
  return { 'x-redamon-job': mintJobCredential({ tenant, projectId }) }
}

const RULES = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [] } } }
const CONTRACT_RULES = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [
  { id: 'k3f9a2', name: 'Informational templates', enabled: true,
    all: [{ field: 'severity', op: 'in', value: ['info'] }] },
] } } }
const PROJECT_GET_CONTRACT = join(__dirname, '../../../../lib/nodeFilters/contracts/project_get.json')
const params = { params: Promise.resolve({ id: 'proj-1' }) }

function wireProject() {
  mockProjectFindUnique.mockImplementation((args: { select?: unknown }) =>
    args?.select
      ? Promise.resolve({ id: 'proj-1', userId: 'owner' })
      : Promise.resolve({
          id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.com',
          user: { id: 'owner' }, authProfile: null,
          nodeFilter: {
            projectId: 'proj-1', mode: 'denylist', applyToScans: true, rules: RULES,
            revision: 4, updatedBy: 'owner', updatedAt: new Date(),
          },
          nodeFilterExemptions: [{ label: 'Vulnerability', nodeKey: 'v1' }],
        }),
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockIsInternal.mockReturnValue(false)
  mockIsScanner.mockReturnValue(false)
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner' })
  wireProject()
})

describe('PUT keeps only scalar columns', () => {
  function put(body: unknown) {
    return PUT(new NextRequest('http://x/api/projects/proj-1', {
      method: 'PUT', body: JSON.stringify(body),
    }), params)
  }

  test('a nested nodeFilter write in the body has no effect', async () => {
    mockProjectUpdate.mockResolvedValue({ id: 'proj-1', userId: 'owner', ipMode: true, targetDomain: '' })
    const res = await put({
      name: 'renamed',
      nodeFilter: { upsert: { create: { mode: 'allowlist', rules: {} }, update: { applyToScans: true } } },
      nodeFilterRuns: { deleteMany: {} },
      nodeFilterExemptions: { deleteMany: {} },
    })
    expect(res.status).toBe(200)
    expect(mockProjectUpdate.mock.calls[0][0].data).toEqual({ name: 'renamed', updatedById: 'owner' })
  })

  test('any relation, and any key that is not a column, is dropped', async () => {
    mockProjectUpdate.mockResolvedValue({ id: 'proj-1', userId: 'owner', ipMode: true, targetDomain: '' })
    await put({
      name: 'x', nucleiSeverity: ['high'],
      scanJobs: { create: [{}] }, triageRuns: { deleteMany: {} }, notAColumn: 1,
    })
    expect(mockProjectUpdate.mock.calls[0][0].data).toEqual({ name: 'x', nucleiSeverity: ['high'], updatedById: 'owner' })
  })
})

describe('GET hands node filters to service callers only', () => {
  const get = (headers: Record<string, string> = {}) =>
    GET(new NextRequest('http://x/api/projects/proj-1', { headers }), params)

  test.each([
    ['internal', () => mockIsInternal.mockReturnValue(true), () => ({})],
    ['scanner', () => mockIsScanner.mockReturnValue(true), () => scanJob()],
  ])('%s caller gets the rules and the exemptions', async (_label, arrange, headers) => {
    arrange()
    const body = await (await get(headers())).json()
    expect(body.nodeFilter).toEqual({
      mode: 'denylist', applyToScans: true, rules: RULES, revision: 4,
      exemptions: [['Vulnerability', 'v1']],
    })
    expect(body.nodeFilterExemptions).toBeUndefined()
    const include = mockProjectFindUnique.mock.calls.find(([a]) => !a?.select)?.[0].include
    expect(include.nodeFilter).toBe(true)
    expect(include.nodeFilterExemptions).toEqual({ select: { label: true, nodeKey: true } })
  })

  test('a browser caller gets neither, and the query does not load them', async () => {
    const body = await (await get()).json()
    expect(body.nodeFilter).toBeUndefined()
    expect(body.nodeFilterExemptions).toBeUndefined()
    const include = mockProjectFindUnique.mock.calls.find(([a]) => !a?.select)?.[0].include
    expect(include.nodeFilter).toBeUndefined()
  })

  test('the service body is the contract the recon sweep parses', async () => {
    // recon/tests/test_node_filter_scan_sweep.py feeds this same file to
    // fetch_node_filters. A shape change here that recon does not follow reads
    // there as "not armed", and every scan silently stops filtering.
    // Regenerate with NODE_FILTER_CONTRACT_WRITE=1 after a deliberate change.
    mockIsScanner.mockReturnValue(true)
    mockProjectFindUnique.mockResolvedValue({
      id: 'proj-1', userId: 'owner', user: { id: 'owner' }, authProfile: null,
      nodeFilter: {
        projectId: 'proj-1', mode: 'denylist', applyToScans: true, rules: CONTRACT_RULES,
        revision: 4, updatedBy: 'owner', updatedAt: new Date(),
      },
      nodeFilterExemptions: [{ label: 'Vulnerability', nodeKey: 'v1' }, { label: 'Secret', nodeKey: 's9' }],
    })
    const body = await (await get(scanJob())).json()
    const wire = { nodeFilter: body.nodeFilter }
    if (process.env.NODE_FILTER_CONTRACT_WRITE === '1') {
      writeFileSync(PROJECT_GET_CONTRACT, JSON.stringify(wire, null, 2) + '\n')
    }
    expect(wire).toEqual(JSON.parse(readFileSync(PROJECT_GET_CONTRACT, 'utf8')))
  })

  test('a project with no filter row reads as null for a service caller', async () => {
    mockIsScanner.mockReturnValue(true)
    mockProjectFindUnique.mockResolvedValue({
      id: 'proj-1', userId: 'owner', user: { id: 'owner' }, authProfile: null,
      nodeFilter: null, nodeFilterExemptions: [],
    })
    expect((await (await get(scanJob())).json()).nodeFilter).toBeNull()
  })
})
