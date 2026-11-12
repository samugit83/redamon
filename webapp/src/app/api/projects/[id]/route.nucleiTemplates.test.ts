/**
 * A project may use only its owner's Nuclei templates and the instance ones (HD-08).
 *
 * - PUT (the form's save and the single-field auto-save) refuses, with 400
 *   template_not_selectable and nothing written, an entry it adds that points nuclei at
 *   another member's file: a selected custom template, or a free-form `nucleiTemplates`
 *   / `nucleiCustomTemplates` path that resolves under the custom-templates mount.
 * - GET for a service caller (the scan reading its settings) drops such entries from
 *   all three fields and logs `[rbac] nuclei template dropped`, so a project written by
 *   import, a preset or an MCP tool, which never pass the PUT, still never scans
 *   another member's file. A browser reads the stored row unchanged.
 *
 * The route and lib/nucleiTemplateOwnership.ts are real; Prisma is mocked.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/projects/[id]/route.nucleiTemplates.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => {
  process.env.NUCLEI_TEMPLATES_PATH = '/nonexistent/rbac-nuclei-selection'
  return {
    stored: {} as Record<string, unknown>,
    templates: [] as { path: string; ownerUserId: string | null }[],
    internal: false,
    scanner: false,
  }
})

const mockUpdate = vi.fn()
const mockUpdateMany = vi.fn()
const mockTemplateFindMany = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async (args?: { select?: Record<string, unknown> }) => {
        if (!args?.select) return { ...h.stored, user: { id: 'owner', name: 'o', email: 'o@e2e.local' }, authProfile: null }
        return Object.fromEntries(Object.keys(args.select).filter(k => args.select![k]).map(k => [k, h.stored[k]]))
      },
      update: (...a: unknown[]) => mockUpdate(...a),
      updateMany: (...a: unknown[]) => mockUpdateMany(...a),
    },
    nucleiTemplate: { findMany: (...a: unknown[]) => mockTemplateFindMany(...a) },
    userLlmProvider: { findFirst: vi.fn() },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/userSkillAgentPayload', () => ({ userSkillsForAgent: async () => [] }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => h.internal, isScannerRequest: () => h.scanner }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner' }),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { GET, PUT } from './route'
import { mintJobCredential } from '@/lib/authz/machineCredential'

// Step 1.16: a scan reads its project with the scanner key AND its job credential.
function scanJob(projectId = 'proj-1', tenant = 'owner'): Record<string, string> {
  vi.stubEnv('INTERNAL_API_KEY', 'internal-key-for-tests-0000000000000')
  return { 'x-redamon-job': mintJobCredential({ tenant, projectId }) }
}

const params = { params: Promise.resolve({ id: 'proj-1' }) }

function put(body: Record<string, unknown>) {
  return PUT(new NextRequest('http://localhost/api/projects/proj-1', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), params)
}
const get = (headers: Record<string, string> = {}) =>
  GET(new NextRequest('http://localhost/api/projects/proj-1', { headers }), params)

beforeEach(() => {
  vi.clearAllMocks()
  h.internal = false
  h.scanner = false
  h.stored = {
    id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test', ipMode: false, domainBatchMode: false,
    nucleiSelectedCustomTemplates: [], nucleiTemplates: [], nucleiCustomTemplates: [],
    updatedAt: new Date('2026-11-01T10:00:00.000Z'),
  }
  h.templates = [
    { path: 'mine.yaml', ownerUserId: 'owner' },
    { path: 'theirs.yaml', ownerUserId: 'other-member' },
    { path: 'shipped.yaml', ownerUserId: null },
  ]
  mockTemplateFindMany.mockImplementation(async ({ where }: { where: { path: { in: string[] } } }) =>
    h.templates.filter(t => where.path.in.includes(t.path)))
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...h.stored, ...data }))
  mockUpdateMany.mockResolvedValue({ count: 1 })
})

describe('PUT', () => {
  test("selecting another member's template refused: 400, nothing written", async () => {
    const res = await put({ nucleiSelectedCustomTemplates: ['mine.yaml', 'theirs.yaml'] })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({
      code: 'template_not_selectable', field: 'nucleiSelectedCustomTemplates', entry: 'theirs.yaml',
    })
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockUpdateMany).not.toHaveBeenCalled()
  })

  test("a free-form nucleiTemplates path into another member's file refused", async () => {
    const res = await put({ nucleiTemplates: ['http/cves/', '../../custom-templates/theirs.yaml'] })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'template_not_selectable', field: 'nucleiTemplates' })
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a free-form nucleiCustomTemplates value that loads the whole mount refused', async () => {
    const res = await put({ nucleiCustomTemplates: ['/custom-templates/'] })
    expect(res.status).toBe(400)
    expect((await res.json()).field).toBe('nucleiCustomTemplates')
  })

  test('instance template selectable, with the owner\'s own and official paths', async () => {
    const res = await put({
      nucleiSelectedCustomTemplates: ['shipped.yaml', 'mine.yaml'],
      nucleiTemplates: ['http/cves/'],
      nucleiCustomTemplates: ['/custom-templates/mine.yaml'],
    })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).toMatchObject({ nucleiSelectedCustomTemplates: ['shipped.yaml', 'mine.yaml'] })
  })

  test('the single-field auto-save is judged the same way', async () => {
    expect((await put({ nucleiSelectedCustomTemplates: ['theirs.yaml'] })).status).toBe(400)
    expect((await put({ nucleiSelectedCustomTemplates: ['shipped.yaml'] })).status).toBe(200)
  })

  test('a whole-row save keeps a stored entry that is no longer selectable, and judges only what it adds', async () => {
    h.stored.nucleiSelectedCustomTemplates = ['theirs.yaml']
    const res = await put({ ...h.stored, updatedAt: (h.stored.updatedAt as Date).toISOString(), name: 'renamed' })
    expect(res.status).toBe(200)
    expect(mockTemplateFindMany).not.toHaveBeenCalled()
  })

  test('the check runs before the numeric bounds, so an allowed selection reaches them', async () => {
    const res = await put({ nucleiSelectedCustomTemplates: ['shipped.yaml'], nucleiRateLimit: 0 })
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('setting_rejected')
  })
})

describe('GET', () => {
  const STORED_SELECTION = {
    nucleiSelectedCustomTemplates: ['mine.yaml', 'theirs.yaml', 'shipped.yaml'],
    nucleiTemplates: ['http/cves/', '/custom-templates/theirs.yaml'],
    nucleiCustomTemplates: ['.', '/custom-templates/mine.yaml'],
  }

  test('service GET drops a non-selectable entry from each of the three fields, and logs it', async () => {
    Object.assign(h.stored, STORED_SELECTION)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const who of ['internal', 'scanner'] as const) {
      h.internal = who === 'internal'
      h.scanner = who === 'scanner'
      const res = await get(who === 'scanner' ? scanJob() : {})
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.nucleiSelectedCustomTemplates).toEqual(['mine.yaml', 'shipped.yaml'])
      expect(body.nucleiTemplates).toEqual(['http/cves/'])
      expect(body.nucleiCustomTemplates).toEqual(['/custom-templates/mine.yaml'])
    }
    const lines = warn.mock.calls.map(c => String(c[0]))
    expect(lines).toContain('[rbac] nuclei template dropped project=proj-1 field=nucleiSelectedCustomTemplates count=1')
    expect(lines).toContain('[rbac] nuclei template dropped project=proj-1 field=nucleiTemplates count=1')
    expect(lines).toContain('[rbac] nuclei template dropped project=proj-1 field=nucleiCustomTemplates count=1')
  })

  test('an existing selection of instance templates reaches the scan unchanged, without a log line', async () => {
    h.stored.nucleiSelectedCustomTemplates = ['shipped.yaml', 'host-added.yaml']
    h.internal = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const body = await (await get()).json()
    expect(body.nucleiSelectedCustomTemplates).toEqual(['shipped.yaml', 'host-added.yaml'])
    expect(warn.mock.calls.some(c => String(c[0]).includes('nuclei template dropped'))).toBe(false)
  })

  test('a browser reads the stored row as it is', async () => {
    Object.assign(h.stored, STORED_SELECTION)
    const body = await (await get()).json()
    expect(body.nucleiSelectedCustomTemplates).toEqual(STORED_SELECTION.nucleiSelectedCustomTemplates)
    expect(mockTemplateFindMany).not.toHaveBeenCalled()
  })

  test('the agent\'s settings read (includeSkillContent) gets the same filtered fields', async () => {
    Object.assign(h.stored, STORED_SELECTION)
    h.internal = true
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = await GET(new NextRequest('http://localhost/api/projects/proj-1?includeSkillContent=true'), params)
    expect(res.status).toBe(200)
    expect((await res.json()).nucleiSelectedCustomTemplates).toEqual(['mine.yaml', 'shipped.yaml'])
  })
})
