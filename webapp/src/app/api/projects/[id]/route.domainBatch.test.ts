/**
 * Domain batch F2 + F8: PUT /api/projects/[id].
 *
 * F2, the regression this file exists for: the batch recompute was gated on the
 * KEY being present in the body. The project form PUTs the whole row and
 * MINIMAL_DEFAULTS carries `domainBatchHosts: []`, so the key is present on every
 * single-domain and IP project too. validateDomainBatch([]) fails, so EVERY edit
 * of EVERY non-batch project returned 400 "Domain batch mode needs at least one
 * hostname". The gate is now the project actually being a batch.
 *
 * F8: the modes are mutually exclusive on update, not only on create.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockEffectiveUser = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }) }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: () => mockEffectiveUser(),
    requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'u1' } }),
  }
})

import { PUT } from './route'

const PROJECT_ID = 'cmnbt9q1c0001nq01nv1wp1si'

/** What the settings form actually sends: the entire project row. */
function fullFormBody(overrides: Record<string, unknown> = {}) {
  return {
    name: 'My Project',
    description: '',
    targetDomain: 'example.com',
    subdomainList: ['www.'],
    ipMode: false,
    targetIps: [],
    // Present on EVERY project because MINIMAL_DEFAULTS seeds it. This is the
    // field that used to poison the whole request.
    domainBatchMode: false,
    domainBatchHosts: [],
    scanModules: ['domain_discovery'],
    ...overrides,
  }
}

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest(`http://localhost/api/projects/${PROJECT_ID}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: PROJECT_ID }) },
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockEffectiveUser.mockResolvedValue({ userId: 'u1', isAdmin: false })
  mockFindUnique.mockResolvedValue({ id: PROJECT_ID, userId: 'u1', domainBatchMode: false })
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({
    id: PROJECT_ID, userId: 'u1', ...data,
  }))
})

describe('F2: a non-batch project can still be edited', () => {
  test('a full form PUT carrying an empty domainBatchHosts succeeds', async () => {
    const res = await put(fullFormBody())
    expect(res.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalled()
  })

  test('it does NOT return the domain-batch validation error', async () => {
    const res = await put(fullFormBody())
    const body = await res.json()
    expect(JSON.stringify(body)).not.toContain('at least one hostname')
  })

  test('an IP-mode project with an empty host list is editable too', async () => {
    const res = await put(fullFormBody({ ipMode: true, targetDomain: '', targetIps: ['10.0.0.1'] }))
    expect(res.status).toBe(200)
  })

  test('a project whose row is batch but whose body omits the mode is still validated', async () => {
    // The gate falls back to the stored value, so an omitted flag cannot be used
    // to smuggle an empty scope past the check.
    mockFindUnique.mockResolvedValue({ id: PROJECT_ID, userId: 'u1', domainBatchMode: true })
    const res = await put({ name: 'x', domainBatchHosts: [] })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('at least one hostname')
  })
})

describe('a partial save on a batch project does not touch the scope', () => {
  // The reported bug: toggling a module in the workflow view auto-saves ONE
  // field, e.g. { katanaEnabled: false }. That body has no domainBatchHosts, and
  // the recompute treated the absent list as empty, so every toggle 400'd with
  // "needs at least one hostname".
  test('a single-field toggle succeeds and never re-derives the groups', async () => {
    mockFindUnique.mockResolvedValue({ id: PROJECT_ID, userId: 'u1', domainBatchMode: true })
    const res = await put({ katanaEnabled: false })

    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(data).not.toHaveProperty('domainBatchHosts')
    expect(data).not.toHaveProperty('domainBatchGroups')
    expect(data.katanaEnabled).toBe(false)
  })

  test('a partial save cannot smuggle a scope in via domainBatchGroups', async () => {
    mockFindUnique.mockResolvedValue({ id: PROJECT_ID, userId: 'u1', domainBatchMode: true })
    const res = await put({
      katanaEnabled: false,
      domainBatchGroups: [{ rootDomain: 'attacker.com', prefixes: ['.'], hosts: ['attacker.com'] }],
    })

    expect(res.status).toBe(200)
    // The untrusted grouping is stripped, and nothing is re-derived from an empty
    // host list, so the stored scope is left exactly as it was.
    expect(mockUpdate.mock.calls[0][0].data).not.toHaveProperty('domainBatchGroups')
  })

  test('a save that DOES change the host list still validates', async () => {
    mockFindUnique.mockResolvedValue({ id: PROJECT_ID, userId: 'u1', domainBatchMode: true })
    const res = await put({ domainBatchHosts: [] })
    expect(res.status).toBe(400)
  })
})

describe('F2: a batch project is still validated and normalized', () => {
  test('a valid host list is grouped and persisted', async () => {
    const res = await put(fullFormBody({
      domainBatchMode: true,
      targetDomain: '',
      domainBatchHosts: ['SUB1.Domain1.com', 'https://sub2.domain2.it/x', 'sub1.domain1.com'],
    }))
    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.domainBatchHosts).toEqual(['sub1.domain1.com', 'sub2.domain2.it'])
    expect(data.domainBatchGroups.map((g: { rootDomain: string }) => g.rootDomain))
      .toEqual(['domain1.com', 'domain2.it'])
  })

  test('an empty host list on a batch project is refused', async () => {
    const res = await put(fullFormBody({ domainBatchMode: true, domainBatchHosts: [] }))
    expect(res.status).toBe(400)
  })

  test('an invalid hostname is refused rather than dropped', async () => {
    const res = await put(fullFormBody({
      domainBatchMode: true, domainBatchHosts: ['good.example.com', 'localhost'],
    }))
    expect(res.status).toBe(400)
  })
})

describe('F2: a client-supplied scope is never trusted', () => {
  test('domainBatchGroups is recomputed from the hosts, not taken from the body', async () => {
    const res = await put(fullFormBody({
      domainBatchMode: true,
      targetDomain: '',
      domainBatchHosts: ['real.example.com'],
      domainBatchGroups: [{ rootDomain: 'attacker-chosen.com', prefixes: ['.'], hosts: ['attacker-chosen.com'] }],
    }))
    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(JSON.stringify(data.domainBatchGroups)).not.toContain('attacker-chosen.com')
    expect(data.domainBatchGroups[0].rootDomain).toBe('example.com')
  })

  test('a non-batch project cannot have a scope injected at all', async () => {
    const res = await put(fullFormBody({
      domainBatchGroups: [{ rootDomain: 'attacker-chosen.com', prefixes: ['.'] }],
    }))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).not.toHaveProperty('domainBatchGroups')
  })
})

describe('F8: the target modes stay mutually exclusive on update', () => {
  test('setting both ipMode and domainBatchMode is refused', async () => {
    const res = await put(fullFormBody({
      ipMode: true, domainBatchMode: true, domainBatchHosts: ['a.example.com'],
    }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('both IP mode and Domain batch')
  })

  test('either mode alone is accepted', async () => {
    expect((await put(fullFormBody({ ipMode: true, targetIps: ['10.0.0.1'] }))).status).toBe(200)
    expect((await put(fullFormBody({
      domainBatchMode: true, targetDomain: '', domainBatchHosts: ['a.example.com'],
    }))).status).toBe(200)
  })
})
