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
import { Prisma } from '@prisma/client'

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
const mockGraphSession = vi.fn(() => ({ run: vi.fn(), close: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => mockGraphSession() }))
// Scope edits are refused while a scan writes the graph; default is idle.
const mockScanWriters = vi.fn()
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: () => mockScanWriters() }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }) }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
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
  mockScanWriters.mockResolvedValue(null)
  mockGraphSession.mockReturnValue({ run: vi.fn(), close: vi.fn() })
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
    // Cleared, never stored: recon and replay read the column whatever the mode.
    expect(mockUpdate.mock.calls[0][0].data.domainBatchGroups).toBe(Prisma.DbNull)
    expect(mockUpdate.mock.calls[0][0].data.domainBatchHosts).toEqual([])
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

/**
 * Batch scope became editable after creation, so this route is now the only path
 * that can add a domain to a live engagement. POST guardrails what it creates;
 * until these tests, PUT guardrailed nothing.
 */
describe('editing batch scope is guarded', () => {
  const BATCH_ROW = {
    id: PROJECT_ID, userId: 'u1', domainBatchMode: true,
    targetGuardrailEnabled: false,
    domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['api.'] }],
  }

  beforeEach(() => {
    mockFindUnique.mockResolvedValue(BATCH_ROW)
  })

  test('a hard-blocked root added on edit is refused, and nothing is written', async () => {
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['api.example.com', 'www.senate.gov'] })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('senate.gov')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('an unchanged host list is not treated as a scope change', async () => {
    // A partial save (one module toggle) must not pay for a guardrail round trip
    // or be blocked by an unrelated running scan.
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['api.example.com'] })
    expect(res.status).toBe(200)
  })

  test('turning a literal group into a wildcard counts as a scope change', async () => {
    // Same root, same group count - so a roots-only comparison sees no change,
    // while the group went from one host to every host under the domain.
    mockScanWriters.mockResolvedValue('a recon scan is running')
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['*.example.com'] })
    expect(res.status).toBe(409)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a scope edit during a running scan is refused', async () => {
    mockScanWriters.mockResolvedValue('a recon scan is running')
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['api.example.com', 'new.other.com'] })
    expect(res.status).toBe(409)
    expect((await res.json()).error).toContain('a recon scan is running')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('it fails closed when scan status cannot be determined', async () => {
    mockScanWriters.mockResolvedValue('the scan status could not be verified')
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['new.other.com'] })
    expect(res.status).toBe(409)
  })

  test('a Domain node is seeded for every batch root, not just targetDomain', async () => {
    // targetDomain is '' for a batch, so the single-domain seed condition skipped
    // it entirely and a root added on edit had no node for partial recon to offer.
    const runs: string[] = []
    mockGraphSession.mockReturnValue({
      run: async (_q: string, p: { name: string }) => { runs.push(p.name); return [] },
      close: async () => {},
    } as never)
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['*.example.com', 'api.other.com'] })
    expect(res.status).toBe(200)
    expect(runs).toEqual(['example.com', 'other.com'])
  })
})

/**
 * The scope gates (busy 409, hard and soft guardrail) used to run only for a
 * batch host-list edit. A single-domain target change, a batch -> single flip
 * and entering IP mode re-point the engagement just as much, and got neither.
 */
describe('every mode is guarded on update, not only a batch host list', () => {
  const SINGLE_ROW = {
    id: PROJECT_ID, userId: 'u1', domainBatchMode: false, ipMode: false,
    targetDomain: 'example.com', subdomainList: ['www.'], targetIps: [],
    domainBatchHosts: [], domainBatchGroups: null,
  }

  test('a single-domain target change to a government domain is refused, naming it', async () => {
    mockFindUnique.mockResolvedValue(SINGLE_ROW)
    const res = await put(fullFormBody({ targetDomain: 'agency.gov.uk' }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('agency.gov.uk')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a prefix that makes a blocked host is refused too', async () => {
    // org.jm is a public suffix, so the target itself is refused (400) before the
    // guardrail (403) would name isa.org.jm; either way nothing is written.
    mockFindUnique.mockResolvedValue(SINGLE_ROW)
    const res = await put(fullFormBody({ targetDomain: 'org.jm', subdomainList: ['isa.'] }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('public suffix')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('an unchanged single-domain save passes while a scan runs', async () => {
    mockFindUnique.mockResolvedValue(SINGLE_ROW)
    mockScanWriters.mockResolvedValue('a full recon is running')
    expect((await put(fullFormBody())).status).toBe(200)
  })

  test('a single-domain target change while a scan runs is a 409', async () => {
    mockFindUnique.mockResolvedValue(SINGLE_ROW)
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put(fullFormBody({ targetDomain: 'other.example.com' }))
    expect(res.status).toBe(409)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a batch -> single flip while a scan runs is a 409', async () => {
    mockFindUnique.mockResolvedValue({
      ...SINGLE_ROW, domainBatchMode: true, targetDomain: '',
      domainBatchHosts: ['www.example.com'],
      domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['www.'], hosts: ['www.example.com'], wildcard: false }],
    })
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put(fullFormBody({ domainBatchMode: false, targetDomain: 'example.com' }))
    expect(res.status).toBe(409)
  })

  test('entering IP mode while a scan runs is a 409', async () => {
    mockFindUnique.mockResolvedValue(SINGLE_ROW)
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put(fullFormBody({ ipMode: true, targetDomain: '', targetIps: ['192.0.2.10'] }))
    expect(res.status).toBe(409)
  })

  test('a batch -> single flip clears the stored batch scope', async () => {
    mockFindUnique.mockResolvedValue({
      ...SINGLE_ROW, domainBatchMode: true, targetDomain: '',
      domainBatchHosts: ['www.example.com'],
      domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['www.'], hosts: ['www.example.com'], wildcard: false }],
    })
    const res = await put(fullFormBody({ domainBatchMode: false, targetDomain: 'example.com' }))
    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.domainBatchGroups).toBe(Prisma.DbNull)
    expect(data.domainBatchHosts).toEqual([])
  })

  test('a partial save of a single-domain row with a stale batch scope clears it', async () => {
    mockFindUnique.mockResolvedValue({
      ...SINGLE_ROW, domainBatchHosts: ['www.example.com'],
      domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['www.'], hosts: ['www.example.com'], wildcard: false }],
    })
    expect((await put({ katanaEnabled: false })).status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.domainBatchGroups).toBe(Prisma.DbNull)
  })

  test('a batch host listed under a multi-label government name is refused, naming the host', async () => {
    mockFindUnique.mockResolvedValue({ ...SINGLE_ROW, domainBatchMode: true, targetDomain: '' })
    const res = await put(fullFormBody({
      domainBatchMode: true, targetDomain: '', domainBatchHosts: ['ok.example.com', 'www.isa.org.jm'],
    }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('www.isa.org.jm')
  })
})

describe('an unchanged save is not a scope change, whatever the mode', () => {
  test('an IP-mode row saved with the same address list passes while a scan runs', async () => {
    mockFindUnique.mockResolvedValue({
      id: PROJECT_ID, userId: 'u1', ipMode: true, domainBatchMode: false, targetDomain: '',
      subdomainList: [], targetIps: ['192.0.2.10', '192.0.2.11'], domainBatchHosts: [], domainBatchGroups: null,
    })
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put(fullFormBody({ ipMode: true, targetDomain: '', subdomainList: [], targetIps: ['192.0.2.10', '192.0.2.11'] }))
    expect(res.status).toBe(200)
  })

  test('the same prefixes in another order pass while a scan runs', async () => {
    mockFindUnique.mockResolvedValue({
      id: PROJECT_ID, userId: 'u1', ipMode: false, domainBatchMode: false, targetDomain: 'example.com',
      subdomainList: ['www.', 'api.', '.'], targetIps: [], domainBatchHosts: [], domainBatchGroups: null,
    })
    mockScanWriters.mockResolvedValue('a full recon is running')
    const res = await put(fullFormBody({ subdomainList: ['.', 'api.', 'www.'] }))
    expect(res.status).toBe(200)
  })
})

/**
 * The exclusivity check read only the body, so a request carrying one mode flag
 * let the other stand from the stored row: an IP-mode project could be saved as
 * a batch too. Its hosts were never guardrailed (IP mode has no names), and
 * recon's auth scope and the replay read the stored groups whatever the mode.
 */
describe('mode exclusivity holds against the stored row, not only the body', () => {
  test('a batch flip sent to an IP-mode row without ipMode:false is refused', async () => {
    mockFindUnique.mockResolvedValue({
      id: PROJECT_ID, userId: 'u1', ipMode: true, domainBatchMode: false, targetDomain: '',
      subdomainList: [], targetIps: ['192.0.2.10'], domainBatchHosts: [], domainBatchGroups: null,
      targetGuardrailEnabled: false,
    })
    const res = await put({ domainBatchMode: true, domainBatchHosts: ['www.agency.gov.uk'] })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('both IP mode and Domain batch')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('an IP flip sent to a batch row without domainBatchMode:false is refused', async () => {
    mockFindUnique.mockResolvedValue({
      id: PROJECT_ID, userId: 'u1', ipMode: false, domainBatchMode: true, targetDomain: '',
      subdomainList: [], targetIps: [], domainBatchHosts: ['www.example.com'],
      domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['www.'], hosts: ['www.example.com'], wildcard: false }],
    })
    const res = await put({ ipMode: true, targetIps: ['192.0.2.10'] })
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('a row already in both modes can still take an unrelated partial save', () => {
  test('a module toggle on such a row is not refused', async () => {
    mockFindUnique.mockResolvedValue({
      id: PROJECT_ID, userId: 'u1', ipMode: true, domainBatchMode: true, targetDomain: '',
      subdomainList: [], targetIps: ['192.0.2.10'], domainBatchHosts: ['www.example.com'],
      domainBatchGroups: [{ rootDomain: 'example.com', prefixes: ['www.'], hosts: ['www.example.com'], wildcard: false }],
    })
    expect((await put({ katanaEnabled: false })).status).toBe(200)
  })
})

describe('WEB-12: a save seeds the org Domain', () => {
  test('a deep single-domain target seeds its registrable domain, not the scan root', async () => {
    const run = vi.fn()
    mockGraphSession.mockReturnValue({ run, close: vi.fn() })
    const res = await put(fullFormBody({ targetDomain: 'api.example.com', subdomainList: [] }))
    expect(res.status).toBe(200)
    const names = run.mock.calls
      .filter(([q]) => String(q).includes('MERGE (d:Domain'))
      .map(([, p]) => (p as { name: string }).name)
    expect(names).toEqual(['example.com'])
  })
})
