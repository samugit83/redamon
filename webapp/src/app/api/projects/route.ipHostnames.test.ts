/**
 * POST /api/projects and the hostname policy of an IP-mode project
 * ("Hostnames on target IPs", design §9).
 *
 * A new IP project reads ip_only (D-02: the Prisma default; POST sends nothing it
 * was not given). The create path runs the shared cross-field rules on the whole
 * new row (B-25), so the policy gets the same refusals as a save: scan_all needs
 * its confirmation and is refused on a third-party engagement (D-03),
 * record_filter needs an include entry, the lists parse with the Domain-batch
 * rules and hold at most 200 entries (D-05), the policy applies only in IP mode,
 * and the include entries get the hard guardrail.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()
const mockFetch = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: { create: (...a: unknown[]) => mockProjectCreate(...a), update: vi.fn() },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { POST } from './route'

const IP_BASE = {
  name: 'IP project', ipMode: true, targetIps: ['203.0.113.0/30'], targetGuardrailEnabled: false,
}

function post(body: Record<string, unknown>) {
  return POST(new Request('http://localhost/api/projects', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }) as never)
}

const created = () => mockProjectCreate.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  mockProjectCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
    id: 'generated-id', userId: 'user-1', ...data,
  }))
  vi.stubGlobal('fetch', mockFetch)
  mockFetch.mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) })
})

describe('a new IP project', () => {
  test('without a policy is created with none, so the column default ip_only applies', async () => {
    const res = await post(IP_BASE)
    expect(res.status).toBe(201)
    expect(created()).not.toHaveProperty('ipHostnameMode')
  })

  test('record_filter with include entries is stored with canonical tokens', async () => {
    const res = await post({ ...IP_BASE, ipHostnameMode: 'record_filter',
      ipHostnameInclude: ['*Example.com', 'APP.example.org.'], ipHostnameExclude: 'old.example.com' })
    expect(res.status).toBe(201)
    expect(created()).toMatchObject({
      ipHostnameMode: 'record_filter',
      ipHostnameInclude: ['*.example.com', 'app.example.org'],
      ipHostnameExclude: ['old.example.com'],
    })
  })

  test('scan_all with its confirmation is created', async () => {
    const res = await post({ ...IP_BASE, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true })
    expect(res.status).toBe(201)
    expect(created().ipHostnameScanAllConfirmed).toBe(true)
  })

  test('a confirmation without scan_all is dropped', async () => {
    await post({ ...IP_BASE, ipHostnameMode: 'record_only', ipHostnameScanAllConfirmed: true })
    expect(created().ipHostnameScanAllConfirmed).toBe(false)
  })
})

describe('refusals', () => {
  test.each([
    ['scan_all without its confirmation', { ipHostnameMode: 'scan_all' }, 'ipHostnameScanAllConfirmed'],
    ['scan_all on a third-party engagement', {
      ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true, engagementKind: 'third_party',
    }, 'third_party'],
    ['record_filter without an include entry', { ipHostnameMode: 'record_filter' }, 'ipHostnameInclude'],
    ['an unknown mode', { ipHostnameMode: 'scan_everything' }, 'ipHostnameMode must be one of'],
    ['an IP literal include entry', { ipHostnameMode: 'record_filter', ipHostnameInclude: ['203.0.113.5'] }, 'ipHostnameInclude'],
    ['a public-suffix include entry', { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.co.uk'] }, 'ipHostnameInclude'],
    ['more than 200 exclude entries', {
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'],
      ipHostnameExclude: Array.from({ length: 201 }, (_, i) => `h${i}.example.com`),
    }, 'more than 200'],
    ['a cap above its bound', { ipHostnameMaxScanned: 5000 }, 'ipHostnameMaxScanned'],
  ])('%s', async (_name, policy, needle) => {
    const res = await post({ ...IP_BASE, ...policy })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain(needle)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a hard-blocked include entry is refused by the hard guardrail', async () => {
    const res = await post({ ...IP_BASE, ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.agency.gov.uk'] })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('agency.gov.uk')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('the hard guardrail reads an include list sent as one string too', async () => {
    const res = await post({ ...IP_BASE, ipHostnameMode: 'record_filter', ipHostnameInclude: '*.example.com,*.agency.gov.uk' })
    expect(res.status).toBe(403)
  })

  test('a domain project carrying a hostname policy is refused', async () => {
    const res = await post({ name: 'd', targetDomain: 'example.com', targetGuardrailEnabled: false,
      ipHostnameMode: 'record_only' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('only to IP-mode projects')
  })

  test('a domain project sending the form defaults is created', async () => {
    const res = await post({ name: 'd', targetDomain: 'example.com', targetGuardrailEnabled: false,
      ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [],
      ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false,
      ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500 })
    expect(res.status).toBe(201)
  })
})

describe('B-25: the other cross-field rules now run at creation too', () => {
  test('a fireteam concurrency above its team size is refused', async () => {
    const res = await post({ ...IP_BASE, fireteamMaxConcurrent: 9, fireteamMaxMembers: 2 })
    expect(res.status).toBe(400)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})
