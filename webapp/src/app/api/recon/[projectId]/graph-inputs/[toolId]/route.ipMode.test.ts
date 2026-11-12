/** @vitest-environment node */
/**
 * The graph-inputs route on an IP-mode project, per Hostnames on target IPs
 * mode.
 *
 * The counts follow what the container keeps: a target's label and a target
 * address always, and a name only when the project's CURRENT policy admits it
 * among those a run scanned (a graph reason of 'scanned' alone is not trusted,
 * design §6.3). The org Domain of such a name is no stale root; the org Domain
 * of a name the policy no longer admits is.
 *
 * Documentation addresses (RFC 5737) and reserved names only.
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockGuard = vi.fn()
const mockFindUnique = vi.fn()
const mockRun = vi.fn()

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } } }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: vi.fn() }),
}))

import { GET } from './route'

function record(fields: Record<string, unknown>) {
  return { get: (k: string) => fields[k] }
}

const ROOT = 'ip-targets.p1'
const PROJECT = {
  userId: 'u1', targetDomain: '', ipMode: true, targetIps: ['203.0.113.0/30'],
  ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: [],
}
const SCANNED = [{ name: 'app.example.com', orgs: ['example.com'] }, { name: 'shop.example.net', orgs: ['example.net'] }]

function call(toolId: string) {
  return GET({} as never, { params: Promise.resolve({ projectId: 'p1', toolId }) })
}

/** The tool's own count query: the one that reads the IP-mode scope lists. */
function toolCall() {
  return mockRun.mock.calls.find(([cypher]) => /\$ip(Subs|Hosts)/.test(String(cypher))) as
    [string, Record<string, unknown>] | undefined
}

beforeEach(() => {
  vi.clearAllMocks()
  mockGuard.mockResolvedValue(null)
  mockFindUnique.mockResolvedValue(PROJECT)
  mockRun.mockImplementation(async (cypher: string) => {
    if (cypher.includes('AS hasData')) {
      return { records: [{ name: ROOT, hasData: true }, { name: 'example.com', hasData: true },
        { name: 'example.net', hasData: true }].map(record) }
    }
    if (cypher.includes("source: 'ip_hostname_selection'")) return { records: SCANNED.map(record) }
    if (cypher.includes('AS labels')) {
      return { records: [record({ labels: ['203-0-113-1', '203-0-113-9', 'host1.provider.example'] })] }
    }
    if (cypher.includes('AS endpointHosts')) {
      return { records: [record({ hosts: ['203.0.113.2', '198.51.100.7', 'app.example.com', 'shop.example.net'],
        endpointHosts: ['203.0.113.1'] })] }
    }
    return { records: [record({ subdomains: ['203-0-113-1', 'app.example.com'], subCount: 2, ipCount: 1,
      portCount: 3, baseurls: ['http://203.0.113.2/'], baseurlCount: 1, endpointCount: 4 })] }
  })
})

describe('the IP-mode scope of the counts', () => {
  test('Record + scan matching: labels, target addresses and the names the policy admits', async () => {
    const body = await (await call('Httpx')).json()
    expect(body.domains).toEqual([ROOT])
    const [cypher, params] = toolCall()!
    expect(params.ipSubs).toEqual(['203-0-113-1', 'app.example.com'])
    expect(params.ipHosts).toEqual(['203.0.113.2', '203.0.113.1', 'app.example.com'])
    expect(cypher).toContain('toLower(s.name) IN $ipSubs')
    expect(cypher).not.toContain('HAS_SUBDOMAIN')
    expect(body.existing_subdomains_count).toBe(2)
  })

  test("the org Domain of a scanned name the policy still admits is not stale; the other is", async () => {
    const body = await (await call('Httpx')).json()
    expect(body.stale_domains).toEqual(['example.net'])
  })

  test('IP only: no name counts, and every org Domain is stale', async () => {
    mockFindUnique.mockResolvedValue({ ...PROJECT, ipHostnameMode: 'ip_only' })
    const body = await (await call('Naabu')).json()
    const [, params] = toolCall()!
    expect(params.ipSubs).toEqual(['203-0-113-1'])
    expect(params.ipHosts).toEqual(['203.0.113.2', '203.0.113.1'])
    expect(body.stale_domains).toEqual(['example.com', 'example.net'])
  })

  test('Record hostnames: the same as IP only', async () => {
    mockFindUnique.mockResolvedValue({ ...PROJECT, ipHostnameMode: 'record_only' })
    await call('Naabu')
    expect(toolCall()![1].ipSubs).toEqual(['203-0-113-1'])
  })

  test('Record + scan all: every scanned name', async () => {
    mockFindUnique.mockResolvedValue({ ...PROJECT, ipHostnameMode: 'scan_all' })
    const body = await (await call('Katana')).json()
    const [cypher, params] = toolCall()!
    expect(params.ipSubs).toEqual(['203-0-113-1', 'app.example.com', 'shop.example.net'])
    expect(params.ipHosts).toEqual(['203.0.113.2', '203.0.113.1', 'app.example.com', 'shop.example.net'])
    expect(cypher).toContain('IN $ipHosts')
    expect(body.stale_domains).toEqual([])
  })

  test('a filter the policy cannot read admits no name', async () => {
    mockFindUnique.mockResolvedValue({ ...PROJECT, ipHostnameInclude: ['*.*'] })
    await call('Httpx')
    expect(toolCall()![1].ipSubs).toEqual(['203-0-113-1'])
  })

  test('every IP-mode read is tenant-scoped', async () => {
    await call('Httpx')
    for (const [cypher, params] of mockRun.mock.calls as [string, Record<string, unknown>][]) {
      expect(cypher).toContain('user_id: $uid, project_id: $pid')
      expect(params).toMatchObject({ uid: 'u1', pid: 'p1' })
    }
  })

  test('a domain project reads none of the IP-mode lists', async () => {
    mockFindUnique.mockResolvedValue({ userId: 'u1', targetDomain: 'example.com', ipMode: false, subdomainList: [] })
    await call('Httpx')
    expect(toolCall()).toBeUndefined()
    expect(mockRun.mock.calls.some(([c]) => String(c).includes("source: 'ip_hostname_selection'"))).toBe(false)
  })
})
