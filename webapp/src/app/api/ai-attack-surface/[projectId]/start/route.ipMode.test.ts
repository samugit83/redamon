/**
 * AI Gauntlet start: the run config carries the project's IP-mode scope
 * (design §11, P4).
 *
 * The scanner attacks graph Endpoints by URL and never reads the project row,
 * so the start route hands it what it needs to admit a target: whether the
 * project is in IP mode, its target IPs, its RoE exclusions and the hostname
 * policy as saved now. The scanner refuses an IP-mode project whose config does
 * not say (scanners/ai_attack_surface_scan/target_loader.ip_mode_scope), so a
 * domain project states ip_mode false too.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ findProject: vi.fn(), orchestratorFetch: vi.fn() }))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'u1' }) }))
vi.mock('@/lib/scanTimeline', () => ({ recordScanStart: async () => null }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    engagementAuthorization: { count: async () => 1, findFirst: async () => null },
  },
}))

import { POST } from './route'

const call = () => POST(
  new NextRequest('http://localhost/api/ai-attack-surface/p1/start', {
    method: 'POST',
    body: JSON.stringify({ tool: 'garak', targets: [{ baseurl: 'https://app.example.com', path: '/v1/chat' }] }),
  }),
  { params: Promise.resolve({ projectId: 'p1' }) },
)

const IP_PROJECT = {
  id: 'p1', userId: 'u1', targetDomain: '', subdomainList: [], domainBatchMode: false, domainBatchHosts: [],
  engagementKind: 'internal', roeGlobalMaxRps: 0,
  ipMode: true, targetIps: ['203.0.113.0/24', '10.0.0.5'], roeExcludedHosts: ['203.0.113.11'],
  ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'],
  ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100,
  ipHostnamePassiveMaxNames: 500,
}

const sent = () => JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)

beforeEach(() => {
  vi.clearAllMocks()
  h.findProject.mockResolvedValue(IP_PROJECT)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1', status: 'running' }) })
})

describe('the run config carries the IP-mode scope', () => {
  test('an IP-mode project sends its targets, RoE and current policy', async () => {
    expect((await call()).status).toBe(200)
    const body = sent()
    expect(body.ip_mode).toBe(true)
    expect(body.target_ips).toEqual(['203.0.113.0/24', '10.0.0.5'])
    expect(body.roe_excluded_hosts).toEqual(['203.0.113.11'])
    expect(body.ip_hostname_policy).toEqual({
      mode: 'record_filter', include: ['*.example.com'], exclude: ['old.example.com'],
    })
  })

  test('the row is read with every column the scope needs', async () => {
    await call()
    const select = h.findProject.mock.calls.map(c => c[0]?.select).find(s => s && 'ipMode' in s)
    expect(select).toMatchObject({ ipMode: true, targetIps: true, roeExcludedHosts: true,
      ipHostnameMode: true, ipHostnameInclude: true, ipHostnameExclude: true })
  })

  test('a domain project states it is not in IP mode and sends no targets', async () => {
    h.findProject.mockResolvedValue({ ...IP_PROJECT, ipMode: false, targetDomain: 'example.com', roeExcludedHosts: [] })
    await call()
    const body = sent()
    expect(body.ip_mode).toBe(false)
    expect(body.target_ips).toEqual([])
    expect(body.roe_excluded_hosts).toEqual([])
  })

  test('null columns travel as empty lists, a missing mode as ip_only', async () => {
    h.findProject.mockResolvedValue({ ...IP_PROJECT, targetIps: null, roeExcludedHosts: null,
      ipHostnameMode: null, ipHostnameInclude: null, ipHostnameExclude: null })
    await call()
    const body = sent()
    expect(body.target_ips).toEqual([])
    expect(body.roe_excluded_hosts).toEqual([])
    expect(body.ip_hostname_policy).toEqual({ mode: 'ip_only', include: [], exclude: [] })
  })
})
