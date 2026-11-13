/**
 * update_project_scope: the one tool that changes an existing project's
 * targets.
 *
 * Every test here is a way the platform could be re-pointed without the
 * controls that make re-pointing acceptable: a field outside the rescopable
 * target lists, a root on the permanent blocklist, a third-party widening with no
 * record of who authorized it, a grouping the caller supplied instead of the one
 * derived from the host list, or an IP project's hostname policy widened while
 * its schedules keep running.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  projectFind: vi.fn(),
  projectUpdateMany: vi.fn(),
  authCreate: vi.fn(),
  jobs: vi.fn(),
  schedules: vi.fn(),
  schedulesUpdate: vi.fn(),
  userSettings: vi.fn(),
  live: vi.fn(),
  seed: vi.fn(),
  legacy: vi.fn(),
  audit: vi.fn(),
  fetch: vi.fn(),
  recordingFind: vi.fn(),
  recordingUpdate: vi.fn(),
  mark: vi.fn(),
  activating: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      findUnique: (...a: unknown[]) => h.projectFind(...a),
      updateMany: (...a: unknown[]) => h.projectUpdateMany(...a),
    },
    engagementAuthorization: { create: (...a: unknown[]) => h.authCreate(...a) },
    jobQueue: { findMany: (...a: unknown[]) => h.jobs(...a) },
    scanSchedule: {
      findMany: (...a: unknown[]) => h.schedules(...a),
      updateMany: (...a: unknown[]) => h.schedulesUpdate(...a),
    },
    userSettings: { findUnique: (...a: unknown[]) => h.userSettings(...a) },
    recordingSession: {
      findFirst: (...a: unknown[]) => h.recordingFind(...a),
      update: (...a: unknown[]) => h.recordingUpdate(...a),
    },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: (...a: unknown[]) => h.live(...a) }))
vi.mock('@/lib/graphSeedDomains', async orig => ({
  ...(await orig<typeof import('@/lib/graphSeedDomains')>()),
  seedProjectDomains: (...a: unknown[]) => h.seed(...a),
}))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/ipHostnamePolicy', () => ({ markOutOfPolicy: (...a: unknown[]) => h.mark(...a) }))
vi.mock('@/lib/activationLock', async orig => ({
  ...(await orig<typeof import('@/lib/activationLock')>()),
  activationBusy: (...a: unknown[]) => h.activating(...a),
}))

import { McpScopeError, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { validateDomainBatch } from '@/lib/domainBatch'
import { createOnlyFields } from '@/lib/reconSettings/registry'
import { updateProjectScope } from './scopeTools'
import type { McpContext } from './tools'

const EVERY: McpScope[] = [
  'recon:read', 'recon:scan', 'recon:overwrite', 'recon:settings', 'triage:read', 'recon:queue',
  'triage:write', 'graph:cypher', 'project:create', 'engagement:authorize',
  'preset:write', 'preset:apply', 'project:rescope', 'kali:exec',
]
const ctx = (scopes: McpScope[] = ['project:rescope']): McpContext => ({
  token: { tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa', name: 'agent', scopes },
})

const AT = new Date('2026-09-29T08:00:00.000Z')
const AUTH = {
  documentSha256: 'a'.repeat(64),
  documentKind: 'hackerone_program',
  issuedAt: '2026-01-01T00:00:00.000Z',
}

const batchRow = (hosts: string[], over: Record<string, unknown> = {}) => ({
  domainBatchMode: true,
  domainBatchHosts: hosts,
  domainBatchGroups: validateDomainBatch(hosts).groups,
  engagementKind: 'internal',
  githubTargetOrg: '', githubTargetRepos: '', gvmScanTargets: 'both',
  supplyChainOrgName: '', supplyChainRepoUrl: '', supplyChainRepoRef: '', supplyChainRepoScope: '',
  userId: 'owner',
  updatedAt: AT,
  ...over,
})

let row: Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  row = batchRow(['a.example.com', 'b.example.com'])
  h.projectFind.mockImplementation(async (args: { select?: Record<string, unknown> }) =>
    Object.keys(args.select ?? {}).length === 2 ? { id: 'p1', userId: 'owner' } : row)
  h.projectUpdateMany.mockResolvedValue({ count: 1 })
  h.authCreate.mockResolvedValue({ id: 'auth1' })
  h.jobs.mockResolvedValue([])
  h.schedules.mockResolvedValue([])
  h.schedulesUpdate.mockResolvedValue({ count: 0 })
  h.userSettings.mockResolvedValue(null)
  h.live.mockResolvedValue(null)
  h.seed.mockResolvedValue(true)
  h.legacy.mockResolvedValue([])
  h.audit.mockResolvedValue(undefined)
  h.fetch.mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) })
  vi.stubGlobal('fetch', h.fetch)
  h.recordingFind.mockResolvedValue(null)
  h.recordingUpdate.mockResolvedValue({})
  h.mark.mockResolvedValue(true)
  h.activating.mockResolvedValue(false)
})

const call = (changes: Record<string, unknown>, extra: Record<string, unknown> = {}, scopes?: McpScope[]) =>
  updateProjectScope(ctx(scopes), { projectId: 'p1', changes, ...extra } as never)

describe('only the rescopable target lists move', () => {
  test('every other create-only field is refused, whatever the token holds', async () => {
    const fixed = createOnlyFields().filter(f => !f.rescope).map(f => f.key)
    expect(fixed).toHaveLength(11)
    for (const key of fixed) {
      __resetRateLimiter()
      await expect(call({ [key]: 'x' }, {}, EVERY), key).rejects.toMatchObject({ code: 'setting_rejected' })
    }
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('an ordinary setting is pointed at update_recon_settings', async () => {
    await expect(call({ katanaDepth: 3 })).rejects.toThrow(/update_recon_settings/)
  })

  test('the batch grouping is derived here; a caller\'s copy is refused', async () => {
    await expect(call({ domainBatchGroups: [{ rootDomain: 'attacker.example', prefixes: ['*'] }] }))
      .rejects.toMatchObject({ code: 'setting_rejected' })
    await call({ domainBatchHosts: ['a.example.com', 'c.example.org'] })
    const data = h.projectUpdateMany.mock.calls[0][0].data
    // The stored record is the legacy shape, derived here; the hosts are the normalised entries.
    expect(data.domainBatchGroups).toEqual(validateDomainBatch(['a.example.com', 'c.example.org']).legacy)
    expect(data.domainBatchHosts).toEqual(['a.example.com', 'c.example.org'])
    expect(data.updatedById).toBe('owner')
  })
})

describe('values are validated as the form validates them', () => {
  test('the GVM strategy is a closed set', async () => {
    await expect(call({ gvmScanTargets: 'everything' })).rejects.toThrow(/must be one of both, ips_only, hostnames_only/)
    await expect(call({ gvmScanTargets: 'ips_only' })).resolves.toBeTruthy()
  })

  test('GitHub names follow GitHub\'s grammar', async () => {
    await expect(call({ githubTargetOrg: 'bad org!' })).rejects.toMatchObject({ code: 'setting_rejected' })
    await expect(call({ githubTargetRepos: 'owner/repo' })).rejects.toThrow(/no owner\/ prefix/)
    await expect(call({ githubTargetOrg: 'acme-labs', githubTargetRepos: 'api, web.site' })).resolves.toBeTruthy()
  })

  test('a supply-chain repository on a host nobody registered is refused', async () => {
    await expect(call({ supplyChainRepoUrl: 'https://git.example.com/acme/app' }))
      .rejects.toThrow(/Repository must be a repo on github\.com/)
  })

  test('a batch host list on a project that is not a batch is refused', async () => {
    row = batchRow(['a.example.com'], { domainBatchMode: false })
    await expect(call({ domainBatchHosts: ['a.example.com'] })).rejects.toThrow(/not one/)
  })

  test('the permanent guardrail refuses a blocked root', async () => {
    await expect(call({ domainBatchHosts: ['a.example.com', 'portal.example.gov'] }))
      .rejects.toThrow(/permanently blocked/)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('a host under a government name is refused though no group root is blocked', async () => {
    // www.isa.org.jm groups under org.jm, which no rule names: only the host is.
    await expect(call({ domainBatchHosts: ['a.example.com', 'www.isa.org.jm'] }))
      .rejects.toThrow(/permanently blocked: www\.isa\.org\.jm:/)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })
})

describe('widening a third-party engagement needs an authorization', () => {
  beforeEach(() => {
    row = batchRow(['a.example.com', 'b.example.com'], { engagementKind: 'third_party' })
  })

  test('a new root without one is refused, and nothing is written', async () => {
    await expect(call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] }))
      .rejects.toMatchObject({ code: 'authorization_required' })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('a wildcard on an existing root is a widening too', async () => {
    await expect(call({ domainBatchHosts: ['*.example.com'] }))
      .rejects.toMatchObject({ code: 'authorization_required' })
  })

  test('passing an authorization needs engagement:authorize: a scope denial', async () => {
    await expect(call({ domainBatchHosts: ['a.example.com', 'c.example.org'] }, { authorization: AUTH }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('with both, the authorization is written in the same transaction', async () => {
    const r = await call(
      { domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] },
      { authorization: AUTH },
      ['project:rescope', 'engagement:authorize'],
    )
    expect(r.authorizationId).toBe('auth1')
    expect(r.addedRoots).toEqual(['example.org'])
    expect(h.authCreate.mock.calls[0][0].data).toMatchObject({
      projectId: 'p1', documentSha256: 'a'.repeat(64), recordedVia: 'mcp', recordedByTokenId: 't1',
    })
  })

  test('a narrowing needs neither', async () => {
    const r = await call({ domainBatchHosts: ['a.example.com'] })
    expect(r.removedRoots).toEqual([])
    expect(h.authCreate).not.toHaveBeenCalled()
    expect(h.projectUpdateMany).toHaveBeenCalled()
  })

  test('a new GitHub organisation is a widening; emptying the repo list is too', async () => {
    await expect(call({ githubTargetOrg: 'other-org' })).rejects.toMatchObject({ code: 'authorization_required' })
    row = { ...row, githubTargetRepos: 'api' }
    await expect(call({ githubTargetRepos: '' })).rejects.toMatchObject({ code: 'authorization_required' })
    await expect(call({ gvmScanTargets: 'ips_only' })).resolves.toBeTruthy()
  })
})

describe('the write itself', () => {
  test('a compare-and-swap, and a lost one is a conflict', async () => {
    await call({ gvmScanTargets: 'ips_only' })
    expect(h.projectUpdateMany.mock.calls[0][0].where).toEqual({ id: 'p1', updatedAt: AT })
    h.projectUpdateMany.mockResolvedValue({ count: 0 })
    await expect(call({ gvmScanTargets: 'hostnames_only' })).rejects.toMatchObject({ code: 'conflict' })
  })

  test('refused while anything reads or writes the graph', async () => {
    h.live.mockResolvedValue('an agent session is running')
    await expect(call({ gvmScanTargets: 'ips_only' })).rejects.toMatchObject({ code: 'busy' })
    await expect(call({ gvmScanTargets: 'ips_only' })).rejects.toThrow(/stop the session in the RedAmon UI/)
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('a session flag the agent could not confirm says to check the agent (C-8)', async () => {
    h.live.mockResolvedValue('an agent session is marked running and the agent could not be reached to confirm it')
    await expect(call({ gvmScanTargets: 'ips_only' })).rejects.toThrow(/check that its container is up/)
  })

  test('a failed Domain seed is reported, and the update stands', async () => {
    h.seed.mockResolvedValue(false)
    const r = await call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] })
    expect(r.graphSeeded).toBe(false)
    expect(h.projectUpdateMany).toHaveBeenCalled()
    expect(h.seed.mock.calls[0]).toEqual([['example.org'], 'owner', 'p1'])
    expect(h.audit.mock.calls[0][0].after.graphSeeded).toBe(false)
  })

  test('on an old-model graph the new roots are not seeded, and the call says why', async () => {
    h.legacy.mockResolvedValue(['co.uk'])
    const r = await call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.org'] })
    expect(h.projectUpdateMany).toHaveBeenCalled()
    expect(h.seed).not.toHaveBeenCalled()
    expect(r.graphSeeded).toBe(false)
    expect(r.legacyGraph).toEqual(['co.uk'])
    expect(r.note).toMatch(/built before the current scope model; run a full recon first/)
    // asked with the scope as it is after the write
    expect(h.legacy.mock.calls[0][2].map((g: { scanRoot: string }) => g.scanRoot))
      .toEqual(['example.com', 'example.org'])
  })

  test('it reports the queued scans the change parked, by id', async () => {
    h.jobs.mockResolvedValue([{ id: 'j9', kind: 'gvm', projectId: 'p1', payload: {}, settingsHash: 'old' }])
    const r = await call({ gvmScanTargets: 'ips_only' })
    expect(r.queuedJobsNeedingReview).toEqual({ count: 1, jobIds: ['j9'] })
  })

  test('a call that changes nothing is refused', async () => {
    await expect(call({ gvmScanTargets: 'both' })).rejects.toMatchObject({ code: 'bad_args' })
  })
})

describe('a batch that gains hosts pauses the scan schedules (C-7)', () => {
  const SCHEDULES = [{ id: 's1', label: 'nightly' }, { id: 's2', label: '' }]

  test('in the same transaction, and the result and the audit say which', async () => {
    h.schedules.mockResolvedValueOnce(SCHEDULES).mockResolvedValue([])
    h.schedulesUpdate.mockResolvedValue({ count: 2 })
    const r = await call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.com'] })
    expect(h.schedules.mock.calls[0][0]).toEqual({
      where: { projectId: 'p1', enabled: true }, select: { id: true, label: true },
    })
    expect(h.schedulesUpdate).toHaveBeenCalledWith({
      where: { id: { in: ['s1', 's2'] }, enabled: true },
      data: { enabled: false },
    })
    expect(r.pausedSchedules).toEqual({ count: 2, names: ['nightly', 's2'] })
    expect(r.affectedSchedules).toEqual({ count: 0, names: [] })
    expect(r.note).toMatch(/2 scheduled scan\(s\) were paused; a person re-enables them in the Scans tab/)
    expect(h.audit.mock.calls[0][0].after.pausedScheduleIds).toEqual(['s1', 's2'])
  })

  test('a wildcard on an existing root gains entries too', async () => {
    h.schedules.mockResolvedValueOnce(SCHEDULES).mockResolvedValue([])
    await call({ domainBatchHosts: ['a.example.com', 'b.example.com', '*.example.com'] })
    expect(h.schedulesUpdate).toHaveBeenCalled()
  })

  test('the pause is written only when the project update wins its compare-and-swap', async () => {
    h.schedules.mockResolvedValue(SCHEDULES)
    h.projectUpdateMany.mockResolvedValue({ count: 0 })
    await expect(call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.com'] }))
      .rejects.toMatchObject({ code: 'conflict' })
    expect(h.schedulesUpdate).not.toHaveBeenCalled()
  })

  test.each([
    ['a narrowed batch', { domainBatchHosts: ['a.example.com'] }],
    ['a batch that only reorders', { domainBatchHosts: ['b.example.com', 'a.example.com', 'a.example.com'] }],
    ['a new GitHub organisation: no scheduled run reads it', { githubTargetOrg: 'other-org' }],
    ['the GVM strategy', { gvmScanTargets: 'ips_only' }],
  ])('%s pauses nothing and only reports the schedules', async (_label, changes) => {
    h.schedules.mockResolvedValue(SCHEDULES)
    const r = await call(changes)
    expect(h.schedulesUpdate).not.toHaveBeenCalled()
    expect(r.pausedSchedules).toEqual({ count: 0, names: [] })
    expect(r.affectedSchedules).toEqual({ count: 2, names: ['nightly', 's2'] })
    expect(r.note).not.toMatch(/paused/)
  })

  test.each([
    ['a wildcard narrowed to one of its hosts', ['www.example.com']],
    ['a seed under the wildcard', ['*.example.com', 'v1.example.com']],
  ])('%s is no widening by containment (D-21): pauses nothing', async (_label, hosts) => {
    row = batchRow(['*.example.com'])
    h.schedules.mockResolvedValue(SCHEDULES)
    const r = await call({ domainBatchHosts: hosts })
    expect(h.schedulesUpdate).not.toHaveBeenCalled()
    expect(r.pausedSchedules).toEqual({ count: 0, names: [] })
    expect(r.widenings).toEqual([])
  })

  test('no enabled schedule: nothing to pause, no empty update', async () => {
    await call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.com'] })
    expect(h.schedulesUpdate).not.toHaveBeenCalled()
  })
})

describe('the soft guardrail judges a rescope as the form\'s save does (Q-1)', () => {
  const body = () => JSON.parse(h.fetch.mock.calls[0][1].body as string)

  test('a refusal is target_blocked and nothing is written', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ allowed: false, reason: 'a government site' }) })
    await expect(call({ domainBatchHosts: ['a.example.com', 'www.acme.co.uk'] }))
      .rejects.toMatchObject({ code: 'target_blocked', message: expect.stringMatching(/a government site/) })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
    expect(body()).toMatchObject({ target_domain: '', target_domains: ['example.com', 'acme.co.uk'], user_id: 'owner' })
  })

  test('a narrowing is judged too; an unreachable agent fails open', async () => {
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await call({ domainBatchHosts: ['a.example.com'] })
    expect(h.fetch).toHaveBeenCalledTimes(1)
    expect(h.projectUpdateMany).toHaveBeenCalled()
    warn.mockRestore()
  })

  test('a project that switched it off, or a regroup of the same hosts, is not asked', async () => {
    row = batchRow(['a.example.com', 'b.example.com'], { targetGuardrailEnabled: false })
    await call({ domainBatchHosts: ['a.example.com', 'b.example.com', 'c.example.com'] })
    row = batchRow(['a.example.com', 'b.example.com'])
    await call({ domainBatchHosts: ['b.example.com', 'a.example.com'] })
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('an active login recording follows the rescope (WEB-15b)', () => {
  test('its scope is re-derived from the new host list, RoE still applied', async () => {
    row = batchRow(['a.example.com'], { roeExcludedHosts: ['b.example.com'] })
    h.recordingFind.mockResolvedValue({ id: 'rec-1' })
    const r = await call({ domainBatchHosts: ['a.example.com', 'b.example.com', '*.example.org'] })
    expect(h.recordingUpdate).toHaveBeenCalledWith({
      where: { id: 'rec-1' }, data: { scopeHosts: ['a.example.com', '*.example.org'] },
    })
    expect(r.recordingScopeUpdated).toBe(true)
  })

  test('a regroup, or a change that leaves the batch alone, does not touch it', async () => {
    h.recordingFind.mockResolvedValue({ id: 'rec-1' })
    await call({ domainBatchHosts: ['b.example.com', 'a.example.com'] })
    const r = await call({ gvmScanTargets: 'ips_only' })
    expect(h.recordingFind).not.toHaveBeenCalled()
    expect(r.recordingScopeUpdated).toBe(false)
  })
})

describe('an IP project\'s hostname policy (Hostnames on target IPs, design §6.3 and §9)', () => {
  const SCHEDULES = [{ id: 's1', label: 'nightly' }]
  const ipRow = (over: Record<string, unknown> = {}) => batchRow([], {
    domainBatchMode: false, domainBatchGroups: null, ipMode: true,
    ipHostnameMode: 'record_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnamePassiveExpand: true,
    ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
    ...over,
  })
  beforeEach(() => { row = ipRow() })

  test('every policy field is rescopable, and the row is read with ipMode', async () => {
    await call({ ipHostnameMode: 'ip_only' })
    const select = h.projectFind.mock.calls.map(([a]) => a?.select).find(s => s && 'ipHostnameMode' in s)
    for (const key of ['ipMode', 'ipHostnameMode', 'ipHostnameInclude', 'ipHostnameExclude',
      'ipHostnamePassiveExpand', 'ipHostnameScanAllConfirmed', 'ipHostnameMaxScanned', 'ipHostnamePassiveMaxNames']) {
      expect(select[key], key).toBe(true)
    }
  })

  test('record_only -> record_filter is a widening: enabled schedules pause, the result says which', async () => {
    h.schedules.mockResolvedValueOnce(SCHEDULES).mockResolvedValue([])
    const r = await call({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] })
    expect(r.widenings).toEqual(['hostname mode record_only -> record_filter'])
    expect(h.schedulesUpdate).toHaveBeenCalledWith({ where: { id: { in: ['s1'] }, enabled: true }, data: { enabled: false } })
    expect(r.pausedSchedules).toEqual({ count: 1, names: ['nightly'] })
    expect(r.note).toMatch(/The hostname policy widened, so 1 scheduled scan\(s\) were paused/)
    expect(h.projectUpdateMany.mock.calls[0][0].data.ipHostnameInclude).toEqual(['*.example.com'])
  })

  test('ip_only -> record_only pauses nothing: lookups, not target traffic', async () => {
    row = ipRow({ ipHostnameMode: 'ip_only' })
    h.schedules.mockResolvedValue(SCHEDULES)
    const r = await call({ ipHostnameMode: 'record_only' })
    expect(r.widenings).toEqual([])
    expect(h.schedulesUpdate).not.toHaveBeenCalled()
  })

  test.each([
    ['an include entry added', { ipHostnameInclude: ['*.example.com', '*.example.org'] }],
    ['an exclude entry removed', { ipHostnameExclude: [] }],
    ['passive expansion turned on', { ipHostnamePassiveExpand: true }],
    ['the scan cap raised', { ipHostnameMaxScanned: 500 }],
  ])('%s is a widening that pauses the schedules', async (_name, changes) => {
    row = ipRow({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'],
      ipHostnameExclude: ['old.example.com'], ipHostnamePassiveExpand: false })
    h.schedules.mockResolvedValueOnce(SCHEDULES).mockResolvedValue([])
    const r = await call(changes)
    expect(r.widenings.length).toBeGreaterThan(0)
    expect(h.schedulesUpdate).toHaveBeenCalled()
  })

  test('a third-party widening without an authorization is refused, nothing written', async () => {
    row = ipRow({ engagementKind: 'third_party' })
    await expect(call({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }))
      .rejects.toMatchObject({ code: 'authorization_required', message: expect.stringMatching(/hostname mode record_only -> record_filter/) })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('a third-party widening with its authorization is written with it', async () => {
    row = ipRow({ engagementKind: 'third_party' })
    const r = await call({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] },
      { authorization: AUTH }, ['project:rescope', 'engagement:authorize'])
    expect(r.authorizationId).toBe('auth1')
  })

  test('scan_all is refused on a third-party engagement, even with an authorization (D-03)', async () => {
    row = ipRow({ engagementKind: 'third_party' })
    await expect(call({ ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true },
      { authorization: AUTH }, ['project:rescope', 'engagement:authorize']))
      .rejects.toMatchObject({ code: 'setting_rejected', message: expect.stringMatching(/third_party/) })
  })

  test('scan_all without its confirmation is refused', async () => {
    await expect(call({ ipHostnameMode: 'scan_all' })).rejects.toThrow(/ipHostnameScanAllConfirmed/)
  })

  test('a hard-blocked include entry is refused as target_blocked', async () => {
    await expect(call({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.agency.gov.uk'] }))
      .rejects.toMatchObject({ code: 'target_blocked' })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('a policy change waits for a version activation', async () => {
    h.activating.mockResolvedValue(true)
    await expect(call({ ipHostnameMode: 'ip_only' })).rejects.toMatchObject({ code: 'busy' })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })

  test('refused while anything reads or writes the graph', async () => {
    h.live.mockResolvedValue('a full recon is running')
    await expect(call({ ipHostnameMode: 'ip_only' })).rejects.toMatchObject({ code: 'busy' })
  })

  test('a domain project has no hostname policy to change', async () => {
    row = batchRow(['a.example.com'])
    await expect(call({ ipHostnameMode: 'record_only' })).rejects.toThrow(/only to IP-mode projects/)
  })

  test('leaving scan_all writes the reset confirmation too', async () => {
    row = ipRow({ ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true })
    await call({ ipHostnameMode: 'record_only' })
    expect(h.projectUpdateMany.mock.calls[0][0].data).toMatchObject({
      ipHostnameMode: 'record_only', ipHostnameScanAllConfirmed: false,
    })
  })

  test('a narrowing runs the marker after the commit and returns hostnamePolicyMarked', async () => {
    row = ipRow({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] })
    const r = await call({ ipHostnameMode: 'record_only' })
    expect(r.hostnamePolicyMarked).toBe(true)
    expect(h.mark).toHaveBeenCalledTimes(1)
    expect(h.mark.mock.calls[0].slice(0, 2)).toEqual(['p1', 'owner'])
    expect(h.mark.mock.calls[0][2].ipHostnameMode).toBe('record_only')
    expect(h.projectUpdateMany.mock.invocationCallOrder[0]).toBeLessThan(h.mark.mock.invocationCallOrder[0])
    expect(h.schedulesUpdate).not.toHaveBeenCalled()
  })

  test('a marker that throws answers false, says so, and the change stands', async () => {
    row = ipRow({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] })
    h.mark.mockRejectedValue(new Error('neo4j down'))
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const r = await call({ ipHostnameExclude: ['old.example.com'] })
    expect(r.hostnamePolicyMarked).toBe(false)
    expect(r.note).toMatch(/could not be marked out_of_policy/)
    expect(h.projectUpdateMany).toHaveBeenCalled()
    warn.mockRestore()
  })

  test('a widening runs no marker and carries no hostnamePolicyMarked', async () => {
    const r = await call({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] })
    expect(h.mark).not.toHaveBeenCalled()
    expect(r).not.toHaveProperty('hostnamePolicyMarked')
  })
})

// Review of 5.12 (finding 5): the scope waits while an ownership transfer holds the project.
describe('update_project_scope during an ownership transfer (review of 5.12)', () => {
  test('refused with project_transfer_in_progress, nothing written', async () => {
    row = { ...row, activationState: 'transfer_split', activationStartedAt: null }
    await expect(call({ gvmScanTargets: 'ips_only' })).rejects.toMatchObject({ code: 'project_transfer_in_progress' })
    expect(h.projectUpdateMany).not.toHaveBeenCalled()
  })
})
