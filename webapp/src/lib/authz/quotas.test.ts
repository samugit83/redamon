/**
 * Step 6.8 (GV-09..GV-11, GV-13; OQ-39): the quota store, the resolution order, the reader behind the
 * switch and the refusal helpers. The database, the instance row, the principal and the capability
 * resolution are doubles; the clock is pinned.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/quotas.test.ts
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const db = vi.hoisted(() => ({
  instanceRow: null as null | { quotas: unknown },
  instanceRead: vi.fn(),
  principal: vi.fn(),
  caps: vi.fn(),
  projectCount: vi.fn(),
  tokenCount: vi.fn(),
  setFind: vi.fn(),
  userFind: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { count: db.projectCount },
    mcpAccessToken: { count: db.tokenCount },
    permissionSet: { findMany: db.setFind },
    user: { findMany: db.userFind },
  },
}))
vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => {
    db.instanceRead()
    return db.instanceRow
  },
}))
vi.mock('./principal', () => ({ loadPrincipal: db.principal }))
vi.mock('./capabilities', () => ({ resolveCapabilities: db.caps }))

import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import {
  QUOTA_FIELDS, UNLIMITED, actorScanCap, activeMcpTokenCount, applyQuotaPatch, changedQuotaKeys,
  clearQuotaWarningsForTests, latestTokenExpiryAllowed, mcpTokenQuotaRefusal, mcpTokenQuotaView,
  parseQuotaPatch, parseQuotaStore, projectQuotaReached, projectQuotaRefusal, quotaFor, quotaLimit,
  resolveQuota, storeIsEmpty, unknownQuotaTargets, type QuotaStore,
} from './quotas'

const GOV_ON = { identity: true, permissions: true, governance: true }
const store = (s: Partial<QuotaStore>): QuotaStore => ({ defaults: {}, perSet: {}, perUser: {}, ...s })

function member(sets: string[], accountType: 'member' | 'admin' | 'root' = 'member') {
  db.principal.mockResolvedValue({ id: 'u1', role: accountType === 'member' ? 'standard' : 'admin', status: 'active' })
  db.caps.mockResolvedValue({ accountType, sets: sets.map((id) => ({ id, name: id, kind: 'member', via: 'assigned' })) })
}

beforeEach(() => {
  vi.clearAllMocks()
  db.instanceRow = null
  clearQuotaWarningsForTests()
  setFlagsForTests(GOV_ON)
  setNowForTests(() => new Date('2026-11-13T12:00:00Z'))
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('the stored value', () => {
  test('{} and anything that is not an object read as unlimited', () => {
    for (const raw of [{}, null, undefined, 'x', 3, []]) {
      const s = parseQuotaStore(raw)
      expect(storeIsEmpty(s)).toBe(true)
      expect(resolveQuota(s, { userId: 'u1', setIds: ['a'] }).quota).toEqual(UNLIMITED)
    }
  })

  test('an invalid stored value reads as unlimited (null) and is logged once', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const s = parseQuotaStore({ defaults: { maxProjects: -1, maxMcpTokens: 2.5, maxConcurrentScans: 3, bogus: 1 }, perSet: 'no' })
    expect(s.defaults).toEqual({ maxProjects: null, maxMcpTokens: null, maxConcurrentScans: 3 })
    expect(s.perSet).toEqual({})
    parseQuotaStore({ defaults: { maxProjects: -1 } })
    expect(warn.mock.calls.filter(([l]) => String(l).includes('defaults.maxProjects'))).toHaveLength(1)
    expect(warn.mock.calls.every(([l]) => String(l).startsWith('[rbac] quotas:'))).toBe(true)
    warn.mockRestore()
  })
})

describe('resolution order', () => {
  const s = store({
    defaults: { maxProjects: 2, maxConcurrentScans: 1 },
    perSet: { recon: { maxProjects: 5, maxMcpTokens: 1 }, lab: { maxProjects: 3, maxMcpTokens: null }, big: { maxProjects: null } },
    perUser: { u1: { maxProjects: 1 }, u2: { maxConcurrentScans: null } },
  })

  test('the per-user value wins over every set and the default', () => {
    const r = resolveQuota(s, { userId: 'u1', setIds: ['recon', 'big'] })
    expect(r.quota.maxProjects).toBe(1)
    expect(r.sources.maxProjects).toEqual({ kind: 'user' })
  })

  test('else the most permissive of the sets in force: the larger number, and null (unlimited) beats any', () => {
    expect(resolveQuota(s, { userId: 'u9', setIds: ['lab', 'recon'] }).quota.maxProjects).toBe(5)
    const r = resolveQuota(s, { userId: 'u9', setIds: ['recon', 'big'] })
    expect(r.quota.maxProjects).toBeNull()
    expect(r.sources.maxProjects).toEqual({ kind: 'set', setId: 'big' })
    expect(resolveQuota(s, { userId: 'u9', setIds: ['recon', 'lab'] }).quota.maxMcpTokens).toBeNull()
  })

  test('a set with no value for a field leaves it to the default; sets not held count for nobody', () => {
    const r = resolveQuota(s, { userId: 'u9', setIds: ['recon'] })
    expect(r.quota.maxConcurrentScans).toBe(1)
    expect(r.sources.maxConcurrentScans).toEqual({ kind: 'default' })
    expect(resolveQuota(s, { userId: 'u9', setIds: ['other'] }).quota.maxProjects).toBe(2)
  })

  test('null unlimited: a default left out or null limits nothing; a per-user null lifts a default', () => {
    const r = resolveQuota(s, { userId: 'u2', setIds: [] })
    expect(r.quota.maxConcurrentScans).toBeNull()
    expect(r.quota.maxConcurrentAgentRuns).toBeNull()
    expect(r.quota.llmDailyCalls).toBeNull()
    expect(r.sources.maxConcurrentAgentRuns).toEqual({ kind: 'default' })
  })

  test('every field resolves, llmDailyCalls (6.11) included', () => {
    expect(Object.keys(resolveQuota(s, { userId: 'u1', setIds: [] }).quota).sort()).toEqual([...QUOTA_FIELDS].sort())
  })
})

describe('the reader', () => {
  test('switch off: nothing enforced and nothing read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    db.instanceRow = { quotas: { defaults: { maxProjects: 0 } } }
    const r = await quotaFor('u1')
    expect(r.enforced).toBe(false)
    expect(r.quota).toEqual(UNLIMITED)
    expect(db.instanceRead).not.toHaveBeenCalled()
    expect(await projectQuotaRefusal('u1')).toBeNull()
    expect(await actorScanCap('u1')).toEqual({})
    expect(db.projectCount).not.toHaveBeenCalled()
  })

  test('an empty store costs no account read', async () => {
    db.instanceRow = { quotas: {} }
    expect((await quotaFor('u1')).quota).toEqual(UNLIMITED)
    expect(db.principal).not.toHaveBeenCalled()
  })

  test('the sets come from the capability resolution, read fresh', async () => {
    db.instanceRow = { quotas: { defaults: { maxProjects: 1 }, perSet: { 'builtin:recon-operator': { maxProjects: 4 } } } }
    member(['builtin:recon-operator'])
    expect(await quotaLimit('u1', 'maxProjects')).toBe(4)
    expect(db.principal).toHaveBeenCalledWith('u1', { fresh: true })
    expect(db.caps).toHaveBeenCalledWith(expect.anything(), { fresh: true })
  })

  test('Root is never limited', async () => {
    db.instanceRow = { quotas: { defaults: { maxProjects: 0 }, perUser: { u1: { maxProjects: 0 } } } }
    member([], 'root')
    const r = await quotaFor('u1')
    expect(r.enforced).toBe(false)
    expect(r.sources.maxProjects).toEqual({ kind: 'root' })
  })

  test('a failed read throws (the write is refused, never let through)', async () => {
    db.instanceRow = { quotas: { defaults: { maxProjects: 1 } } }
    db.principal.mockRejectedValue(new Error('db down'))
    await expect(projectQuotaRefusal('u1')).rejects.toThrow('db down')
  })
})

describe('project quota', () => {
  beforeEach(() => {
    db.instanceRow = { quotas: { defaults: { maxProjects: 2 } } }
    member([])
  })

  test('under the limit passes; at it, 409 quota_exceeded with the quota and limit, logged', async () => {
    db.projectCount.mockResolvedValue(1)
    expect(await projectQuotaRefusal('u1')).toBeNull()
    expect(db.projectCount).toHaveBeenCalledWith({ where: { userId: 'u1' } })
    db.projectCount.mockResolvedValue(2)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = await projectQuotaRefusal('u1')
    expect(res!.status).toBe(409)
    const body = await res!.json()
    expect(body).toMatchObject({ code: 'quota_exceeded', quota: 'maxProjects', limit: 2 })
    expect(body.error).toMatch(/limit is 2 projects/)
    expect(warn).toHaveBeenCalledWith('[rbac] quota_exceeded quota=maxProjects user=u1 limit=2 used=2')
    warn.mockRestore()
  })

  test('a limit of 0 refuses the first project', async () => {
    db.instanceRow = { quotas: { defaults: { maxProjects: 0 } } }
    db.projectCount.mockResolvedValue(0)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect((await projectQuotaRefusal('u1'))!.status).toBe(409)
  })
})

describe('scan cap and token count', () => {
  test('the actor\'s maxConcurrentScans travels as actor_max_concurrent; unlimited sends nothing', async () => {
    db.instanceRow = { quotas: { perUser: { u1: { maxConcurrentScans: 2 } } } }
    member([])
    expect(await actorScanCap('u1')).toEqual({ actor_max_concurrent: 2 })
    expect(await actorScanCap('u2')).toEqual({})
  })

  test('active tokens: not revoked and not expired on the clock', async () => {
    db.tokenCount.mockResolvedValue(3)
    expect(await activeMcpTokenCount('u1')).toBe(3)
    expect(db.tokenCount).toHaveBeenCalledWith({
      where: { userId: 'u1', revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: new Date('2026-11-13T12:00:00Z') } }] },
    })
  })
})

describe('token count and expiry', () => {
  const NOW = new Date('2026-11-13T12:00:00Z')
  const DAY = 86_400_000

  beforeEach(() => {
    db.instanceRow = { quotas: { defaults: { maxMcpTokens: 2, maxMcpTokenExpiryDays: 90 } } }
    member([])
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  test('the latest expiry allowed is the end (UTC) of the day N days out', () => {
    expect(latestTokenExpiryAllowed(90, NOW).toISOString()).toBe('2027-02-11T23:59:59.999Z')
  })

  test('expiry: "never" and anything past the allowed day refused; within it allowed', async () => {
    db.tokenCount.mockResolvedValue(0)
    expect((await mcpTokenQuotaRefusal('u1', null, { counting: false }))!.status).toBe(409)
    const late = await mcpTokenQuotaRefusal('u1', new Date(NOW.getTime() + 91 * DAY), { counting: false })
    expect(await late!.json()).toMatchObject({ code: 'quota_exceeded', quota: 'maxMcpTokenExpiryDays', limit: 90 })
    expect(await mcpTokenQuotaRefusal('u1', new Date(NOW.getTime() + 90 * DAY), { counting: true })).toBeNull()
    expect(await mcpTokenQuotaRefusal('u1', latestTokenExpiryAllowed(90), { counting: false })).toBeNull()
  })

  test('token count: counted only when asked (a mint, a revival); at the limit refused', async () => {
    db.tokenCount.mockResolvedValue(2)
    const soon = new Date(NOW.getTime() + 30 * DAY)
    expect(await mcpTokenQuotaRefusal('u1', soon, { counting: false })).toBeNull()
    expect(db.tokenCount).not.toHaveBeenCalled()
    const res = await mcpTokenQuotaRefusal('u1', soon, { counting: true })
    expect(await res!.json()).toMatchObject({ quota: 'maxMcpTokens', limit: 2 })
  })

  test('the screen\'s view: limits and the count, or null when neither token quota applies', async () => {
    db.tokenCount.mockResolvedValue(1)
    expect(await mcpTokenQuotaView('u1')).toEqual({ maxMcpTokens: 2, maxMcpTokenExpiryDays: 90, active: 1 })
    db.instanceRow = { quotas: { defaults: { maxProjects: 1 } } }
    expect(await mcpTokenQuotaView('u1')).toBeNull()
  })

  test('projectQuotaReached gives the limit and the count for the MCP error', async () => {
    db.instanceRow = { quotas: { defaults: { maxProjects: 1 } } }
    db.projectCount.mockResolvedValue(1)
    expect(await projectQuotaReached('u1')).toEqual({ limit: 1, used: 1 })
    db.projectCount.mockResolvedValue(0)
    expect(await projectQuotaReached('u1')).toBeNull()
  })
})

describe('writes', () => {
  test('a patch is checked: known fields, whole numbers in bounds, null for unlimited', () => {
    expect(parseQuotaPatch({ defaults: { maxProjects: 3, llmDailyCalls: null } })).toEqual({
      patch: { defaults: { maxProjects: 3, llmDailyCalls: null } },
    })
    expect(parseQuotaPatch('x')).toMatchObject({ error: { field: 'quotas' } })
    expect(parseQuotaPatch({ other: {} })).toMatchObject({ error: { field: 'quotas.other' } })
    expect(parseQuotaPatch({ defaults: { maxProjects: -1 } })).toMatchObject({ error: { field: 'quotas.defaults.maxProjects' } })
    expect(parseQuotaPatch({ defaults: { maxMcpTokenExpiryDays: 0 } })).toMatchObject({ error: { field: 'quotas.defaults.maxMcpTokenExpiryDays' } })
    expect(parseQuotaPatch({ defaults: { maxProjects: '3' } })).toMatchObject({ error: {} })
    expect(parseQuotaPatch({ perSet: { s1: { nope: 1 } } })).toMatchObject({ error: { field: 'quotas.perSet.s1.nope' } })
    expect(parseQuotaPatch({ perUser: { u1: null, u2: { maxMcpTokens: 0 } } })).toEqual({
      patch: { perUser: { u1: null, u2: { maxMcpTokens: 0 } } },
    })
  })

  test('apply: defaults replaced, named entries replaced or removed (null or empty), others kept', () => {
    const before = store({
      defaults: { maxProjects: 2 },
      perSet: { a: { maxProjects: 3 }, b: { maxProjects: 4 } },
      perUser: { u1: { maxProjects: 1 }, u2: { maxProjects: 9 } },
    })
    const after = applyQuotaPatch(before, {
      defaults: { maxConcurrentScans: 1 },
      perSet: { a: null, c: { maxMcpTokens: 2 } },
      perUser: { u1: {} },
    })
    expect(after).toEqual({
      defaults: { maxConcurrentScans: 1 },
      perSet: { b: { maxProjects: 4 }, c: { maxMcpTokens: 2 } },
      perUser: { u2: { maxProjects: 9 } },
    })
    expect(before.perSet.a).toEqual({ maxProjects: 3 })
    expect(changedQuotaKeys(before, after)).toEqual([
      'defaults.maxProjects', 'defaults.maxConcurrentScans', 'perSet.a', 'perSet.c', 'perUser.u1',
    ])
    expect(changedQuotaKeys(after, after)).toEqual([])
  })

  test('a new entry must name a set or an account that exists; removals are never refused', async () => {
    db.setFind.mockResolvedValue([{ id: 'cset' }])
    db.userFind.mockResolvedValue([{ id: 'u1' }])
    expect(await unknownQuotaTargets({
      perSet: { 'builtin:recon-operator': { maxProjects: 1 }, 'builtin:nope': { maxProjects: 1 }, cset: { maxProjects: 1 }, gone: { maxProjects: 1 }, old: null },
      perUser: { u1: { maxProjects: 1 }, ghost: { maxProjects: 1 }, left: null },
    })).toEqual({ sets: ['builtin:nope', 'gone'], users: ['ghost'] })
    expect(db.setFind).toHaveBeenCalledWith({ where: { id: { in: ['builtin:nope', 'cset', 'gone'] } }, select: { id: true } })
  })
})
