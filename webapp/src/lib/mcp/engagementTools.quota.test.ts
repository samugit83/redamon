/**
 * create_project obeys the token user's project quota (step 6.8, GV-09), as the HTTP create and import
 * do: at maxProjects owned it fails with `quota_exceeded` (the refusal audited by the server with the
 * quota and the limit) and creates nothing; an idempotent replay of a project already created is still
 * answered; under the limit, unlimited, or with RBAC_GOVERNANCE_ENABLED off (nothing read) it creates as
 * before. The resolution is the real lib/authz/quotas.ts over a doubled instance row, account and
 * capability resolution.
 *
 * Same harness as engagementTools.ownershipToken.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  owned: 0,
  count: vi.fn(),
  replay: null as null | { projectId: string; project: { userId: string; name: string } },
  quotas: {} as unknown,
  instanceRead: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: async () => null,
      count: async (...a: unknown[]) => { h.count(...a); return h.owned },
    },
    engagementAuthorization: {
      create: vi.fn(), findFirst: async () => null, findUnique: async () => h.replay,
      findMany: async () => [], count: async () => 0,
    },
    scanJob: { findFirst: async () => null },
    userLlmProvider: { count: async () => 0 },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => undefined) }))
vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => { h.instanceRead(); return { quotas: h.quotas } },
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active', legacyGrants: [], permissionSets: [], permissionOverrides: [] }),
}))
vi.mock('@/lib/authz/capabilities', () => ({
  resolveCapabilities: async () => ({ accountType: 'member', sets: [{ id: 'builtin:default-member', name: 'Default member', kind: 'member', via: 'default' }] }),
}))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { McpToolError } from './errors'
import { createProject } from './engagementTools'
import type { McpContext } from './tools'

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'creator', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'project:create'] as never,
  },
})

const create = (extra: Record<string, unknown> = {}) => createProject(ctx(), {
  name: 'test', engagementKind: 'internal', targetDomain: 'example.invalid',
  settings: { targetGuardrailEnabled: false } as never, ...extra,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.owned = 0
  h.replay = null
  h.quotas = { defaults: { maxProjects: 2 } }
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('create_project: the project quota', () => {
  test('under the limit the project is created; the owned count is the token user\'s', async () => {
    h.owned = 1
    await create()
    expect(h.createProject).toHaveBeenCalledTimes(1)
    expect(h.count).toHaveBeenCalledWith({ where: { userId: 'creator' } })
  })

  test('at the limit: quota_exceeded with the quota and the limit for the audit row; nothing created; logged', async () => {
    h.owned = 2
    const err = await create().catch((e) => e)
    expect(err).toBeInstanceOf(McpToolError)
    expect(err.code).toBe('quota_exceeded')
    expect(err.audit).toEqual({ quota: 'maxProjects', limit: 2 })
    expect(err.message).toMatch(/limit is 2 projects you own/)
    expect(h.createProject).not.toHaveBeenCalled()
    expect(console.warn).toHaveBeenCalledWith('[rbac] quota_exceeded quota=maxProjects user=creator limit=2 used=2')
  })

  test('an idempotent replay of a project already created is answered, even at the limit', async () => {
    h.owned = 2
    h.replay = { projectId: 'p0', project: { userId: 'creator', name: 'first' } }
    expect(await create({ idempotencyKey: 'k-1' })).toMatchObject({ projectId: 'p0', created: false })
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('unlimited, and the switch off: created, and with the switch off nothing read', async () => {
    h.quotas = {}
    h.owned = 99
    await create()
    setFlagsForTests({ identity: true, permissions: true })
    h.quotas = { defaults: { maxProjects: 0 } }
    h.instanceRead.mockClear()
    await create()
    expect(h.createProject).toHaveBeenCalledTimes(2)
    expect(h.instanceRead).not.toHaveBeenCalled()
  })
})
