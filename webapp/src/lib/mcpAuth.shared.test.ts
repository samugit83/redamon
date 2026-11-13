/**
 * MCP tokens and shared projects (step 4.10; SH-42, PE-20 project level): a token reaches a project
 * shared with its user only when it opted in, only when its allowlist is empty or names the project,
 * and only through a share (never oversight or break-glass); then a read tool needs `R`, a raw tool
 * `R*`, and every other tool stays the owner's. A revoked or expired share fails the next call.
 *
 * Real assertMcpProjectAccess, projectAccess(), the sharing policy reader and capabilities over the
 * sharedProjectDb double; the write tools' own effects are never reached.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  agentCalls: 0,
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => undefined }))

import {
  McpAccessDenied, McpLevelDenied, __resetRateLimiter, assertMcpProjectAccess, isTokenWidening, mcpProjectAccess,
  resolveMcpToken, hashToken, validateSharedReach, type ResolvedMcpToken,
} from '@/lib/mcpAuth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { setNowForTests } from '@/lib/authz/clock'
import {
  COLLABORATOR, OVERSEER, OWNER, SHARED_PROJECT, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'
import { startRecon, updateReconSettings } from '@/lib/mcp/writeTools'
import { queueRecon } from '@/lib/mcp/queueTools'
import { getReconSettings, graphSummary } from '@/lib/mcp/tools'
import type { McpContext } from '@/lib/mcp/tools'

const ALL_SCOPES = ['recon:read', 'recon:scan', 'recon:settings', 'recon:queue', 'graph:cypher'] as never

function token(userId: string, sharedProjects?: ResolvedMcpToken['sharedProjects']): ResolvedMcpToken {
  return { tokenId: `tok-${userId}`, userId, tokenPrefix: 'rdmn_mcp_0a1b2c3d', name: 'agent', scopes: ALL_SCOPES, sharedProjects }
}
const optedIn = (userId: string, allowlist: string[] = []) => token(userId, { allowlist })
const ctxOf = (t: ResolvedMcpToken): McpContext => ({ token: t })

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.agentCalls = 0
  __resetRateLimiter()
  vi.stubGlobal('fetch', async () => { h.agentCalls += 1; return new Response('{}', { status: 500 }) })
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('which tokens reach a shared project', () => {
  test('existing token never reaches a shared project', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    const legacy = token(COLLABORATOR)
    await expect(assertMcpProjectAccess(legacy, SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    await expect(assertMcpProjectAccess(token(COLLABORATOR, null), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    // A bare user id is a token that never opted in, at every level.
    await expect(assertMcpProjectAccess(COLLABORATOR, SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    // The level refusal is not raised either: the token does not reach the project at all.
    await expect(assertMcpProjectAccess(legacy, SHARED_PROJECT)).rejects.not.toBeInstanceOf(McpLevelDenied)
  })

  test('opt-in reaches it, answering the owner as the tenant', async () => {
    shareWith(h.db, COLLABORATOR)
    expect(await assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R')).toEqual({ id: SHARED_PROJECT, userId: OWNER })
    const { access } = await mcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R')
    expect(access).toMatchObject({ level: 'read', via: 'share', toggles: { rawData: false } })
  })

  test('allowlist limits it', async () => {
    shareWith(h.db, COLLABORATOR)
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR, ['P-other']), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    expect(await assertMcpProjectAccess(optedIn(COLLABORATOR, ['P-other', SHARED_PROJECT]), SHARED_PROJECT, 'R'))
      .toEqual({ id: SHARED_PROJECT, userId: OWNER })
  })

  test("the allowlist narrows shared projects only: the owner's own token reaches its projects whatever it names", async () => {
    expect(await assertMcpProjectAccess(optedIn(OWNER, ['P-other']), SHARED_PROJECT)).toEqual({ id: SHARED_PROJECT, userId: OWNER })
  })

  test('a token that opted in reaches no project that is not shared with its user', async () => {
    await expect(assertMcpProjectAccess(optedIn('carol'), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), 'P-missing', 'R')).rejects.toThrow(new McpAccessDenied())
  })

  test('oversight never opens a project to a token, opted in or not', async () => {
    await expect(assertMcpProjectAccess(optedIn(OVERSEER), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    await expect(assertMcpProjectAccess(token(OVERSEER), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
  })

  test("Root's break-glass never opens a project to a token", async () => {
    h.db.breakGlass.set(`${SHARED_PROJECT}|${OVERSEER}`, new Date(Date.now() + 3_600_000))
    await expect(assertMcpProjectAccess(optedIn(OVERSEER), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
  })

  test('with sharing not in force an opted-in token reaches only its own projects (DV-30)', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    h.db.policy = {}
    clearSharingPolicyCacheForTests()
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
  })
})

describe('the level a tool needs on a shared project', () => {
  test('write tool refused on a shared project', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    const ctx = ctxOf(optedIn(COLLABORATOR))
    for (const call of [
      () => updateReconSettings(ctx, SHARED_PROJECT, { naabuEnabled: false }),
      () => startRecon(ctx, SHARED_PROJECT),
      () => queueRecon(ctx, SHARED_PROJECT),
    ]) {
      const err = await call().catch((e: unknown) => e)
      expect(err).toBeInstanceOf(McpLevelDenied)
      // A level refusal is still an access refusal, so every caller that maps McpAccessDenied keeps refusing.
      expect(err).toBeInstanceOf(McpAccessDenied)
      expect((err as Error).message).toMatch(/shared with your account at Read access/)
    }
    expect(h.db.writes).toEqual([])
    expect(h.agentCalls).toBe(0)
  })

  test('a share stored as write still reads as read until Phase 5: the write tool is refused', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write', rawData: true })
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT)).rejects.toBeInstanceOf(McpLevelDenied)
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'W')).rejects.toBeInstanceOf(McpLevelDenied)
  })

  test('a raw tool needs Raw data & files', async () => {
    shareWith(h.db, COLLABORATOR)
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R*')).rejects.toThrow(/without Raw data & files/)
    shareWith(h.db, COLLABORATOR, { rawData: true })
    expect(await assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R*')).toEqual({ id: SHARED_PROJECT, userId: OWNER })
  })

  test("the owner's token reaches every level, as before", async () => {
    for (const level of ['R', 'R*', 'W', 'M', 'O'] as const) {
      expect(await assertMcpProjectAccess(token(OWNER), SHARED_PROJECT, level)).toEqual({ id: SHARED_PROJECT, userId: OWNER })
    }
  })
})

describe('a share that ends', () => {
  test('revoked share → next call 404', async () => {
    shareWith(h.db, COLLABORATOR)
    const ctx = ctxOf(optedIn(COLLABORATOR))
    await expect(getReconSettings(ctx, SHARED_PROJECT)).resolves.toMatchObject({ projectId: SHARED_PROJECT })
    h.db.shares.clear()
    await expect(getReconSettings(ctx, SHARED_PROJECT)).rejects.toThrow(new McpAccessDenied())
  })

  test('an expired share fails the next call', async () => {
    const at = new Date('2026-11-13T12:00:00Z')
    setNowForTests(() => at)
    shareWith(h.db, COLLABORATOR, { expiresAt: new Date(at.getTime() + 60_000) })
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R')).resolves.toEqual({ id: SHARED_PROJECT, userId: OWNER })
    setNowForTests(() => new Date(at.getTime() + 120_000))
    await expect(graphSummary(ctxOf(optedIn(COLLABORATOR)), SHARED_PROJECT)).rejects.toThrow(new McpAccessDenied())
  })

  test("a collaborator's disabled account ends the share", async () => {
    shareWith(h.db, COLLABORATOR, { status: 'disabled' })
    await expect(assertMcpProjectAccess(optedIn(COLLABORATOR), SHARED_PROJECT, 'R')).rejects.toThrow(new McpAccessDenied())
  })
})

describe('the token row carries the opt-in', () => {
  const PLAIN = 'rdmn_mcp_' + 'ab'.repeat(24)
  const row = (over: Record<string, unknown>) => ({
    id: 't1', userId: COLLABORATOR, name: 'agent', tokenPrefix: PLAIN.slice(0, 17), tokenHash: hashToken(PLAIN),
    scopes: ['recon:read'], revokedAt: null, expiresAt: null, ...over,
  })

  test.each([
    ['opted in, no allowlist', { includeSharedProjects: true, projectAllowlist: [] }, { allowlist: [] }],
    ['opted in, an allowlist', { includeSharedProjects: true, projectAllowlist: ['P-1'] }, { allowlist: ['P-1'] }],
    ['not opted in (an allowlist without the opt-in means nothing)', { includeSharedProjects: false, projectAllowlist: ['P-1'] }, null],
    ['a row from before sharing (no column)', {}, null],
  ])('%s', async (_what, columns, expected) => {
    h.db.models.mcpAccessToken = { findUnique: () => row(columns) }
    const resolved = await resolveMcpToken(PLAIN)
    expect(resolved.ok).toBe(true)
    expect(resolved.token?.sharedProjects ?? null).toEqual(expected)
  })
})

describe('opt-in needs the password: opening a token to shared projects widens it', () => {
  const base = { scopes: ['recon:read'], expiresAt: null }
  test.each([
    ['opting in', { includeSharedProjects: false }, { includeSharedProjects: true, projectAllowlist: [] }, true],
    ['opting in with an allowlist', { includeSharedProjects: false }, { includeSharedProjects: true, projectAllowlist: ['P-1'] }, true],
    ['emptying the allowlist (every shared project)', { includeSharedProjects: true, projectAllowlist: ['P-1'] }, { includeSharedProjects: true, projectAllowlist: [] }, true],
    ['naming another project', { includeSharedProjects: true, projectAllowlist: ['P-1'] }, { includeSharedProjects: true, projectAllowlist: ['P-1', 'P-2'] }, true],
    ['naming fewer', { includeSharedProjects: true, projectAllowlist: ['P-1', 'P-2'] }, { includeSharedProjects: true, projectAllowlist: ['P-1'] }, false],
    ['naming some where it reached every one', { includeSharedProjects: true, projectAllowlist: [] }, { includeSharedProjects: true, projectAllowlist: ['P-1'] }, false],
    ['opting out', { includeSharedProjects: true, projectAllowlist: [] }, { includeSharedProjects: false, projectAllowlist: [] }, false],
    ['an edit that leaves the opt-in alone', { includeSharedProjects: false }, {}, false],
  ])('%s', (_what, before, after, widens) => {
    expect(isTokenWidening({ ...base, ...before }, { ...base, ...after })).toBe(widens)
  })
})

describe('validateSharedReach', () => {
  test('a valid opt-in, deduplicated', () => {
    expect(validateSharedReach(true, ['P-1', 'P-1', 'P-2'])).toEqual({ includeSharedProjects: true, projectAllowlist: ['P-1', 'P-2'] })
  })
  test('without the opt-in the allowlist is dropped', () => {
    expect(validateSharedReach(false, ['P-1'])).toEqual({ includeSharedProjects: false, projectAllowlist: [] })
    expect(validateSharedReach(undefined, undefined)).toEqual({ includeSharedProjects: false, projectAllowlist: [] })
  })
  test.each([
    ['a non-boolean opt-in', 'yes', []],
    ['a non-list allowlist', true, 'P-1'],
    ['a non-id entry', true, ['P 1; drop']],
    ['too many ids', true, Array.from({ length: 101 }, (_, i) => `P-${i}`)],
  ])('%s is refused', (_what, include, list) => {
    expect(validateSharedReach(include, list)).toHaveProperty('error')
  })
})
