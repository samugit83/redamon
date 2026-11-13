/**
 * The Priority Board's writes over MCP on a shared project (step 4.8, SH-07): a token held by a read
 * collaborator (with or without Raw data & files, or a share stored as `write`) or by an admin who
 * reaches the project by oversight cannot record a verdict, submit a review, mute, unmute, or start or
 * stop a triage run there. Each tool asks `assertMcpProjectAccess`, which needs the owner level, before
 * it writes anything; a token's project tools have no route permission whose level could admit less.
 * The owner's token still passes the check.
 *
 * Real assertMcpProjectAccess, projectAccess(), sharing policy reader and capabilities; Prisma
 * (sharedProjectDb), the triage writes and the agent are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  reached: [] as string[],
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/triage/actions', async (orig) => ({
  ...(await orig<typeof import('@/lib/triage/actions')>()),
  recordVerdict: async () => { h.reached.push('recordVerdict'); return { label: 'Vulnerability', rescored: true, before: null, after: null, row: null } },
  submitReview: async () => { h.reached.push('submitReview'); return { accepted: true, dropped: [], rescored: true, before: null, after: null, reviewSurvivesRescan: true } },
  startRun: async () => { h.reached.push('startRun'); return { runId: 'run-1' } },
  stopRun: async () => { h.reached.push('stopRun'); return { stopped: true } },
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: async () => { h.reached.push('agent'); return new Response(JSON.stringify({ error: 'not doubled' }), { status: 500 }) },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => undefined }))

import { McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import {
  COLLABORATOR, OVERSEER, OWNER, SHARED_PROJECT, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'
import { setFindingVerdict } from './verdictTools'
import { startTriageRun, stopTriageRun, submitFindingReview } from './triageTools'
import { muteFindings, unmuteFindings } from './muteTools'
import type { McpContext } from './tools'

const ALL_TRIAGE_SCOPES = ['triage:read', 'triage:write', 'triage:review', 'triage:mute', 'triage:run']
const ctxOf = (userId: string): McpContext => ({
  token: { tokenId: `tok-${userId}`, userId, tokenPrefix: 'rdmn_mcp_0a1b2c3d', name: 'agent', scopes: ALL_TRIAGE_SCOPES as never },
})

const TOOLS: Array<{ tool: string; call: (ctx: McpContext) => Promise<unknown> }> = [
  { tool: 'set_finding_verdict', call: ctx => setFindingVerdict(ctx, SHARED_PROJECT, 'f-1', 'confirmed', 'checked by hand') },
  { tool: 'submit_finding_review', call: ctx => submitFindingReview(ctx, SHARED_PROJECT, 'f-1', { evidenceHash: 'h', verdict: 'doubtful' }) },
  { tool: 'mute_findings', call: ctx => muteFindings(ctx, SHARED_PROJECT, { findingIds: ['f-1'], reason: 'noise on a test host' }) },
  { tool: 'unmute_findings', call: ctx => unmuteFindings(ctx, SHARED_PROJECT, { findingIds: ['f-1'] }) },
  { tool: 'start_triage_run', call: ctx => startTriageRun(ctx, SHARED_PROJECT) },
  { tool: 'stop_triage_run', call: ctx => stopTriageRun(ctx, SHARED_PROJECT) },
]

const HOLDERS: Array<{ name: string; userId: string; arrange: () => void }> = [
  { name: 'a read collaborator', userId: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR) },
  { name: 'a read collaborator with Raw data & files', userId: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR, { rawData: true }) },
  { name: 'a collaborator whose share is stored as write', userId: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR, { access: 'write', rawData: true }) },
  { name: 'an admin by oversight', userId: OVERSEER, arrange: () => {} },
]

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.reached.length = 0
  __resetRateLimiter()
  vi.stubGlobal('fetch', async () => { h.reached.push('agent'); return new Response('{}', { status: 500 }) })
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
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe.each(HOLDERS)('$name\'s token writes nothing on the shared project (step 4.8)', ({ userId, arrange }) => {
  test.each(TOOLS)('$tool: refused as not found before any write', async ({ call }) => {
    arrange()
    await expect(call(ctxOf(userId))).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.reached).toEqual([])
    expect(h.db.writes).toEqual([])
  })
})

describe('the owner\'s token', () => {
  test.each(TOOLS)('$tool: passes the access check on its own project', async ({ call }) => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    const outcome = await call(ctxOf(OWNER)).catch((err: unknown) => err)
    expect(outcome).not.toBeInstanceOf(McpAccessDenied)
  })
})
