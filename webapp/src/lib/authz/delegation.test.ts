/**
 * Step 3.6 (PE-04, PE-22 wave A, T1): every owner helper asks the policy instead of comparing
 * owners itself.
 *
 * - The project helpers answer what `projectAccess()` answers and read the project table no
 *   more themselves: `guardProject`, `requireProjectAccess`, `requireProjectScopedResource`
 *   (access.ts), `requireProjectOwner` (triageClient.ts), `assertMcpProjectAccess` (mcpAuth.ts),
 *   the project scope of `ownsScope` (plugins/changeSetAccess.ts), the project of `strictContext`
 *   (plugins/actions.ts) and of the Gateway's tenancy check (plugins/gateway.ts).
 * - The helpers of a per-user row answer what `ownsRow()` answers: `assertOwner`,
 *   `assertOwnerStrict`, `ownerScope` (`rowOwnerFilter`), the user scope of `ownsScope`, the
 *   session of `strictContext` and of the Gateway (whose project is checked apart). They never
 *   ask `projectAccess()`: the row names its owner, not a project.
 * - The conversation helpers need both: the author (`ownsRow`) and `projectAccess()` on the
 *   conversation's project, so an author who can no longer see the project loses its
 *   conversations, and the project alone never opens another author's.
 *
 * Each test turns the policy's answer against the stored row; the helper must follow the policy.
 * The answers themselves (404, 403, 400, the returned shapes) are pinned by each helper's own
 * test file, which this step leaves unchanged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  eff: null as null | { userId: string },
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getEffectiveUser: vi.fn(async () => h.eff),
}))
vi.mock('./projectAccess', async (orig) => {
  const actual = await orig<typeof import('./projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})
vi.mock('./rowOwner', async (orig) => {
  const actual = await orig<typeof import('./rowOwner')>()
  return { ...actual, ownsRow: vi.fn(actual.ownsRow), rowOwnerFilter: vi.fn(actual.rowOwnerFilter) }
})

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import {
  ALICE,
  ALICE_CONV,
  ALICE_PROJECT,
  ALICE_SESSION,
  BOB,
  BOB_PROJECT,
  BOB_SESSION,
  CALL_SECRET,
  answer,
  gatewayRequest,
  seedWorld,
  token,
} from '@/lib/plugins/__testing__/gatewayHarness'
import { projectAccess, type ProjectAccess } from './projectAccess'
import { ownsRow, rowOwnerFilter } from './rowOwner'
import {
  assertOwner,
  assertOwnerStrict,
  guardProject,
  ownerScope,
  requireConversationAccess,
  requireConversationAccessBySession,
  requireProjectAccess,
  requireProjectScopedResource,
} from '@/lib/access'
import { requireProjectOwner } from '@/lib/triageClient'
import { McpAccessDenied, assertMcpProjectAccess } from '@/lib/mcpAuth'
import { ownsScope } from '@/lib/plugins/changeSetAccess'
import { strictContext } from '@/lib/plugins/actions'
import { withGateway } from '@/lib/plugins/gateway'

let db: FakePrisma
let projectReads: ReturnType<typeof vi.spyOn>

const policy = vi.mocked(projectAccess)
const rowPolicy = vi.mocked(ownsRow)

/** What projectAccess() answers for a project the caller may reach (the owner's id stays the owner's). */
function granted(id: string, ownerId: string): ProjectAccess {
  return Object.freeze({ project: Object.freeze({ id, userId: ownerId }), level: 'owner' as const, toggles: Object.freeze({ rawData: true }), via: 'owner' as const })
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.eff = { userId: ALICE }
  policy.mockReset()
  rowPolicy.mockReset()
  vi.mocked(rowOwnerFilter).mockClear()
  projectReads = vi.spyOn(db.project, 'findUnique')
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const status = (r: unknown) => (r as NextResponse).status

describe('the project helpers answer what projectAccess() answers', () => {
  test('requireProjectAccess: refused when the policy says no, even on a project the row gives the caller', async () => {
    policy.mockResolvedValueOnce(null)
    const r = await requireProjectAccess({ userId: ALICE }, ALICE_PROJECT)
    expect(status(r)).toBe(404)
    expect(await (r as NextResponse).json()).toEqual({ error: 'Not found' })
    expect(policy).toHaveBeenCalledWith({ userId: ALICE }, ALICE_PROJECT)
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('requireProjectAccess: allowed when the policy says yes, and the project keeps its owner', async () => {
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await requireProjectAccess({ userId: ALICE }, BOB_PROJECT)).toEqual({ project: { id: BOB_PROJECT, userId: BOB } })
    expect(policy).toHaveBeenCalledWith({ userId: ALICE }, BOB_PROJECT)
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('requireProjectAccess: an empty project id stays its own 400, before the policy', async () => {
    expect(status(await requireProjectAccess({ userId: ALICE }, ''))).toBe(400)
    expect(policy).not.toHaveBeenCalled()
  })

  test('guardProject: follows the policy for the effective user', async () => {
    policy.mockResolvedValueOnce(null)
    expect(status(await guardProject(ALICE_PROJECT))).toBe(404)
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await guardProject(BOB_PROJECT)).toBeNull()
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('guardProject: no session is a 401 that asks nothing', async () => {
    h.eff = null
    expect(status(await guardProject(ALICE_PROJECT))).toBe(401)
    expect(policy).not.toHaveBeenCalled()
  })

  test('requireProjectScopedResource: follows the policy on the parent project', async () => {
    policy.mockResolvedValueOnce(null)
    expect(status(await requireProjectScopedResource({ userId: ALICE }, async () => ALICE_PROJECT))).toBe(404)
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await requireProjectScopedResource({ userId: ALICE }, async () => BOB_PROJECT)).toEqual({ ok: true })
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
  })

  test("requireProjectOwner (triage): follows the policy and still returns the owner's id", async () => {
    policy.mockResolvedValueOnce(null)
    const refused = await requireProjectOwner(ALICE_PROJECT)
    expect(status(refused)).toBe(404)
    expect(await (refused as NextResponse).json()).toEqual({ error: 'Not found' })
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await requireProjectOwner(BOB_PROJECT)).toEqual({ userId: BOB, projectId: BOB_PROJECT })
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('requireProjectOwner (triage): the 400 and the 401 come first and ask nothing', async () => {
    expect(status(await requireProjectOwner(''))).toBe(400)
    h.eff = null
    expect(status(await requireProjectOwner(ALICE_PROJECT))).toBe(401)
    expect(policy).not.toHaveBeenCalled()
  })

  test("assertMcpProjectAccess: follows the policy for the token's user; still a flat McpAccessDenied", async () => {
    policy.mockResolvedValueOnce(null)
    await expect(assertMcpProjectAccess(ALICE, ALICE_PROJECT)).rejects.toThrow(new McpAccessDenied())
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await assertMcpProjectAccess(ALICE, BOB_PROJECT)).toEqual({ id: BOB_PROJECT, userId: BOB })
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('assertMcpProjectAccess: a missing project id is refused before the policy', async () => {
    await expect(assertMcpProjectAccess(ALICE, '')).rejects.toThrow('projectId is required')
    await expect(assertMcpProjectAccess(ALICE, 42)).rejects.toThrow('projectId is required')
    expect(policy).not.toHaveBeenCalled()
  })

  test('ownsScope (plugin change sets): a project scope follows the policy', async () => {
    policy.mockResolvedValueOnce(null)
    expect(await ownsScope({ type: 'project', id: ALICE_PROJECT }, ALICE)).toBe(false)
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await ownsScope({ type: 'project', id: BOB_PROJECT }, ALICE)).toBe(true)
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('strictContext (plugin actions): the project follows the policy', async () => {
    policy.mockResolvedValueOnce(null)
    const refused = await strictContext({ projectId: ALICE_PROJECT }, ALICE)
    expect(status(refused)).toBe(404)
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await strictContext({ projectId: BOB_PROJECT }, ALICE)).toEqual({ projectId: BOB_PROJECT, sessionId: null, conversationId: null })
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
    expect(projectReads).not.toHaveBeenCalled()
  })

  test("the Gateway's tenancy: the project a call token names follows the policy for the token's user", async () => {
    const handler = vi.fn(async () => ({ ok: true }))
    policy.mockResolvedValueOnce(null)
    const own = await answer(await withGateway(gatewayRequest('x', {}, { token: await token({ ses: undefined, conv: undefined }) }), { op: 'x' }, handler))
    expect(own.status).toBe(404)
    expect(handler).not.toHaveBeenCalled()
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    const other = await answer(await withGateway(gatewayRequest('x', {}, { token: await token({ prj: BOB_PROJECT, ses: undefined, conv: undefined }) }), { op: 'x' }, handler))
    expect(other.status).toBe(200)
    expect(handler).toHaveBeenCalledTimes(1)
    expect(policy.mock.calls).toEqual([[{ userId: ALICE }, ALICE_PROJECT], [{ userId: ALICE }, BOB_PROJECT]])
    expect(projectReads).not.toHaveBeenCalled()
  })
})

describe('the MCP and plugin helpers, which no route permission backs, need the owner level', () => {
  // What Phase 4 adds: projectAccess() answering a share's level. These helpers stay the
  // owner's until their own steps set the level (Phase 4 MCP opt-in, Phase 5 plugin actions).
  const shared = Object.freeze({ project: Object.freeze({ id: BOB_PROJECT, userId: BOB }), level: 'read' }) as unknown as ProjectAccess

  test('assertMcpProjectAccess: a project reached below the owner level is a flat McpAccessDenied', async () => {
    policy.mockResolvedValueOnce(shared)
    await expect(assertMcpProjectAccess(ALICE, BOB_PROJECT)).rejects.toThrow(new McpAccessDenied())
  })

  test('ownsScope: a project scope reached below the owner level is not owned', async () => {
    policy.mockResolvedValueOnce(shared)
    expect(await ownsScope({ type: 'project', id: BOB_PROJECT }, ALICE)).toBe(false)
  })

  test('strictContext: a project reached below the owner level is a 404', async () => {
    policy.mockResolvedValueOnce(shared)
    expect(status(await strictContext({ projectId: BOB_PROJECT }, ALICE))).toBe(404)
  })

  test("the Gateway's tenancy: a project reached below the owner level is a 404, the handler not run", async () => {
    const handler = vi.fn(async () => ({ ok: true }))
    policy.mockResolvedValueOnce(shared)
    const r = await answer(await withGateway(gatewayRequest('x', {}, { token: await token({ prj: BOB_PROJECT, ses: undefined, conv: undefined }) }), { op: 'x' }, handler))
    expect(r.status).toBe(404)
    expect(handler).not.toHaveBeenCalled()
  })
})

// Step 4.3: the answers projectAccess() now gives below the owner, as it builds them. Each of these
// helpers asks meetsLevel(access, 'O'), which no share, break-glass or oversight reaches, so they
// stay the owner's (4.10 opens MCP to shares by its own opt-in; plugin actions stay the owner's).
describe.each([
  ['a read share', 'share', false],
  ['a share with Raw data & files', 'share', true],
  ['a break-glass read', 'break_glass', true],
  ['oversight', 'oversight', false],
])('the owner-only helpers refuse %s (step 4.3)', (_what, via, rawData) => {
  const below = (): ProjectAccess => Object.freeze({
    project: Object.freeze({ id: BOB_PROJECT, userId: BOB }), level: 'read', toggles: Object.freeze({ rawData }), via,
  }) as ProjectAccess

  test('assertMcpProjectAccess: McpAccessDenied', async () => {
    policy.mockResolvedValueOnce(below())
    await expect(assertMcpProjectAccess(ALICE, BOB_PROJECT)).rejects.toThrow(new McpAccessDenied())
  })

  test('ownsScope: not owned', async () => {
    policy.mockResolvedValueOnce(below())
    expect(await ownsScope({ type: 'project', id: BOB_PROJECT }, ALICE)).toBe(false)
  })

  test('strictContext: 404', async () => {
    policy.mockResolvedValueOnce(below())
    expect(status(await strictContext({ projectId: BOB_PROJECT }, ALICE))).toBe(404)
  })

  test("the Gateway's tenancy: 404, the handler not run", async () => {
    const handler = vi.fn(async () => ({ ok: true }))
    policy.mockResolvedValueOnce(below())
    const r = await answer(await withGateway(gatewayRequest('x', {}, { token: await token({ prj: BOB_PROJECT, ses: undefined, conv: undefined }) }), { op: 'x' }, handler))
    expect(r.status).toBe(404)
    expect(handler).not.toHaveBeenCalled()
  })
})

describe('the per-user row helpers answer what ownsRow() answers, never projectAccess()', () => {
  test('assertOwner: 404 when the row check says no, null when it says yes', () => {
    rowPolicy.mockReturnValueOnce(false)
    expect(status(assertOwner({ userId: 'u1' }, 'u1'))).toBe(404)
    rowPolicy.mockReturnValueOnce(true)
    expect(assertOwner({ userId: 'u1' }, 'u2')).toBeNull()
    expect(rowPolicy.mock.calls).toEqual([[{ userId: 'u1' }, 'u1'], [{ userId: 'u1' }, 'u2']])
    expect(policy).not.toHaveBeenCalled()
  })

  test('assertOwnerStrict: 403 when the row check says no, null when it says yes', () => {
    rowPolicy.mockReturnValueOnce(false)
    expect(status(assertOwnerStrict({ userId: 'u1' }, 'u1'))).toBe(403)
    rowPolicy.mockReturnValueOnce(true)
    expect(assertOwnerStrict({ userId: 'u1' }, 'u2')).toBeNull()
    expect(rowPolicy.mock.calls).toEqual([[{ userId: 'u1' }, 'u1'], [{ userId: 'u1' }, 'u2']])
  })

  test("ownerScope: the row filter of lib/authz", () => {
    vi.mocked(rowOwnerFilter).mockReturnValueOnce({ userId: 'from-the-policy' })
    expect(ownerScope({ userId: 'u9' })).toEqual({ userId: 'from-the-policy' })
    expect(rowOwnerFilter).toHaveBeenCalledWith({ userId: 'u9' })
  })

  test('ownsScope: a user scope follows the row check', async () => {
    rowPolicy.mockReturnValueOnce(false)
    expect(await ownsScope({ type: 'user', id: ALICE }, ALICE)).toBe(false)
    rowPolicy.mockReturnValueOnce(true)
    expect(await ownsScope({ type: 'user', id: BOB }, ALICE)).toBe(true)
    expect(rowPolicy.mock.calls).toEqual([[{ userId: ALICE }, ALICE], [{ userId: ALICE }, BOB]])
    expect(policy).not.toHaveBeenCalled()
  })

  test("strictContext: the session's conversation follows the row check", async () => {
    rowPolicy.mockReturnValueOnce(false)
    expect(status(await strictContext({ projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }, ALICE))).toBe(404)
    expect(rowPolicy).toHaveBeenCalledWith({ userId: ALICE }, ALICE)
  })

  test("the Gateway's tenancy: the session's conversation follows the row check", async () => {
    const handler = vi.fn(async () => ({ ok: true }))
    rowPolicy.mockReturnValueOnce(false)
    const r = await answer(await withGateway(gatewayRequest('x', {}, { token: await token() }), { op: 'x' }, handler))
    expect(r.status).toBe(404)
    expect(handler).not.toHaveBeenCalled()
    expect(rowPolicy).toHaveBeenCalledWith({ userId: ALICE }, ALICE)
  })
})

// A conversation is its author's, and the author keeps it only while they can still see its
// project: both checks, never the project alone (another member's conversation stays closed).
describe.each([
  ['requireConversationAccess', (id: 'alice' | 'bob') => requireConversationAccess({ userId: ALICE }, id === 'alice' ? ALICE_CONV : 'conv-bob')],
  ['requireConversationAccessBySession', (id: 'alice' | 'bob') => requireConversationAccessBySession({ userId: ALICE }, id === 'alice' ? ALICE_SESSION : BOB_SESSION)],
])("%s: the author (ownsRow) AND projectAccess() on the conversation's project", (_name, check) => {
  test('not the author: 404, and the project is not asked', async () => {
    rowPolicy.mockReturnValueOnce(false)
    expect(status(await check('alice'))).toBe(404)
    expect(rowPolicy).toHaveBeenCalledWith({ userId: ALICE }, ALICE)
    expect(policy).not.toHaveBeenCalled()
  })

  test('the author, but the policy says no on the project: 404', async () => {
    policy.mockResolvedValueOnce(null)
    const r = await check('alice')
    expect(status(r)).toBe(404)
    expect(await (r as NextResponse).json()).toEqual({ error: 'Not found' })
    expect(policy).toHaveBeenCalledWith({ userId: ALICE }, ALICE_PROJECT)
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('both say yes: the conversation, whoever the stored rows name', async () => {
    rowPolicy.mockReturnValueOnce(true)
    policy.mockResolvedValueOnce(granted(BOB_PROJECT, BOB))
    expect(await check('bob')).toEqual({ conversation: { id: 'conv-bob', userId: BOB, projectId: BOB_PROJECT } })
    expect(rowPolicy).toHaveBeenCalledWith({ userId: ALICE }, BOB)
    expect(policy).toHaveBeenCalledWith({ userId: ALICE }, BOB_PROJECT)
    expect(projectReads).not.toHaveBeenCalled()
  })

  test('the project alone opens nothing: the policy says yes, the row check no -> 404', async () => {
    rowPolicy.mockReturnValueOnce(false)
    policy.mockResolvedValue(granted(BOB_PROJECT, BOB))
    expect(status(await check('bob'))).toBe(404)
  })
})
