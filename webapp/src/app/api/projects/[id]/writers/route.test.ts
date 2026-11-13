/**
 * GET /api/projects/[id]/writers (step 5.11, SH-40): who else is writing the project, for the
 * ProjectWriters banner. Each live writer of another person, once per person and kind, named by
 * name, email and account type, never the caller's own and never an account id. graph:read, then
 * the Write level (the owner, a write share); a Read share and an overseer answer 403 naming the
 * level, a stranger 404. With sharing not in force the route does not exist (404, nothing read).
 *
 * Real guard, can() and projectAccess(); the session, Prisma, the orchestrator's active-scan list and
 * the agent's live-session authors are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), shares: new Map(), policy: { enabled: true } as unknown, models: {} as Record<string, unknown>, refused: vi.fn(),
  scans: [] as Array<Record<string, unknown>>,
  authors: [] as string[],
  orchestrator: vi.fn(),
}))
vi.mock('@/lib/session', () => ({ getAuthzIdentity: (...a: unknown[]) => h.identity(...a), mayActAs: async () => false }))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedReads')).sharedReadPrisma(h as never) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestrator(...a) }))
vi.mock('@/lib/agentSessions', () => ({ runningSessionAuthors: async () => ({ userIds: [...h.authors] }) }))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import {
  COLLABORATOR, OVERSEER, OWNER, RAW_COLLABORATOR, SHARED_PROJECT, STRANGER,
  clearCaches, endSharedReads, resetSharedReads, setFlags, signInAs,
} from '@/lib/authz/__testing__/sharedReads'

const PEOPLE: Record<string, { id: string; name: string; email: string; role: string }> = {
  [OWNER]: { id: OWNER, name: 'Alice', email: 'alice@example.test', role: 'standard' },
  [COLLABORATOR]: { id: COLLABORATOR, name: 'Bob', email: 'bob@example.test', role: 'standard' },
}

const get = (projectId = SHARED_PROJECT) =>
  GET(new NextRequest(`http://x/api/projects/${projectId}/writers`), { params: Promise.resolve({ id: projectId }) })

beforeEach(async () => {
  await resetSharedReads(h as never)
  h.scans = []
  h.authors = []
  h.orchestrator.mockReset()
  h.orchestrator.mockImplementation(async () => ({ ok: true, status: 200, json: async () => ({ scans: h.scans }) }))
  h.models.triageRun = { findMany: async () => [], updateMany: async () => ({ count: 0 }) }
  h.models.nodeFilterRun = { findMany: async () => [] }
  h.models.user = {
    findUnique: async () => null,
    findMany: async ({ where }: { where: { id: { in: string[] } } }) => where.id.in.map(id => PEOPLE[id]).filter(Boolean),
  }
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(async () => {
  await endSharedReads()
  vi.restoreAllMocks()
})

describe('the owner reads who else is writing', () => {
  test("a collaborator's scans and session, once per kind, by name, email and type; never the owner's own", async () => {
    signInAs(h as never, OWNER)
    h.scans = [
      { kind: 'partial_recon', project_id: SHARED_PROJECT, run_id: 'r1', status: 'running', actor_user_id: COLLABORATOR },
      { kind: 'partial_recon', project_id: SHARED_PROJECT, run_id: 'r2', status: 'starting', actor_user_id: COLLABORATOR },
      { kind: 'full_recon', project_id: SHARED_PROJECT, status: 'running', actor_user_id: OWNER },
    ]
    h.authors = [COLLABORATOR, OWNER]
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({
      writers: [
        { kind: 'partial_recon', phrase: 'a partial recon', person: { name: 'Bob', email: 'bob@example.test', accountType: 'member', deleted: false } },
        { kind: 'agent', phrase: 'an agent session', person: { name: 'Bob', email: 'bob@example.test', accountType: 'member', deleted: false } },
      ],
      unverified: false,
      startsRefused: true,
    })
    expect(JSON.stringify(body)).not.toContain(`"${COLLABORATOR}"`)
  })

  test('nobody else: an empty list', async () => {
    signInAs(h as never, OWNER)
    h.scans = [{ kind: 'gvm', project_id: SHARED_PROJECT, status: 'running', actor_user_id: OWNER }]
    expect(await (await get()).json()).toEqual({ writers: [], unverified: false, startsRefused: true })
  })

  test('the orchestrator down: what could be read, flagged unverified', async () => {
    signInAs(h as never, OWNER)
    h.orchestrator.mockRejectedValue(new Error('ECONNREFUSED'))
    h.authors = [COLLABORATOR]
    const body = await (await get()).json()
    expect(body.unverified).toBe(true)
    expect(body.writers.map((w: { kind: string }) => w.kind)).toEqual(['agent'])
  })
})

describe('who may read it', () => {
  test.each([[COLLABORATOR], [RAW_COLLABORATOR], [OVERSEER]])('%s (read level): 403 naming the Write level, nothing asked', async (who) => {
    signInAs(h as never, who)
    const res = await get()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'graph:read', level: 'W' })
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test('a stranger: 404, as a missing project', async () => {
    signInAs(h as never, STRANGER)
    expect((await get()).status).toBe(404)
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test("a write share reads the others' writers, never its own", async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    await clearCaches()
    h.policy = { enabled: true, maxLevel: 'write' }
    h.shares.set(`${SHARED_PROJECT}|${COLLABORATOR}`, {
      access: 'write', rawData: true, runScans: false, useAgent: false, exploit: false, manage: false, expiresAt: null, user: { status: 'active' },
    })
    signInAs(h as never, COLLABORATOR)
    h.scans = [{ kind: 'gvm', project_id: SHARED_PROJECT, status: 'running', actor_user_id: COLLABORATOR }]
    h.authors = [OWNER]
    const res = await get()
    expect(res.status).toBe(200)
    expect((await res.json()).writers).toEqual([
      { kind: 'agent', phrase: 'an agent session', person: { name: 'Alice', email: 'alice@example.test', accountType: 'member', deleted: false } },
    ])
  })
})

describe('sharing not in force: the route does not exist (DV-30)', () => {
  test('the switch off: 404 for the owner, nothing read', async () => {
    await setFlags({ identity: true, permissions: true, sharing: false })
    signInAs(h as never, OWNER)
    const res = await get()
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Not found' })
    expect(h.identity).not.toHaveBeenCalled()
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test("Root's policy disabled: 404", async () => {
    h.policy = { enabled: false }
    await clearCaches()
    signInAs(h as never, OWNER)
    expect((await get()).status).toBe(404)
    expect(h.orchestrator).not.toHaveBeenCalled()
  })
})
