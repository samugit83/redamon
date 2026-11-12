/**
 * The owner checks that lived inline in routes and libraries, and the "my projects" lists, ask the
 * policy (lib/authz) instead of comparing ids themselves, so the next change to the policy (shares,
 * permission sets) reaches them:
 *
 * - a triage run starts only on a project `projectAccess()` lets the actor see at the owner's level
 *   (an internal start, which no route permission backs);
 * - a mute-rule preset and an MCP token are their owner's rows (`ownsRow()`);
 * - the project list, the reports and the running scans of the jobs view list the projects
 *   `visibleProjectsWhere()` names, and the jobs view counts the others' scans as its complement.
 *
 * Each test turns the policy's answer against the stored row; the code must follow the policy.
 * What each answers in the ordinary case is pinned by its own test files, unchanged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  eff: { userId: 'alice' } as { userId: string } | null,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async (orig) => ({
  ...(await orig<typeof import('@/lib/access')>()),
  requireEffectiveUser: vi.fn(async () => h.eff),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn(async () => new Response('{"scans":[]}', { status: 200 })) }))
vi.mock('./projectAccess', async (orig) => {
  const actual = await orig<typeof import('./projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})
vi.mock('./rowOwner', async (orig) => {
  const actual = await orig<typeof import('./rowOwner')>()
  return { ...actual, ownsRow: vi.fn(actual.ownsRow) }
})
vi.mock('./visibleProjects', async (orig) => {
  const actual = await orig<typeof import('./visibleProjects')>()
  return { ...actual, visibleProjectsWhere: vi.fn(actual.visibleProjectsWhere) }
})

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { projectAccess, type ProjectAccess } from './projectAccess'
import { ownsRow } from './rowOwner'
import { visibleProjectsWhere } from './visibleProjects'
import { refuseTriageStart } from '@/lib/triageRun'
import { GET as readMutePreset } from '@/app/api/mute-rule-presets/[id]/route'
import { GET as listProjects } from '@/app/api/projects/route'
import { GET as listReports } from '@/app/api/reports/route'
import { GET as jobsView } from '@/app/api/system/jobs/route'

let db: FakePrisma

/** What projectAccess() answers when the policy lets `userId` see the project at `level`. */
function access(projectId: string, ownerId: string, level: string): ProjectAccess {
  return { project: { id: projectId, userId: ownerId }, level } as unknown as ProjectAccess
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.eff = { userId: 'alice' }
  db.seed('project', [
    { id: 'p-alice', userId: 'alice', name: 'A', createdAt: new Date(1) },
    { id: 'p-bob', userId: 'bob', name: 'B', createdAt: new Date(2) },
  ])
  vi.mocked(projectAccess).mockClear()
  vi.mocked(ownsRow).mockClear()
  vi.mocked(visibleProjectsWhere).mockClear()
})

describe('a triage run starts on a project the policy lets the actor see, at the owner level', () => {
  beforeEach(() => {
    h.db = { ...h.db, triageRun: { findMany: async () => [] } }
  })

  test('the owner starts; anyone else and a missing project are one "Not found"', async () => {
    expect(await refuseTriageStart('p-alice', 'alice')).toBeNull()
    expect(await refuseTriageStart('p-bob', 'alice')).toEqual({ reason: 'Not found' })
    expect(await refuseTriageStart('missing', 'alice')).toEqual({ reason: 'Not found' })
    expect(projectAccess).toHaveBeenCalledWith({ userId: 'alice' }, 'p-bob')
  })

  test('the policy decides, not the stored owner', async () => {
    vi.mocked(projectAccess).mockResolvedValueOnce(null)
    expect(await refuseTriageStart('p-alice', 'alice')).toEqual({ reason: 'Not found' })
    vi.mocked(projectAccess).mockResolvedValueOnce(access('p-bob', 'bob', 'owner'))
    expect(await refuseTriageStart('p-bob', 'alice')).toBeNull()
  })

  test('an access below the owner level does not start one', async () => {
    vi.mocked(projectAccess).mockResolvedValueOnce(access('p-bob', 'bob', 'read'))
    expect(await refuseTriageStart('p-bob', 'alice')).toEqual({ reason: 'Not found' })
  })
})

describe('a mute-rule preset is its owner\'s row (ownsRow)', () => {
  const params = { params: Promise.resolve({ id: 'mp-1' }) }
  const req = () => new NextRequest('http://redamon.test/api/mute-rule-presets/mp-1')

  beforeEach(() => {
    const row = { id: 'mp-1', userId: 'alice', name: 'mine', rules: { version: 1, rules: [] }, createdAt: new Date(0), updatedAt: new Date(0) }
    h.db = { ...h.db, userMuteRulesPreset: { findUnique: async ({ where }: { where: { id: string } }) => (where.id === row.id ? row : null) } }
  })

  test('the owner reads it, anyone else gets 404', async () => {
    expect((await readMutePreset(req(), params)).status).toBe(200)
    h.eff = { userId: 'bob' }
    expect((await readMutePreset(req(), params)).status).toBe(404)
    expect(ownsRow).toHaveBeenCalledWith({ userId: 'bob' }, 'alice')
  })

  test('the row check decides', async () => {
    vi.mocked(ownsRow).mockReturnValueOnce(false)
    expect((await readMutePreset(req(), params)).status).toBe(404)
  })
})

describe('the "my projects" lists go by visibleProjectsWhere', () => {
  const SEEN = { id: { in: ['p-bob'] } }

  test('the project list', async () => {
    vi.mocked(visibleProjectsWhere).mockReturnValueOnce(SEEN)
    const rows = await (await listProjects()).json() as Array<{ id: string }>
    expect(rows.map((r) => r.id)).toEqual(['p-bob'])
    expect(visibleProjectsWhere).toHaveBeenCalledWith({ userId: 'alice' })
  })

  test('the reports, by their project', async () => {
    const findMany = vi.fn(async () => [])
    h.db = { ...h.db, report: { findMany } }
    vi.mocked(visibleProjectsWhere).mockReturnValueOnce(SEEN)
    expect((await listReports(new NextRequest('http://x/api/reports'))).status).toBe(200)
    expect(findMany).toHaveBeenCalledWith(expect.objectContaining({ where: { project: SEEN } }))
  })

  test('the jobs view: the running scans and the projects named as mine; the others\' scans are the complement', async () => {
    const scanFind = vi.fn(async () => [])
    const scanCount = vi.fn(async () => 0)
    const projectFind = vi.fn(async () => [])
    h.db = {
      ...h.db,
      jobQueue: { findMany: vi.fn(async () => []), groupBy: vi.fn(async () => []), count: vi.fn(async () => 0) },
      scanJob: { findMany: scanFind, count: scanCount },
      project: { findMany: projectFind },
    }
    vi.mocked(visibleProjectsWhere).mockReturnValueOnce(SEEN).mockReturnValueOnce(SEEN).mockReturnValueOnce(SEEN)
    expect((await jobsView(new NextRequest('http://redamon.test/api/system/jobs'))).status).toBe(200)
    expect(visibleProjectsWhere).toHaveBeenCalledTimes(3)
    expect(scanFind).toHaveBeenCalledWith(expect.objectContaining({ where: { status: 'running', project: SEEN } }))
    expect(scanCount).toHaveBeenCalledWith({ where: { status: 'running', project: { NOT: SEEN } } })
    expect(projectFind).toHaveBeenCalledWith(expect.objectContaining({ where: SEEN }))
  })
})
