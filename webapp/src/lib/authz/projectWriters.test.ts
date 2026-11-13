/**
 * Who is writing a project, and whether a second person may start (step 5.11, SH-40, OQ-35).
 *
 * Until experiment E10 records concurrent writers safe, a start by a second PERSON is refused with
 * 409 `project_writer_busy` naming who holds the project; the same person runs several things at
 * once as before. Sources: the orchestrator's active scans (with their actor), the agent's live
 * sessions (their author), the triage run and the mute-rule apply (their actor). The orchestrator,
 * the agent session reader, Prisma and the sharing policy are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  sharing: true,
  scans: [] as Array<Record<string, unknown>>,
  orchestrator: vi.fn(),
  authors: vi.fn(),
  triage: [] as Array<Record<string, unknown>>,
  applies: [] as Array<Record<string, unknown>>,
  users: new Map<string, { id: string; name: string | null; email: string; role: string }>(),
  root: null as { userId: string } | null,
  projectRead: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectRead(...a) },
    triageRun: { findMany: async () => h.triage, updateMany: async () => ({ count: 0 }) },
    nodeFilterRun: { findMany: async () => h.applies },
    user: {
      findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
        where.id.in.map(id => h.users.get(id)).filter(Boolean),
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestrator(...a) }))
vi.mock('@/lib/agentSessions', () => ({ runningSessionAuthors: (...a: unknown[]) => h.authors(...a) }))
vi.mock('./sharingPolicy', () => ({ sharingInForce: async () => ({ enabled: h.sharing, maxLevel: 'write' }) }))
vi.mock('./root', async (orig) => ({
  ...(await orig<typeof import('./root')>()),
  loadInstanceRoot: async () => h.root,
}))

import {
  otherWritersView, personText, readProjectWriters, secondWriterRefusal, secondWriterResponse,
  SECOND_WRITER_POLICY, WRITER_KIND_PHRASE,
} from './projectWriters'

const OWNER = 'owner-1'
const BOB = 'bob-1'
const CAROL = 'carol-1'
const fresh = () => new Date()

function scan(kind: string, actor: string | null, over: Record<string, unknown> = {}) {
  return { kind, project_id: 'p1', run_id: '', status: 'running', actor_user_id: actor, ...over }
}

beforeEach(() => {
  h.sharing = true
  h.scans = []
  h.triage = []
  h.applies = []
  h.root = null
  h.users = new Map([
    [OWNER, { id: OWNER, name: 'Olivia Owner', email: 'olivia@example.test', role: 'standard' }],
    [BOB, { id: BOB, name: 'Bob Builder', email: 'bob@example.test', role: 'standard' }],
    [CAROL, { id: CAROL, name: null, email: 'carol@example.test', role: 'admin' }],
  ])
  h.orchestrator.mockReset()
  h.orchestrator.mockImplementation(async () => ({ ok: true, status: 200, json: async () => ({ scans: h.scans }) }))
  h.authors.mockReset()
  h.authors.mockResolvedValue({ userIds: [] })
  h.projectRead.mockReset()
  h.projectRead.mockResolvedValue({ userId: OWNER })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('the policy until E10 is recorded', () => {
  test('a second writer is refused, not just noticed', () => {
    expect(SECOND_WRITER_POLICY).toBe('refuse')
  })
})

describe('second writer refused (step 5.11)', () => {
  test("another person's partial recon refuses the start, naming them and what they run", async () => {
    h.scans = [scan('partial_recon', BOB)]
    const refused = await secondWriterRefusal({ projectId: 'p1', personId: OWNER })
    expect(refused).toEqual({
      status: 409,
      code: 'project_writer_busy',
      busy: 'Bob Builder (bob@example.test) is running a partial recon',
      error: 'Bob Builder (bob@example.test) is running a partial recon on this project. One person writes a project at a time: wait for it to finish, or ask them to stop it.',
    })
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] project_writer_busy project=p1 person=owner-1 holder=bob-1 kind=partial_recon/))
  })

  test.each([
    ['full_recon', 'a full recon scan'], ['gvm', 'a GVM vulnerability scan'], ['github_hunt', 'a GitHub Secret Hunt'],
    ['trufflehog', 'a Secret Multiscanner scan'], ['supply_chain', 'a supply-chain scan'],
    ['ai_attack', 'an AI attack-surface scan'], ['some_future_kind', 'a scan'],
  ])('a %s scan of another person refuses: "%s"', async (kind, phrase) => {
    h.scans = [scan(kind, BOB)]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.busy).toBe(`Bob Builder (bob@example.test) is running ${phrase}`)
  })

  test("another person's agent session refuses a scan start (the E10 pair)", async () => {
    h.authors.mockResolvedValue({ userIds: [BOB] })
    const refused = await secondWriterRefusal({ projectId: 'p1', personId: OWNER })
    expect(refused?.busy).toBe('Bob Builder (bob@example.test) is running an agent session')
    expect(h.authors).toHaveBeenCalledWith('p1')
  })

  test("the owner's scan refuses a collaborator's agent ticket (two agent runs, a scan and a run)", async () => {
    h.scans = [scan('full_recon', OWNER)]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: BOB }))?.busy).toBe('Olivia Owner (olivia@example.test) is running a full recon scan')
    h.scans = []
    h.authors.mockResolvedValue({ userIds: [OWNER] })
    expect((await secondWriterRefusal({ projectId: 'p1', personId: BOB }))?.busy).toBe('Olivia Owner (olivia@example.test) is running an agent session')
  })

  test("another person's triage run and mute-rule apply each refuse; a stale apply does not", async () => {
    h.triage = [{ id: 't1', status: 'running', startedAt: fresh(), heartbeatAt: fresh(), actorUserId: BOB }]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.busy).toMatch(/Bob Builder .* is running a triage run$/)
    h.triage = []
    h.applies = [{ actorUserId: BOB, heartbeatAt: fresh() }]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.busy).toMatch(/is running a mute-rule apply$/)
    h.applies = [{ actorUserId: BOB, heartbeatAt: new Date(Date.now() - 60 * 60 * 1000) }]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
  })

  test('a name alone is not an identity: an account without a name is named by its email', async () => {
    h.scans = [scan('gvm', CAROL)]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.busy).toBe('carol@example.test is running a GVM vulnerability scan')
  })

  test('a writer whose account is gone is "a deleted account", and still holds the project', async () => {
    h.scans = [scan('gvm', 'gone-1')]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.busy).toBe('a deleted account is running a GVM vulnerability scan')
  })

  test("a writer whose access ended mid-run still holds the project: shares are not read, the run is", async () => {
    // No share row exists for bob any more (revoked); his scan is still running in the orchestrator.
    h.scans = [scan('partial_recon', BOB)]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.code).toBe('project_writer_busy')
    // Once it stops, the owner starts.
    h.scans = []
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
  })

  test('the 409 as a route answers it', async () => {
    h.scans = [scan('partial_recon', BOB)]
    const res = await secondWriterResponse({ projectId: 'p1', personId: OWNER })
    expect(res?.status).toBe(409)
    expect(await res?.json()).toEqual({
      error: expect.stringContaining('Bob Builder (bob@example.test) is running a partial recon on this project.'),
      code: 'project_writer_busy',
      busy: 'Bob Builder (bob@example.test) is running a partial recon',
    })
  })
})

describe('the same person can run two things as today', () => {
  test('their own scan, agent session, triage run and apply never refuse them', async () => {
    h.scans = [scan('full_recon', BOB), scan('partial_recon', BOB, { run_id: 'r2' })]
    h.authors.mockResolvedValue({ userIds: [BOB] })
    h.triage = [{ id: 't1', status: 'running', startedAt: fresh(), heartbeatAt: fresh(), actorUserId: BOB }]
    h.applies = [{ actorUserId: BOB, heartbeatAt: fresh() }]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: BOB })).toBeNull()
  })

  test("the owner alone on a project: every writer is the owner's, nothing is refused", async () => {
    h.scans = [scan('full_recon', OWNER), scan('gvm', OWNER)]
    h.authors.mockResolvedValue({ userIds: [OWNER] })
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
  })

  test("a scan with no recorded actor (adopted after a restart, started before 5.5) is the owner's", async () => {
    h.scans = [scan('full_recon', null), scan('gvm', '')]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
    expect((await secondWriterRefusal({ projectId: 'p1', personId: BOB }))?.busy).toBe('Olivia Owner (olivia@example.test) is running a full recon scan')
  })

  test('no person given (a schedule from before 5.5) is the owner', async () => {
    h.scans = [scan('full_recon', OWNER)]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: null })).toBeNull()
    h.scans = [scan('full_recon', BOB)]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: null })).not.toBeNull()
  })

  test("other projects' scans and finished ones are not writers of this project", async () => {
    h.scans = [scan('full_recon', BOB, { project_id: 'p2' }), scan('gvm', BOB, { status: 'completed' }), scan('gvm', BOB, { status: 'error' })]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
  })

  test('the owner the caller already read is used; otherwise it is read once, and a missing project refuses nothing', async () => {
    await secondWriterRefusal({ projectId: 'p1', personId: OWNER, ownerId: OWNER })
    expect(h.projectRead).not.toHaveBeenCalled()
    await secondWriterRefusal({ projectId: 'p1', personId: OWNER })
    expect(h.projectRead).toHaveBeenCalledTimes(1)
    h.projectRead.mockResolvedValue(null)
    h.scans = [scan('full_recon', BOB)]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
  })
})

describe('sharing not in force, or the notice policy: nothing read, nothing refused (DV-30)', () => {
  test('sharing off: no orchestrator, agent or database read', async () => {
    h.sharing = false
    h.scans = [scan('full_recon', BOB)]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
    expect(h.orchestrator).not.toHaveBeenCalled()
    expect(h.authors).not.toHaveBeenCalled()
    expect(h.projectRead).not.toHaveBeenCalled()
  })

  test('notice shown with the other writer, start proceeds (the policy after a safe E10)', async () => {
    h.scans = [scan('full_recon', BOB)]
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER }, { policy: 'notice' })).toBeNull()
    expect(h.orchestrator).not.toHaveBeenCalled()
  })
})

describe('a source that cannot be read: the owner goes ahead, anyone else is refused', () => {
  const failures: Array<[string, () => void]> = [
    ['the orchestrator unreachable', () => h.orchestrator.mockRejectedValue(new Error('ECONNREFUSED'))],
    ['the orchestrator answering 500', () => h.orchestrator.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) })],
    ['the orchestrator answering without a list', () => h.orchestrator.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })],
    ['the agent unreachable with a flag set', () => h.authors.mockResolvedValue({ failure: { code: 'agent_unreachable' } })],
    ['the database failing', () => { h.triage = null as unknown as [] }],
  ]

  test.each(failures)('%s: the owner starts, with a log line', async (_name, fail) => {
    fail()
    expect(await secondWriterRefusal({ projectId: 'p1', personId: OWNER })).toBeNull()
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] project_writer_unverified project=p1 person=owner-1: the owner's start goes ahead/))
  })

  test.each(failures)('%s: a collaborator is refused (fail closed)', async (_name, fail) => {
    fail()
    const refused = await secondWriterRefusal({ projectId: 'p1', personId: BOB })
    expect(refused).toMatchObject({ status: 409, code: 'project_writer_busy' })
    expect(refused?.error).toMatch(/^Nothing was started: whether someone else is writing this project could not be verified \((scans|agent|database)\)\. Try again shortly\.$/)
  })

  test('a known other writer is named even when another source failed', async () => {
    h.authors.mockResolvedValue({ failure: { code: 'agent_timeout' } })
    h.scans = [scan('gvm', BOB)]
    expect((await secondWriterRefusal({ projectId: 'p1', personId: OWNER }))?.busy).toMatch(/^Bob Builder/)
  })

  test('the orchestrator is asked with a bounded wait', async () => {
    await readProjectWriters('p1', OWNER)
    expect(h.orchestrator).toHaveBeenCalledWith(expect.stringMatching(/\/system\/active-scans$/), { method: 'GET' }, { timeoutMs: 5000 })
  })
})

describe('the banner view: who else is writing', () => {
  test("lists other people's writers by name, email and type, never the viewer's own, once per person and kind", async () => {
    h.root = { userId: CAROL }
    h.scans = [scan('partial_recon', BOB, { run_id: 'r1' }), scan('partial_recon', BOB, { run_id: 'r2' }), scan('gvm', OWNER), scan('gvm', CAROL)]
    h.authors.mockResolvedValue({ userIds: [OWNER, BOB] })
    const view = await otherWritersView('p1', OWNER, OWNER)
    expect(view).toEqual({
      writers: [
        { kind: 'partial_recon', phrase: 'a partial recon', person: { name: 'Bob Builder', email: 'bob@example.test', accountType: 'member', deleted: false } },
        { kind: 'gvm', phrase: 'a GVM vulnerability scan', person: { name: '', email: 'carol@example.test', accountType: 'root', deleted: false } },
        { kind: 'agent', phrase: 'an agent session', person: { name: 'Bob Builder', email: 'bob@example.test', accountType: 'member', deleted: false } },
      ],
      unverified: false,
      startsRefused: true,
    })
    expect(JSON.stringify(view)).not.toContain(BOB)
  })

  test('a deleted account and an unverified source', async () => {
    h.scans = [scan('gvm', 'gone-1')]
    h.authors.mockResolvedValue({ failure: { code: 'agent_unreachable' } })
    expect(await otherWritersView('p1', OWNER, OWNER)).toEqual({
      writers: [{ kind: 'gvm', phrase: 'a GVM vulnerability scan', person: { name: '', email: null, accountType: null, deleted: true } }],
      unverified: true,
      startsRefused: true,
    })
  })

  test('nobody else: an empty list', async () => {
    h.scans = [scan('gvm', BOB)]
    expect((await otherWritersView('p1', OWNER, BOB)).writers).toEqual([])
  })
})

describe('personText and the phrases', () => {
  test('every kind has a phrase that completes the sentence', () => {
    for (const phrase of Object.values(WRITER_KIND_PHRASE)) expect(phrase).toMatch(/^an? /)
  })
  test('a person in text', () => {
    expect(personText(undefined)).toBe('a deleted account')
    expect(personText({ name: 'N', email: 'n@x.test', accountType: 'member', deleted: false })).toBe('N (n@x.test)')
    expect(personText({ name: '', email: 'n@x.test', accountType: 'member', deleted: false })).toBe('n@x.test')
  })
})
