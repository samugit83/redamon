/**
 * POST /api/users/[id]/tradecraft-resources/refresh-all (Save & refresh all, §3.2, T6.10; R-026,
 * R-159, D-49): one bulk job per ticked enabled resource with one bulkId, one request to the agent,
 * the skipped ones listed with their reason. The guards are doubles here; the act-as refusal
 * through the real session and tokens is in `lib/tradecraft/actAs.tradecraft.test.ts`.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { stubAgent } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb, denied: null as Response | null, person: 'owner' as string | null,
  actingAs: new Set<string>(), refusedAsked: [] as string[],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: async () => ({ actorId: h.person, onBehalfOfUserId: null }),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async (_id: string, action: string) => {
    h.refusedAsked.push(action)
    return h.actingAs.has(action) ? NextResponse.json({ code: 'not_while_acting_as', action }, { status: 403 }) : null
  }),
}))

import { JobStartBatch } from '@/lib/tradecraft/agentContract'
import { POST } from './route'

const post = (body: unknown, id = 'owner') => POST(new NextRequest(`http://webapp.test/api/users/${id}/tradecraft-resources/refresh-all`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), { params: Promise.resolve({ id }) })
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}
const jobCalls = (agent: ReturnType<typeof stubAgent>) => agent.calls.filter(c => c.path === '/tradecraft/v2/jobs')
const jobs = () => h.db.rows('tradecraftIngestionJob')

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.person = 'owner'
  h.actingAs = new Set()
  h.refusedAsked = []
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
  h.db.seed('userSettings', { userId: 'owner', githubAccessToken: '' })
  const r = (id: string, extra: Record<string, unknown> = {}) => h.db.seed('userTradecraftResource', {
    id, userId: 'owner', name: id.toUpperCase(), slug: id, url: `https://${id}.tc-fixture.test/`, llmModel: 'gpt-4o', ...extra,
  })
  r('a'); r('b'); r('c')
  r('off', { enabled: false })
  r('kb', { credentials: { cookie: 'cookie=fake-session' }, hasLogin: true })
  r('gh', { githubTokenOverride: 'ghp_fake_override_0001' })
  h.db.seed('userTradecraftResource', { id: 'x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.tc-fixture.test/', llmModel: 'm' })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('Save & refresh all', () => {
  test('creates_bulk_jobs: one bulk job per ticked resource, one bulkId, one request to the agent', async () => {
    const agent = stubAgent()
    const r = await answer(await post({ resourceIds: ['a', 'b', 'c'] }))
    expect(r.status).toBe(202)
    expect(r.body.skipped).toEqual([])
    expect(r.body.started.map((s: { resourceId: string; name: string }) => [s.resourceId, s.name])).toEqual([['a', 'A'], ['b', 'B'], ['c', 'C']])
    expect(new Set(jobs().map(j => j.bulkId))).toEqual(new Set([r.body.bulkId]))
    expect(jobs().every(j => j.kind === 'bulk' && j.actorUserId === 'owner')).toBe(true)
    expect(jobCalls(agent)).toHaveLength(1)
    expect(JobStartBatch.parse(jobCalls(agent)[0].body).jobs.map(j => j.resource_id)).toEqual(['a', 'b', 'c'])
  })

  test('untick_excludes and the rest: only the ids sent; a disabled one, another account\'s and an unknown one are skipped with a reason', async () => {
    const agent = stubAgent()
    const r = await answer(await post({ resourceIds: ['a', 'off', 'x', 'nope', 'a'] }))
    expect(r.body.started.map((s: { resourceId: string }) => s.resourceId)).toEqual(['a'])
    expect(r.body.skipped).toEqual([
      { resourceId: 'off', name: 'OFF', reason: 'disabled' },
      { resourceId: 'x', name: '', reason: 'not_found' },
      { resourceId: 'nope', name: '', reason: 'not_found' },
    ])
    expect(jobs().map(j => j.resourceId)).toEqual(['a'])
    expect(jobCalls(agent)).toHaveLength(1)
  })

  test('skips_running: a resource whose job runs is listed as skipped, the others start', async () => {
    const agent = stubAgent()
    expect((await post({ resourceIds: ['b'] })).status).toBe(202)
    const r = await answer(await post({ resourceIds: ['a', 'b'] }))
    expect(r.body.started.map((s: { resourceId: string }) => s.resourceId)).toEqual(['a'])
    expect(r.body.skipped).toEqual([{ resourceId: 'b', name: 'B', reason: 'job_running' }])
    expect(jobCalls(agent)).toHaveLength(2)
  })

  test('skips_logins_act_as: while acting, a resource with a login and one that would send the GitHub token are skipped; one refusal each (R-159)', async () => {
    const agent = stubAgent()
    h.actingAs = new Set(['use_site_logins', 'use_github_token'])
    const r = await answer(await post({ resourceIds: ['a', 'kb', 'gh'] }))
    expect(r.body.started.map((s: { resourceId: string }) => s.resourceId)).toEqual(['a'])
    expect(r.body.skipped).toEqual([
      { resourceId: 'kb', name: 'KB', reason: 'use_site_logins' },
      { resourceId: 'gh', name: 'GH', reason: 'use_github_token' },
    ])
    expect(h.refusedAsked).toEqual(['use_site_logins', 'use_github_token'])
    const sent = JobStartBatch.parse(jobCalls(agent)[0].body)
    expect(sent.jobs.map(j => j.resource_id)).toEqual(['a'])
    expect(JSON.stringify(sent)).not.toContain('fake-session')
    // Not acting: they all start, and the login travels only in that resource's job.
    h.actingAs = new Set()
    h.db = createTradecraftDb()
    h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
    h.db.seed('userTradecraftResource', { id: 'kb', userId: 'owner', name: 'KB', slug: 'kb', url: 'https://kb.tc-fixture.test/', llmModel: 'm', credentials: { cookie: 'cookie=fake-session' }, hasLogin: true })
    const again = await answer(await post({ resourceIds: ['kb'] }))
    expect(again.body.started).toHaveLength(1)
  })

  test('nothing left to start: 202 with every skip and no request', async () => {
    const agent = stubAgent()
    const r = await answer(await post({ resourceIds: ['off'] }))
    expect(r).toMatchObject({ status: 202, body: { started: [], skipped: [{ resourceId: 'off', reason: 'disabled' }] } })
    expect(jobCalls(agent)).toEqual([])
  })

  test.each([
    ['no list', {}],
    ['an empty list', { resourceIds: [] }],
    ['201 ids', { resourceIds: Array.from({ length: 201 }, (_, i) => `r${i}`) }],
    ['a non-text id', { resourceIds: [1] }],
  ])('a malformed body is a 400, nothing written: %s', async (_name, body) => {
    const agent = stubAgent()
    expect((await answer(await post(body))).status).toBe(400)
    expect(jobs()).toEqual([])
    expect(agent.calls).toEqual([])
  })

  test('the guards: refused access, no person, 2.0 off', async () => {
    stubAgent()
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await post({ resourceIds: ['a'] })).status).toBe(403)
    h.denied = null
    h.person = null
    expect((await post({ resourceIds: ['a'] })).status).toBe(401)
    h.person = 'owner'
    h.db.rows('tradecraftUserSettings', { userId: 'owner' })[0].v2Enabled = false
    expect(await answer(await post({ resourceIds: ['a'] }))).toMatchObject({ status: 404, body: { code: 'tradecraft_v2_off' } })
    expect(jobs()).toEqual([])
  })
})
