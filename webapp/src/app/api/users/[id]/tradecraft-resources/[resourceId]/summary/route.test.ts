/**
 * The summary editor's routes (§6.9, R-164): PUT saves the text, its source and the lock at once,
 * no ingestion; POST /summary/regenerate starts a `regenerate_summary` job, unless the summary is
 * locked or written by the person.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { refused, stubAgent } from '@/lib/tradecraft/__testing__/agentDouble'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb, denied: null as Response | null, person: 'owner' as string | null, actingAs: false,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))
vi.mock('@/lib/auditActor', async orig => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  auditActor: async () => ({ actorId: h.person, onBehalfOfUserId: null }),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async () => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }) : null)),
}))

import { setNowForTests } from '@/lib/authz/clock'
import { JobStartBatch } from '@/lib/tradecraft/agentContract'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { requireUserAccess } from '@/lib/session'
import { PUT } from './route'
import { POST as REGENERATE } from './regenerate/route'

const PR = (resourceId = 'r1') => ({ params: Promise.resolve({ id: 'owner', resourceId }) })
const put = (body: unknown, resourceId = 'r1') => PUT(new NextRequest('http://webapp.test/api/users/owner/tradecraft-resources/r1/summary', {
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), PR(resourceId))
const regenerate = (resourceId = 'r1') => REGENERATE(new NextRequest('http://webapp.test/x', { method: 'POST' }), PR(resourceId))
const row = () => h.db.rows('userTradecraftResource', { id: 'r1' })[0]
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.person = 'owner'
  h.actingAs = false
  setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.tc-fixture.test/', llmModel: 'gpt-4o',
    summary: 'Generated text.', summarySource: 'generated', mapVersion: 3,
  })
  h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.tc-fixture.test/' })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

describe('PUT summary', () => {
  test('summary_lock_and_source: text a person writes is "manual"; the lock is saved; no job starts', async () => {
    const agent = stubAgent()
    const r = await answer(await put({ text: 'My own words.', locked: true }))
    expect(r.status).toBe(200)
    expect(row()).toMatchObject({ summary: 'My own words.', summarySource: 'manual', summaryLocked: true })
    expect(r.body.resource).toMatchObject({ summary: 'My own words.', summarySource: 'manual', summaryLocked: true, job: null })
    expect(agent.calls).toEqual([])
    await put({ locked: false })
    expect(row().summaryLocked).toBe(false)
    await put({ source: 'generated' })
    expect(row()).toMatchObject({ summarySource: 'generated', summary: 'My own words.' })
  })

  test('the text holds at most 6,000 characters, is not empty, and is never "generated"', async () => {
    expect((await put({ text: 'x'.repeat(6000) })).status).toBe(200)
    for (const body of [{ text: 'x'.repeat(6001) }, { text: '  ' }, { text: 'mine', source: 'generated' }, { source: 'mine' }, { locked: 'yes' }, { text: 3 }]) {
      expect((await put(body)).status, JSON.stringify(body).slice(0, 40)).toBe(400)
    }
    expect(row().summary).toBe('x'.repeat(6000))
  })

  test('an empty body, an unknown key: 400, nothing written', async () => {
    for (const body of [{}, { summary: 'x' }, { text: 'x', extra: 1 }]) expect((await put(body)).status).toBe(400)
    expect(row().summary).toBe('Generated text.')
  })

  test("another account's resource: 404; 2.0 off: 404 tradecraft_v2_off; no person: 401", async () => {
    expect((await put({ text: 'x' }, 'r-x')).status).toBe(404)
    h.person = null
    expect((await put({ text: 'x' })).status).toBe(401)
    h.person = 'owner'
    h.db.tables.tradecraftUserSettings[0].v2Enabled = false
    expect(await answer(await put({ text: 'x' }))).toMatchObject({ status: 404, body: { code: 'tradecraft_v2_off' } })
    expect(row().summary).toBe('Generated text.')
  })

  test('the account rule (write) and self:tradecraft run first', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await put({ text: 'x' })).status).toBe(403)
    expect(h.db.calls).toEqual([])
    expect(vi.mocked(requireUserAccess).mock.calls.at(-1)![2]).toEqual({ mode: 'write' })
    h.denied = null
    await put({ text: 'x' })
    expect(vi.mocked(requireSelfPermission).mock.calls.at(-1)!.slice(1)).toEqual(['owner', 'self:tradecraft'])
  })
})

describe('POST summary/regenerate', () => {
  test('regenerate_starts_job: a regenerate_summary job, answered at once', async () => {
    const agent = stubAgent()
    const r = await answer(await regenerate())
    expect(r.status).toBe(202)
    expect(r.body.job).toMatchObject({ kind: 'regenerate_summary', status: 'queued' })
    const [req] = JobStartBatch.parse(agent.calls.find(c => c.path === '/tradecraft/v2/jobs')!.body).jobs
    expect([req.kind, req.resource_id, req.actor_user_id]).toEqual(['regenerate_summary', 'r1', 'owner'])
  })

  test('a locked summary or one the person wrote is theirs: 409, no job', async () => {
    const agent = stubAgent()
    row().summaryLocked = true
    expect(await answer(await regenerate())).toMatchObject({ status: 409, body: { code: 'summary_locked' } })
    row().summaryLocked = false
    row().summarySource = 'manual'
    expect(await answer(await regenerate())).toMatchObject({ status: 409, body: { code: 'summary_manual' } })
    expect(agent.calls).toEqual([])
  })

  test('twice: the second answers the running job, one job only', async () => {
    stubAgent()
    expect((await regenerate()).status).toBe(202)
    const second = await answer(await regenerate())
    expect(second.status).toBe(409)
    expect(second.body.code).toBe('job_running')
    expect(h.db.rows('tradecraftIngestionJob')).toHaveLength(1)
  })

  test('the agent down: 503 agent_unreachable, the claim released', async () => {
    stubAgent(() => refused())
    expect(await answer(await regenerate())).toMatchObject({ status: 503, body: { code: 'agent_unreachable' } })
    expect(row().activeJobId).toBeNull()
  })

  test('act-as: the homepage read would send the GitHub token, so it is refused', async () => {
    h.actingAs = true
    row().githubTokenOverride = 'ghp_fake_token'
    const agent = stubAgent()
    expect((await regenerate()).status).toBe(403)
    expect(agent.calls).toEqual([])
  })

  test("another account's resource: 404; 2.0 off: 404", async () => {
    stubAgent()
    expect((await regenerate('r-x')).status).toBe(404)
    h.db.tables.tradecraftUserSettings[0].v2Enabled = false
    expect(await answer(await regenerate())).toMatchObject({ status: 404, body: { code: 'tradecraft_v2_off' } })
  })
})
