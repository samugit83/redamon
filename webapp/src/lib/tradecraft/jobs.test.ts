/**
 * The webapp's side of a Tradecraft 2.0 job: the claim with its start lease, the takeover of a
 * claim no agent renews, the start request, what a failed delivery does to the claim, and the
 * cancel flag. Prisma is the in-memory double (transactions run one at a time, as the row lock
 * makes them); the agent is a `fetch` double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'
import { json, refused, stubAgent, timedOut } from './__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { setNowForTests } from '@/lib/authz/clock'
import { JobStartBatch, SECRET_PLACEHOLDER } from './agentContract'
import { effectiveSettings } from './effectiveSettings'
import { MANUAL_JOB_KINDS, START_LEASE_MS, cancelJob, jobActorOf, jobView, latestJob, startJob, type JobActor } from './jobs'

const T0 = Date.parse('2026-11-16T10:00:00Z')
let t = new Date(T0)
const advance = (ms: number) => { t = new Date(t.getTime() + ms) }
const OWNER: JobActor = { actorUserId: 'owner', realActorUserId: null }

function start(kind: 'add' | 'refresh' | 'reingest' = 'refresh', resourceId = 'r1', actor = OWNER) {
  return startJob({ ownerId: 'owner', resourceId, kind, actor })
}
const resource = () => h.db.rows('userTradecraftResource', { id: 'r1' })[0]
const jobs = () => h.db.rows('tradecraftIngestionJob')
const job = (id: string) => h.db.rows('tradecraftIngestionJob', { id })[0]
const jobCalls = (agent: ReturnType<typeof stubAgent>) => agent.calls.filter(c => c.path === '/tradecraft/v2/jobs')

beforeEach(() => {
  h.db = createTradecraftDb()
  t = new Date(T0)
  setNowForTests(() => t)
  h.db.clock.now = () => t
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o', generation: 3,
  })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('a start claims the resource for one job', () => {
  test('the job row holds a start lease and the next generation; the resource names it; one request to the agent', async () => {
    const agent = stubAgent()
    const out = await start('refresh')
    expect(out).toMatchObject({ kind: 'started', delivery: 'accepted', job: { status: 'queued', kind: 'refresh', errorCode: '' } })
    const [row] = jobs()
    expect(row).toMatchObject({ userId: 'owner', resourceId: 'r1', status: 'queued', targetGeneration: 4 })
    expect((row.leaseUntil as Date).getTime()).toBe(T0 + START_LEASE_MS)
    expect(resource().activeJobId).toBe(row.id)
    expect(jobCalls(agent)).toHaveLength(1)
    const batch = JobStartBatch.parse(jobCalls(agent)[0].body)
    expect(batch.jobs.map(j => [j.job_id, j.kind, j.resource_id, j.user_id])).toEqual([[row.id, 'refresh', 'r1', 'owner']])
  })

  test('records_actor: the person and the administrator acting as them, on the row and in the request (D-08)', async () => {
    const agent = stubAgent()
    await start('refresh', 'r1', { actorUserId: 'owner', realActorUserId: 'admin-1' })
    expect(jobs()[0]).toMatchObject({ actorUserId: 'owner', realActorUserId: 'admin-1' })
    const [req] = JobStartBatch.parse(jobCalls(agent)[0].body).jobs
    expect([req.actor_user_id, req.real_actor_user_id]).toEqual(['owner', 'admin-1'])
  })

  test('second_claim_refused: a second start while the first holds a live lease is job_running, nothing written', async () => {
    const agent = stubAgent()
    const first = await start()
    const second = await start()
    expect(second).toMatchObject({ kind: 'job_running', job: { id: first.kind === 'started' ? first.job.id : '' } })
    expect(jobs()).toHaveLength(1)
    expect(jobCalls(agent)).toHaveLength(1)
  })

  test('concurrent_claim: two starts at once (two Refresh clicks) give one job and one refusal', async () => {
    stubAgent()
    const outs = await Promise.all([start(), start()])
    expect(outs.map(o => o.kind).sort()).toEqual(['job_running', 'started'])
    expect(jobs()).toHaveLength(1)
    expect(resource().activeJobId).toBe(jobs()[0].id)
  })

  test('the claim is taken under the resource row lock, keyed by the account', async () => {
    stubAgent()
    await start()
    expect(h.db.raw[0].sql).toBe('SELECT id FROM user_tradecraft_resources WHERE id = $1 AND user_id = $2 FOR UPDATE')
    expect(h.db.raw[0].values).toEqual(['r1', 'owner'])
  })

  test("another account's resource: not_found, no job, no request", async () => {
    h.db.seed('userTradecraftResource', { id: 'r-other', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/' })
    const agent = stubAgent()
    expect(await start('refresh', 'r-other')).toEqual({ kind: 'not_found' })
    expect(jobs()).toHaveLength(0)
    expect(agent.calls).toHaveLength(0)
  })
})

describe('a claim no agent renews stops blocking (D-42)', () => {
  test.each([
    ['running, lease expired', { status: 'running', leaseUntil: new Date(T0 - 1000) }],
    ['queued, lease expired', { status: 'queued', leaseUntil: new Date(T0 - 1) }],
    ['queued, never leased', { status: 'queued', leaseUntil: null }],
  ])('stale_claim_taken_over (%s): the old job fails agent_lost and the new one claims', async (_name, stale) => {
    h.db.seed('tradecraftIngestionJob', { id: 'j-old', userId: 'owner', resourceId: 'r1', kind: 'refresh', ...stale })
    resource().activeJobId = 'j-old'
    stubAgent()
    const out = await start()
    expect(out.kind).toBe('started')
    expect(job('j-old')).toMatchObject({ status: 'failed', errorCode: 'agent_lost' })
    expect((job('j-old').finishedAt as Date).getTime()).toBe(T0)
    expect(resource().activeJobId).not.toBe('j-old')
  })

  test('the takeover is one transaction: a failure after the claim leaves the old claim and no new job', async () => {
    h.db.seed('tradecraftIngestionJob', { id: 'j-old', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'running', leaseUntil: new Date(T0 - 1000) })
    resource().activeJobId = 'j-old'
    const agent = stubAgent()
    h.db.failNext('tradecraftIngestionJob.updateMany', Object.assign(new Error('deadlock detected'), { code: 'P2034' }))
    await expect(start()).rejects.toThrow('deadlock detected')
    expect(jobs().map(j => [j.id, j.status])).toEqual([['j-old', 'running']])
    expect(resource().activeJobId).toBe('j-old')
    expect(agent.calls).toHaveLength(0)
  })

  test('a claim naming a finished job does not block, and the finished job is left as it ended', async () => {
    h.db.seed('tradecraftIngestionJob', { id: 'j-done', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'succeeded', leaseUntil: new Date(T0 + 30_000) })
    resource().activeJobId = 'j-done'
    stubAgent()
    expect((await start()).kind).toBe('started')
    expect(job('j-done')).toMatchObject({ status: 'succeeded', errorCode: '' })
  })

  test('a running job with a live lease (an agent renews it) keeps its claim', async () => {
    h.db.seed('tradecraftIngestionJob', { id: 'j-live', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'running', leaseUntil: new Date(T0 + 5_000) })
    resource().activeJobId = 'j-live'
    stubAgent()
    expect(await start()).toMatchObject({ kind: 'job_running', job: { id: 'j-live', status: 'running' } })
  })
})

describe('what a failed delivery does to the claim', () => {
  test.each([
    ['connection refused', refused('ECONNREFUSED')],
    ['no such host', refused('ENOTFOUND')],
    ['401', json({ detail: 'Unauthorized' }, 401)],
    ['403', json({ detail: 'Forbidden' }, 403)],
    ['500', json({ detail: 'boom' }, 500)],
    ['503', json({ detail: 'unavailable' }, 503)],
  ])('agent_unreachable_releases_claim (%s): the job fails and the next Refresh starts at once', async (_name, answer) => {
    const agent = stubAgent(() => answer)
    const out = await start()
    expect(out).toMatchObject({ kind: 'agent_unreachable', job: { status: 'failed', errorCode: 'agent_unreachable' } })
    expect(jobs()[0]).toMatchObject({ status: 'failed', errorCode: 'agent_unreachable' })
    expect(resource().activeJobId).toBeNull()
    agent.setAnswer(() => json({ accepted: [], refused: [] }, 202))
    expect((await start()).kind).toBe('started')
  })

  test('timeout_keeps_claim: the agent may have taken the job; the start lease frees the resource if it did not', async () => {
    const agent = stubAgent(() => timedOut())
    const out = await start()
    expect(out).toMatchObject({ kind: 'started', delivery: 'timeout', job: { status: 'queued' } })
    const first = jobs()[0]
    expect(resource().activeJobId).toBe(first.id)
    expect((await start()).kind).toBe('job_running')
    advance(START_LEASE_MS + 1)
    agent.setAnswer((_p, body) => json({ accepted: (body as { jobs: { job_id: string }[] }).jobs.map(j => j.job_id), refused: [] }, 202))
    expect((await start()).kind).toBe('started')
    expect(job(first.id as string)).toMatchObject({ status: 'failed', errorCode: 'agent_lost' })
  })

  test('a job the agent refuses (its queue is full) fails with that code and frees the claim', async () => {
    stubAgent((_p, body) => json({ accepted: [], refused: [{ job_id: (body as { jobs: { job_id: string }[] }).jobs[0].job_id, code: 'queue_full' }] }, 202))
    const out = await start()
    expect(out).toMatchObject({ kind: 'started', delivery: 'refused', job: { status: 'failed', errorCode: 'queue_full' } })
    expect(resource().activeJobId).toBeNull()
  })

  test('an answer the contract does not know keeps the claim: the lease decides', async () => {
    stubAgent(() => json({ queued: true }, 202))
    expect(await start()).toMatchObject({ kind: 'started', delivery: 'unconfirmed' })
    expect(resource().activeJobId).toBe(jobs()[0].id)
  })

  test('a row the contract refuses fails internal_error before any request; the log names no value', async () => {
    resource().name = 'x'.repeat(600)
    const agent = stubAgent()
    expect(await start()).toMatchObject({ kind: 'bad_request', job: { errorCode: 'internal_error' } })
    expect(agent.calls).toHaveLength(0)
    expect(resource().activeJobId).toBeNull()
    const logged = (console.error as unknown as { mock: { calls: unknown[][] } }).mock.calls.flat().join(' ')
    expect(logged).toContain('[tradecraft] job_request_invalid')
    expect(logged).not.toContain('xxxx')
  })
})

describe('the start request', () => {
  test('uses_current_effective_settings: the account values, the resource overrides, and their hash', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', ingestion: { 'crawl.maxPages': 120 } })
    resource().overrides = { 'fetching.requestTimeoutSec': 45 }
    const agent = stubAgent()
    await start()
    const [req] = JobStartBatch.parse(jobCalls(agent)[0].body).jobs
    const expected = effectiveSettings({ user: { ingestion: { 'crawl.maxPages': 120 } }, resource: { 'fetching.requestTimeoutSec': 45 } })
    expect(req.settings['crawl.maxPages']).toBe(120)
    expect(req.settings['fetching.requestTimeoutSec']).toBe(45)
    expect(req.settings_hash).toBe(expected.hash)
    expect(req.settings_snapshot.provenance['crawl.maxPages']).toBe('user')
    expect(req.settings_snapshot.provenance['fetching.requestTimeoutSec']).toBe('resource')
  })

  test.each([
    ['the resource override wins', 'ghp_override_1', 'ghp_account_1', 'ghp_override_1'],
    ["the account's token otherwise", '', 'ghp_account_1', 'ghp_account_1'],
    ['none', '', '', null],
  ])('github_token: %s', async (_name, override, account, expected) => {
    resource().githubTokenOverride = override
    if (account) h.db.seed('userSettings', { id: 'us1', userId: 'owner', githubAccessToken: account })
    const agent = stubAgent()
    await start()
    expect(JobStartBatch.parse(jobCalls(agent)[0].body).jobs[0].secrets.github_token).toBe(expected)
  })

  test('the login travels only for a resource that has one, never as the placeholder', async () => {
    const agent = stubAgent()
    resource().credentials = { cookie: 'session=fake-session' }
    await start()
    expect(JobStartBatch.parse(jobCalls(agent)[0].body).jobs[0].secrets.credentials).toBeNull()
    await cancelJob('owner', 'r1')
    advance(START_LEASE_MS + 1)
    resource().hasLogin = true
    await start()
    const creds = JobStartBatch.parse(jobCalls(agent)[1].body).jobs[0].secrets.credentials
    expect(creds).toEqual({ cookie: 'session=fake-session', headers: [], basic_auth: null })
    expect(JSON.stringify(jobCalls(agent)[1].body)).not.toContain(`"${SECRET_PLACEHOLDER}"`)
  })

  test('the resource as the agent builds it: URL, slug, storage, model, summary', async () => {
    Object.assign(resource(), { storageMode: 'stored', summary: 'old summary', summaryLocked: true })
    const agent = stubAgent()
    await start('reingest')
    const [req] = JobStartBatch.parse(jobCalls(agent)[0].body).jobs
    expect(req.kind).toBe('reingest')
    expect(req.resource).toMatchObject({
      url: 'https://wiki.example.test/', slug: 'wiki', name: 'Wiki', storage_mode: 'stored', model: 'gpt-4o',
      summary: 'old summary', summary_locked: true,
    })
  })
})

describe('only a person starts a job (R-096, AC-31)', () => {
  test('only_manual_triggers: the kinds a click starts here, and no other kind', async () => {
    expect([...MANUAL_JOB_KINDS]).toEqual(['add', 'refresh', 'reingest'])
    await expect(startJob({ ownerId: 'owner', resourceId: 'r1', kind: 'bulk' as never, actor: OWNER })).rejects.toThrow('not started by a person')
  })

  test('no timer anywhere in the webapp starts or schedules a job', () => {
    const dir = __dirname
    const files = ['jobs.ts', ...readdirSync(join(dir, 'v2')).filter(f => !f.endsWith('.test.ts')).map(f => join('v2', f))]
    for (const f of files) {
      expect(readFileSync(join(dir, f), 'utf8'), f).not.toMatch(/\bset(Interval|Timeout)\s*\(|\bcron\b/)
    }
  })
})

describe('the job view', () => {
  const base = { id: 'j', kind: 'refresh', stage: 'detect', progress: {}, errorCode: '', cancelRequested: false, createdAt: new Date(T0), startedAt: null, finishedAt: null }
  test.each([
    ['queued, lease expired', 'queued', new Date(T0 - 1), 'failed', 'agent_lost'],
    ['running, lease expired', 'running', new Date(T0 - 1), 'failed', 'agent_lost'],
    ['running, never leased', 'running', null, 'failed', 'agent_lost'],
    ['running, live lease', 'running', new Date(T0 + 1), 'running', ''],
    ['succeeded, lease long gone', 'succeeded', new Date(T0 - 999_999), 'succeeded', ''],
  ])('lease_expired_reads_failed (%s)', (_name, status, leaseUntil, shown, code) => {
    expect(jobView({ ...base, status, leaseUntil }, new Date(T0))).toMatchObject({ status: shown, errorCode: code })
  })

  test("latestJob: the account's newest job of the resource", async () => {
    h.db.seed('tradecraftIngestionJob', { id: 'j1', userId: 'owner', resourceId: 'r1', kind: 'add', status: 'succeeded', createdAt: new Date(T0 - 10_000) })
    h.db.seed('tradecraftIngestionJob', { id: 'j2', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'failed', errorCode: 'fetch_failed', createdAt: new Date(T0 - 5_000) })
    expect(await latestJob('owner', 'r1')).toMatchObject({ id: 'j2', errorCode: 'fetch_failed' })
    expect(await latestJob('other', 'r1')).toBeNull()
  })

  test('jobActorOf: the person, and the admin behind them under act-as; nobody without a session', () => {
    expect(jobActorOf({ actorId: 'owner', onBehalfOfUserId: null, actorEmail: null })).toEqual({ actorUserId: 'owner', realActorUserId: null })
    expect(jobActorOf({ actorId: 'admin-1', onBehalfOfUserId: 'managed', actorEmail: null })).toEqual({ actorUserId: 'managed', realActorUserId: 'admin-1' })
    expect(jobActorOf({ actorId: null, onBehalfOfUserId: null, actorEmail: null })).toBeNull()
  })
})

describe('cancel is a database flag', () => {
  test('a running job gets the flag, keeps its claim until the agent stops it, and the agent is told', async () => {
    const agent = stubAgent()
    const out = await start()
    const id = out.kind === 'started' ? out.job.id : ''
    const cancelled = await cancelJob('owner', 'r1')
    expect(cancelled).toMatchObject({ found: true, job: { id, cancelRequested: true, status: 'queued' } })
    expect(job(id).cancelRequested).toBe(true)
    expect(resource().activeJobId).toBe(id)
    expect(agent.calls.map(c => c.path)).toContain(`/tradecraft/v2/jobs/${id}/cancel`)
  })

  test('the flag is set even when the agent cannot be told', async () => {
    const agent = stubAgent()
    await start()
    agent.setAnswer(() => refused())
    const cancelled = await cancelJob('owner', 'r1')
    expect(cancelled.job?.cancelRequested).toBe(true)
  })

  test('a job no agent renews ends here as cancelled and frees the claim', async () => {
    h.db.seed('tradecraftIngestionJob', { id: 'j-lost', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'running', leaseUntil: new Date(T0 - 1) })
    resource().activeJobId = 'j-lost'
    const agent = stubAgent()
    expect(await cancelJob('owner', 'r1')).toMatchObject({ found: true, job: { id: 'j-lost', status: 'cancelled', errorCode: 'cancelled' } })
    expect(resource().activeJobId).toBeNull()
    expect(agent.calls).toHaveLength(0)
  })

  test('nothing running: found, no job; another account: not found', async () => {
    stubAgent()
    expect(await cancelJob('owner', 'r1')).toEqual({ found: true, job: null })
    expect(await cancelJob('other', 'r1')).toEqual({ found: false, job: null })
  })
})
