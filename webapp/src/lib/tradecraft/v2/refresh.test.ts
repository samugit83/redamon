/**
 * Refresh and Verify on 2.0: a background job, answered at once (R-097).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '../__testing__/tradecraftDb'
import { stubAgent } from '../__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb, actingAs: false }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async () => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }) : null)),
}))

import { setNowForTests } from '@/lib/authz/clock'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { refreshResourceV2 } from './refresh'

const refresh = (ownerId = 'owner') => refreshResourceV2({ ownerId, resourceId: 'r1', actor: { actorUserId: ownerId, realActorUserId: null } })

beforeEach(() => {
  h.db = createTradecraftDb()
  h.actingAs = false
  setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
  h.db.seed('userTradecraftResource', { id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' })
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

describe('refreshResourceV2', () => {
  test('202 with the queued refresh job; a second click while it runs is 409 job_running', async () => {
    stubAgent()
    const res = await refresh()
    expect(res.status).toBe(202)
    const { job } = await res.json()
    expect(job).toMatchObject({ kind: 'refresh', status: 'queued' })
    const again = await refresh()
    expect(again.status).toBe(409)
    expect(await again.json()).toMatchObject({ code: 'job_running', job: { id: job.id } })
  })

  test("another account's resource: 404, no job", async () => {
    const agent = stubAgent()
    expect((await refresh('other')).status).toBe(404)
    expect(agent.calls).toHaveLength(0)
  })

  test('act-as with a GitHub token to send: refused, no job', async () => {
    h.actingAs = true
    h.db.seed('userSettings', { userId: 'owner', githubAccessToken: 'ghp_account_fake' })
    const agent = stubAgent()
    expect((await refresh()).status).toBe(403)
    expect(h.db.rows('tradecraftIngestionJob')).toHaveLength(0)
    expect(agent.calls).toHaveLength(0)
  })

  test('use_refused: acting as the account, a resource with a login is refused as use_site_logins, no job', async () => {
    h.actingAs = true
    Object.assign(h.db.rows('userTradecraftResource', { id: 'r1' })[0], { credentials: { cookie: 'session=fake-session' }, hasLogin: true })
    const agent = stubAgent()
    const res = await refresh()
    expect(res.status).toBe(403)
    expect(vi.mocked(refuseWhileActingAsOn).mock.calls.at(-1)).toEqual(['owner', 'use_site_logins'])
    expect(h.db.rows('tradecraftIngestionJob')).toHaveLength(0)
    expect(agent.calls).toHaveLength(0)
  })

  test('act-as with no token to send: the refresh starts (nothing of the account is used)', async () => {
    h.actingAs = true
    stubAgent()
    expect((await refresh()).status).toBe(202)
  })
})
