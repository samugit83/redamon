/**
 * The account-status operations below the routes (step 2.3): the paths the routes do not
 * open yet (Root's admin targets, step 2.6) and the races the routes cannot stage.
 *
 * - Disabling runs in the last-admin guard: even on Root's path the last admin with a
 *   password is never disabled (409 last_admin), and a disabled admin no longer counts.
 * - A row that moved between the read and the conditional write answers 409
 *   account_changed and leaves nothing half-written.
 * - The agent calls never throw.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('./__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from './__testing__/accountDb'
import { disableAccount, enableAccount, revokeSessions } from './accountStatus'
import { agentWorkOf, onAccessReduced } from './revocation'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const req = () => new NextRequest('http://redamon.test/api/x', { method: 'POST' })
// What step 2.6 hands in for Root; the session object of a real request comes from getSession.
const ROOT = { userId: 'root-1', role: 'admin' }

beforeEach(() => {
  db().reset()
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the last admin with a password (Root\'s path, step 2.6)', () => {
  test('disable the last admin with a password → 409 last_admin, nothing changed', async () => {
    db().seedUsers([{ id: 'root-1', role: 'admin', password: '' }, { id: 'admin-2', role: 'admin' }])
    const res = await disableAccount(req(), ROOT, 'admin-2', { adminTarget: true })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('last_admin')
    expect(db().account('admin-2')).toMatchObject({ status: 'active', sessionVersion: 0, passwordOnHold: '' })
    expect(db().audit()).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('another admin with a password remains: the admin is disabled', async () => {
    db().seedUsers([{ id: 'root-1', role: 'admin' }, { id: 'admin-2', role: 'admin' }])
    const res = await disableAccount(req(), ROOT, 'admin-2', { adminTarget: true })
    expect(res.status).toBe(200)
    expect(db().account('admin-2')).toMatchObject({ status: 'disabled', password: '' })
  })

  test('a disabled admin no longer counts: the one left cannot be disabled', async () => {
    db().seedUsers([{ id: 'root-1', role: 'admin', password: '' }, { id: 'admin-2', role: 'admin' }, { id: 'admin-3', role: 'admin' }])
    expect((await disableAccount(req(), ROOT, 'admin-2', { adminTarget: true })).status).toBe(200)
    expect((await disableAccount(req(), ROOT, 'admin-3', { adminTarget: true })).status).toBe(409)
    expect(db().account('admin-3')!.status).toBe('active')
  })

  test('two admins disabled at once: one stays', async () => {
    db().seedUsers([{ id: 'root-1', role: 'admin', password: '' }, { id: 'admin-2', role: 'admin' }, { id: 'admin-3', role: 'admin' }])
    const answers = await Promise.all([
      disableAccount(req(), ROOT, 'admin-2', { adminTarget: true }),
      disableAccount(req(), ROOT, 'admin-3', { adminTarget: true }),
    ])
    expect(answers.map((r) => r.status).sort()).toEqual([200, 409])
    expect([db().account('admin-2')!.status, db().account('admin-3')!.status].sort()).toEqual(['active', 'disabled'])
  })

  test('enable and revoke take an admin target on Root\'s path only', async () => {
    db().seedUsers([
      { id: 'root-1', role: 'admin' },
      { id: 'admin-2', role: 'admin', status: 'disabled', password: '', passwordOnHold: '$2a$12$held' },
    ])
    expect((await enableAccount(req(), ROOT, 'admin-2')).status).toBe(403)
    expect((await enableAccount(req(), ROOT, 'admin-2', { adminTarget: true })).status).toBe(200)
    expect((await revokeSessions(req(), ROOT, 'admin-2')).status).toBe(403)
    expect((await revokeSessions(req(), ROOT, 'admin-2', { adminTarget: true })).status).toBe(200)
    expect(db().account('admin-2')).toMatchObject({ status: 'active', password: '$2a$12$held', sessionVersion: 1 })
  })
})

describe('a row that moved under the write', () => {
  test('the writes are conditional on what was read: the status and the exact password', async () => {
    db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'member-1', password: '$2a$12$current' }])
    const write = vi.spyOn(db().user, 'updateMany')
    const admin = { userId: 'admin-1', role: 'admin' }
    await disableAccount(req(), admin, 'member-1')
    expect(write.mock.calls[0][0].where).toEqual({ id: 'member-1', status: 'active', password: '$2a$12$current' })
    await enableAccount(req(), admin, 'member-1')
    expect(write.mock.calls[1][0].where).toEqual({
      id: 'member-1', status: 'disabled', password: '', passwordOnHold: '$2a$12$current',
    })
  })

  test('disable: 409 account_changed, nothing half-written', async () => {
    db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'member-1' }])
    db().seedToken({ id: 'tok-1', userId: 'member-1' })
    vi.spyOn(db().user, 'updateMany').mockResolvedValueOnce({ count: 0 })
    const res = await disableAccount(req(), { userId: 'admin-1', role: 'admin' }, 'member-1')
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('account_changed')
    expect(db().tokens()[0].revokedAt).toBeNull()
    expect(db().audit()).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('enable: 409 account_changed, still disabled', async () => {
    db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'member-1', status: 'disabled', password: '', passwordOnHold: '$2a$12$held' }])
    vi.spyOn(db().user, 'updateMany').mockResolvedValueOnce({ count: 0 })
    const res = await enableAccount(req(), { userId: 'admin-1', role: 'admin' }, 'member-1')
    expect(res.status).toBe(409)
    expect(db().account('member-1')).toMatchObject({ status: 'disabled', passwordOnHold: '$2a$12$held' })
    expect(db().audit()).toEqual([])
  })

  test('a disable and an enable at once leave a consistent account', async () => {
    db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'member-1', status: 'disabled', password: '', passwordOnHold: '$2a$12$held' }])
    const admin = { userId: 'admin-1', role: 'admin' }
    await Promise.all([enableAccount(req(), admin, 'member-1'), disableAccount(req(), admin, 'member-1')])
    const row = db().account('member-1')!
    if (row.status === 'active') expect(row).toMatchObject({ password: '$2a$12$held', passwordOnHold: '' })
    else expect(row).toMatchObject({ status: 'disabled', password: '', passwordOnHold: '$2a$12$held' })
  })
})

// The agent work a disable ends goes through step 5.9's onAccessReduced (`account_disabled`).
describe('ending the agent work never throws', () => {
  test('an answer that is not JSON reads as nothing closed', async () => {
    fetchMock.mockImplementation(async () => new Response('not json', { status: 200 }))
    expect(agentWorkOf(await onAccessReduced(null, 'member-1', 'account_disabled'))).toEqual({ runs: { stopped: 0 }, sockets: { closed: 0 } })
  })

  test('a timeout is reported, never raised', async () => {
    fetchMock.mockImplementation(async () => { throw Object.assign(new Error('timed out'), { name: 'TimeoutError' }) })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(agentWorkOf(await onAccessReduced(null, 'member-1', 'account_disabled'))).toEqual({
      runs: { error: 'agent_unreachable' }, sockets: { error: 'agent_unreachable' },
    })
    // Each failed call: the helper's own line and the revocation step's.
    expect(err.mock.calls.map((c) => String(c[0]).split(':')[0])).toEqual([
      '[rbac] agent-stop failed user=member-1',
      '[rbac] revocation step failed step=stop_runs reason=account_disabled user=member-1 project=-',
      '[rbac] socket-close failed user=member-1 project=- kinds=agent,kali-terminal,cypherfix-triage,cypherfix-codefix',
      '[rbac] revocation step failed step=close_sockets reason=account_disabled user=member-1 project=-',
    ])
  })
})
