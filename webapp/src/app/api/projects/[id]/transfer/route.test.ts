/**
 * The ownership transfer routes (step 5.12; SH-15, DV-15): /api/projects/[id]/transfer (GET, POST),
 * .../accept, .../decline, .../cancel, .../acknowledge and /api/projects/transfers. Each answers 404 with
 * the write switch off before anything is read, checks the session (or the owner's project:transfer,
 * fresh for a change) before the policy, refuses another site's page, takes same-origin JSON, and hands
 * the request to lib/authz/ownershipTransfer.ts (doubled here; ownershipTransfer.test.ts proves it).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  switchedOff: vi.fn(() => false),
  inForce: vi.fn(async (_opts?: { fresh?: boolean }) => true),
  requirePermission: vi.fn(),
  requireEff: vi.fn(),
  identity: vi.fn(),
  offer: vi.fn(async () => NextResponse.json({ offer: 'made' }, { status: 201 })),
  state: vi.fn(async () => NextResponse.json({ role: 'owner' })),
  accept: vi.fn(async () => NextResponse.json({ transferred: true })),
  decline: vi.fn(async () => NextResponse.json({ withdrawn: true, status: 'declined' })),
  cancel: vi.fn(async () => NextResponse.json({ withdrawn: true, status: 'cancelled' })),
  acknowledge: vi.fn(async () => NextResponse.json({ acknowledged: 1 })),
  feed: vi.fn(async () => ({ incoming: [], outgoing: [], cleared: [] })),
}))

vi.mock('@/lib/authz/ownershipTransfer', () => ({
  transfersSwitchedOff: () => h.switchedOff(),
  writeSharingInForce: (opts?: { fresh?: boolean }) => h.inForce(opts),
  offerTransfer: (...a: unknown[]) => h.offer(...(a as [])),
  transferStateFor: (...a: unknown[]) => h.state(...(a as [])),
  acceptTransfer: (...a: unknown[]) => h.accept(...(a as [])),
  declineTransfer: (...a: unknown[]) => h.decline(...(a as [])),
  cancelTransfer: (...a: unknown[]) => h.cancel(...(a as [])),
  acknowledgeCleared: (...a: unknown[]) => h.acknowledge(...(a as [])),
  transfersForAccount: (...a: unknown[]) => h.feed(...(a as [])),
}))
vi.mock('@/lib/authz/guards', () => ({ requirePermission: (...a: unknown[]) => h.requirePermission(...a) }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => h.requireEff() }))
vi.mock('@/lib/session', () => ({ getAuthzIdentity: (...a: unknown[]) => h.identity(...a) }))

import { GET as STATE, POST as OFFER } from './route'
import { POST as ACCEPT } from './accept/route'
import { POST as DECLINE } from './decline/route'
import { POST as CANCEL } from './cancel/route'
import { POST as ACKNOWLEDGE } from './acknowledge/route'
import { GET as FEED } from '../../transfers/route'

const params = { params: Promise.resolve({ id: 'proj-1' }) }
const AUTH = { session: { userId: 'owner' }, effective: { userId: 'owner' }, access: { project: { id: 'proj-1', userId: 'owner' }, level: 'owner' } }
const IDENTITY = { session: { userId: 'collab' }, principal: { id: 'collab' }, actingAs: null }

function post(path: string, body: unknown = {}, headers: Record<string, string> = {}) {
  return new NextRequest(`http://localhost/api/projects/proj-1/transfer${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost', ...headers },
    body: JSON.stringify(body),
  })
}

const WRITES = [
  ['offer', () => OFFER(post('', { toUserId: 'collab', oldOwnerRole: 'leave', stepUpPassword: 'pw' }), params), h.offer],
  ['accept', () => ACCEPT(post('/accept', { stepUpPassword: 'pw' }), params), h.accept],
  ['decline', () => DECLINE(post('/decline'), params), h.decline],
  ['cancel', () => CANCEL(post('/cancel'), params), h.cancel],
  ['acknowledge', () => ACKNOWLEDGE(post('/acknowledge'), params), h.acknowledge],
] as const

beforeEach(() => {
  vi.clearAllMocks()
  h.switchedOff.mockReturnValue(false)
  h.inForce.mockResolvedValue(true)
  h.requirePermission.mockResolvedValue(AUTH)
  h.requireEff.mockResolvedValue({ userId: 'collab' })
  h.identity.mockResolvedValue(IDENTITY)
})

describe('the write switch off (DV-30)', () => {
  test('every route answers 404 before any session, permission or table is read', async () => {
    h.switchedOff.mockReturnValue(true)
    expect((await STATE(new NextRequest('http://localhost/api/projects/proj-1/transfer'), params)).status).toBe(404)
    expect((await FEED(new NextRequest('http://localhost/api/projects/transfers'))).status).toBe(404)
    for (const [, run] of WRITES) expect((await run()).status).toBe(404)
    for (const f of [h.requirePermission, h.requireEff, h.identity, h.inForce, h.offer, h.accept, h.decline, h.cancel, h.acknowledge, h.state, h.feed]) {
      expect(f).not.toHaveBeenCalled()
    }
  })

  test("Root's policy at Read (write sharing not in force): 404 after the session or the guard, nothing done", async () => {
    h.inForce.mockResolvedValue(false)
    expect((await STATE(new NextRequest('http://localhost/api/projects/proj-1/transfer'), params)).status).toBe(404)
    expect((await FEED(new NextRequest('http://localhost/api/projects/transfers'))).status).toBe(404)
    for (const [, run, writer] of WRITES) {
      expect((await run()).status).toBe(404)
      expect(writer).not.toHaveBeenCalled()
    }
    expect(h.state).not.toHaveBeenCalled()
    expect(h.feed).not.toHaveBeenCalled()
  })
})

describe('only the owner offers, cancels and dismisses (project:transfer, level O)', () => {
  test.each([
    ['offer', () => OFFER(post('', { toUserId: 'collab', oldOwnerRole: 'leave' }), params), true],
    ['cancel', () => CANCEL(post('/cancel'), params), true],
    ['acknowledge', () => ACKNOWLEDGE(post('/acknowledge'), params), undefined],
  ] as const)('%s asks project:transfer on the project first', async (_what, run, fresh) => {
    await run()
    expect(h.requirePermission).toHaveBeenCalledWith(expect.anything(), 'project:transfer', { projectId: 'proj-1', ...(fresh ? { fresh: true } : {}) })
    expect(h.requirePermission.mock.invocationCallOrder[0]).toBeLessThan(h.inForce.mock.invocationCallOrder[0])
  })

  test('a collaborator (the guard refuses) offers nothing; a stranger gets the 404', async () => {
    h.requirePermission.mockResolvedValueOnce(NextResponse.json({ code: 'forbidden', permission: 'project:transfer' }, { status: 403 }))
    expect((await OFFER(post('', { toUserId: 'x', oldOwnerRole: 'leave' }), params)).status).toBe(403)
    h.requirePermission.mockResolvedValueOnce(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    expect((await CANCEL(post('/cancel'), params)).status).toBe(404)
    expect(h.offer).not.toHaveBeenCalled()
    expect(h.cancel).not.toHaveBeenCalled()
  })

  test('the offer hands the guard context and the body to the writer', async () => {
    const res = await OFFER(post('', { toUserId: 'collab', oldOwnerRole: 'co-owner', stepUpPassword: 'pw' }), params)
    expect(res.status).toBe(201)
    expect(h.offer).toHaveBeenCalledWith(expect.any(NextRequest), AUTH, { toUserId: 'collab', oldOwnerRole: 'co-owner', stepUpPassword: 'pw' })
    await CANCEL(post('/cancel'), params)
    expect(h.cancel).toHaveBeenCalledWith(AUTH)
  })
})

describe("the recipient's routes: the person signed in", () => {
  test('accept and decline need a session and hand the identity and the password to the writer', async () => {
    expect((await ACCEPT(post('/accept', { stepUpPassword: 'pw' }), params)).status).toBe(200)
    expect(h.accept).toHaveBeenCalledWith(expect.any(NextRequest), IDENTITY, 'proj-1', 'pw')
    expect(h.identity).toHaveBeenCalledWith({ fresh: true })
    await DECLINE(post('/decline'), params)
    expect(h.decline).toHaveBeenCalledWith(IDENTITY, 'proj-1')
    h.requireEff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await ACCEPT(post('/accept', { stepUpPassword: 'pw' }), params)).status).toBe(401)
    expect((await DECLINE(post('/decline'), params)).status).toBe(401)
    expect(h.accept).toHaveBeenCalledTimes(1)
  })

  test('GET the state and the banner feed are the effective user\'s own', async () => {
    await STATE(new NextRequest('http://localhost/api/projects/proj-1/transfer'), params)
    expect(h.state).toHaveBeenCalledWith('collab', 'proj-1')
    const feed = await FEED(new NextRequest('http://localhost/api/projects/transfers'))
    expect(await feed.json()).toEqual({ incoming: [], outgoing: [], cleared: [] })
    expect(h.feed).toHaveBeenCalledWith('collab')
  })
})

describe('same-origin JSON on every change', () => {
  test.each(WRITES.map(([name, , writer]) => [name, writer] as const))('%s: another site\'s page is refused, and so is a form post', async (name, writer) => {
    const path = name === 'offer' ? '' : `/${name}`
    const run = (req: NextRequest) => ({ offer: OFFER, accept: ACCEPT, decline: DECLINE, cancel: CANCEL, acknowledge: ACKNOWLEDGE })[name](req, params)
    expect((await run(post(path, {}, { origin: 'https://evil.example' }))).status).toBe(403)
    const form = new NextRequest(`http://localhost/api/projects/proj-1/transfer${path}`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://localhost' }, body: 'a=b',
    })
    expect((await run(form)).status).toBe(415)
    expect(writer).not.toHaveBeenCalled()
  })
})
