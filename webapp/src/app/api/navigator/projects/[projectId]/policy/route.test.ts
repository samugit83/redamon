/**
 * The owner's "AI Navigator for collaborators" (plan §5.4, §10.2 row 35): 404 unless sharing is in
 * force; the owner level (a co-owner is refused); refused under act-as; a step-up to turn it on, none
 * to turn it off; the change and its audit row in one transaction; turning it off stops every
 * collaborator's answer in flight.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  sharing: { enabled: true } as null | { enabled: boolean },
  enabled: true,
  auth: null as unknown,
  levelOk: true,
  acting: null as null | NextResponse,
  stepUp: null as null | NextResponse,
  stored: false,
  audits: [] as Array<Record<string, unknown>>,
  ended: [] as Array<[string, string]>,
}))

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/authz/sharingPolicy', () => ({ sharingPolicyInForce: async () => h.sharing }))
vi.mock('@/lib/navigator/switch', () => ({ navigatorEnabled: async () => h.enabled }))
vi.mock('@/lib/authz/guards', () => ({
  requirePermission: async () => h.auth,
  requireLevel: () => (h.levelOk ? null : NextResponse.json({ code: 'forbidden', level: 'O' }, { status: 403 })),
}))
vi.mock('@/lib/authz/actAsRefusals', () => ({ refuseWhileActingAs: async () => h.acting }))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: async (_r: unknown, pw: unknown) => (pw === 'right' ? null : h.stepUp) }))
vi.mock('@/lib/auditForward', () => ({ auditedTransaction: async (_db: unknown, fn: (tx: unknown) => unknown) => fn({}) }))
vi.mock('@/lib/audit', () => ({ writeAuditTx: async (_tx: unknown, e: Record<string, unknown>) => { h.audits.push(e) } }))
vi.mock('@/lib/auditActor', () => ({ auditActorOf: () => ({ actorId: 'owner' }), sessionActor: () => ({ id: 'owner' }) }))
vi.mock('@/lib/authz/navigatorPolicy', () => ({
  navigatorCollaboratorsAllowed: async () => h.stored,
  writeNavigatorPolicy: async (_tx: unknown, _p: string, value: boolean) => {
    const changed = h.stored !== value
    h.stored = value
    return changed
  },
  endCollaboratorNavigator: async (projectId: string, ownerId: string) => { h.ended.push([projectId, ownerId]); return 1 },
}))

import { GET, POST } from './route'

const P = 'cproject000000000000000001'
const params = { params: Promise.resolve({ projectId: P }) }
const post = (body: unknown) => new NextRequest(`http://localhost:3000/api/navigator/projects/${P}/policy`, {
  method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', host: 'localhost:3000' },
})
const get = () => new NextRequest(`http://localhost:3000/api/navigator/projects/${P}/policy`, { headers: { host: 'localhost:3000' } })

beforeEach(() => {
  h.sharing = { enabled: true }
  h.enabled = true
  h.auth = { session: { userId: 'owner' }, effective: { userId: 'owner' }, permission: 'project:share',
    access: { project: { id: P, userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' } }
  h.levelOk = true
  h.acting = null
  h.stepUp = NextResponse.json({ code: 'step_up_required' }, { status: 403 })
  h.stored = false
  h.audits = []
  h.ended = []
})

describe('policy route', () => {
  test('404 with sharing not in force, or the switch off', async () => {
    h.sharing = null
    expect((await GET(get(), params)).status).toBe(404)
    expect((await POST(post({ collaboratorsAllowed: true }), params)).status).toBe(404)
    h.sharing = { enabled: true }
    h.enabled = false
    expect((await GET(get(), params)).status).toBe(404)
  })

  test('GET answers the stored value', async () => {
    h.stored = true
    expect(await (await GET(get(), params)).json()).toEqual({ collaboratorsAllowed: true })
  })

  test('a co-owner (Manage, not Owner) is refused', async () => {
    h.levelOk = false
    expect((await POST(post({ collaboratorsAllowed: true, stepUpPassword: 'right' }), params)).status).toBe(403)
    expect(h.stored).toBe(false)
  })

  test('refused while an admin acts as the owner', async () => {
    h.acting = NextResponse.json({ code: 'act_as_refused' }, { status: 403 })
    expect((await POST(post({ collaboratorsAllowed: true, stepUpPassword: 'right' }), params)).status).toBe(403)
    expect(h.stored).toBe(false)
  })

  test('turning it on asks the password; with it, the change and its audit row land together', async () => {
    expect((await POST(post({ collaboratorsAllowed: true }), params)).status).toBe(403)
    expect(h.stored).toBe(false)
    const res = await POST(post({ collaboratorsAllowed: true, stepUpPassword: 'right' }), params)
    expect(await res.json()).toEqual({ collaboratorsAllowed: true, changed: true })
    expect(h.audits).toEqual([expect.objectContaining({ action: 'project.navigator_collaborators.allow', projectId: P })])
    expect(h.ended).toEqual([])
  })

  test('turning it off needs no password and stops every collaborator\'s answer', async () => {
    h.stored = true
    const res = await POST(post({ collaboratorsAllowed: false }), params)
    expect(await res.json()).toEqual({ collaboratorsAllowed: false, changed: true })
    expect(h.audits).toEqual([expect.objectContaining({ action: 'project.navigator_collaborators.disallow' })])
    expect(h.ended).toEqual([[P, 'owner']])
  })

  test('a non-boolean is 400; an unchanged value writes no row', async () => {
    expect((await POST(post({ collaboratorsAllowed: 'yes' }), params)).status).toBe(400)
    const res = await POST(post({ collaboratorsAllowed: false }), params)
    expect(await res.json()).toEqual({ collaboratorsAllowed: false, changed: false })
    expect(h.audits).toEqual([])
  })
})
