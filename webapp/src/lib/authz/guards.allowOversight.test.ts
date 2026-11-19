/**
 * `allowOversight: false` (AI Navigator plan §5.6): a caller who reaches the project only through
 * oversight or break-glass is refused inside the guard, with 403 `oversight_not_allowed`, before
 * the `project.oversee` audit row is written. Without the option the guard is unchanged.
 *
 * `can()`, the session and the oversight audit are doubles: this pins the guard's ordering only.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  via: 'oversight' as string,
  actingAs: null as null | { id: string },
  auditOversightRead: vi.fn(async () => {}),
  auditActAsRead: vi.fn(async () => {}),
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => ({
    session: { userId: 'admin', role: 'admin' },
    principal: { id: 'admin', role: 'admin' },
    actingAs: h.actingAs,
  }),
}))
vi.mock('./can', () => ({
  actsOnProject: () => true,
  can: async () => ({
    allowed: true,
    capabilities: new Set(['navigator:use']),
    access: { project: { id: 'P1', userId: 'owner' }, level: 'read', toggles: { rawData: false }, via: h.via },
  }),
}))
vi.mock('./oversight', () => ({ auditOversightRead: h.auditOversightRead }))
vi.mock('./actAsReads', () => ({ auditActAsRead: h.auditActAsRead }))

import { requirePermission, withPermission } from './guards'

const req = () => new NextRequest('http://localhost:3000/api/x')

beforeEach(() => {
  h.via = 'oversight'
  h.actingAs = null
  h.auditOversightRead.mockClear()
  h.auditActAsRead.mockClear()
})

describe('allowOversight: false', () => {
  test.each(['oversight', 'break_glass'])('%s: 403 oversight_not_allowed, and no oversight row', async (via) => {
    h.via = via
    const res = await requirePermission(req(), 'navigator:use', { projectId: 'P1', allowOversight: false })
    expect(res).toBeInstanceOf(NextResponse)
    expect((res as NextResponse).status).toBe(403)
    expect(await (res as NextResponse).json()).toMatchObject({ code: 'oversight_not_allowed' })
    expect(h.auditOversightRead).not.toHaveBeenCalled()
  })

  test('withPermission honours it too', async () => {
    const handler = vi.fn(async () => new Response('ok'))
    const route = withPermission('navigator:use', handler, { projectId: () => 'P1', allowOversight: false })
    const res = await route(req(), {})
    expect(res.status).toBe(403)
    expect(handler).not.toHaveBeenCalled()
    expect(h.auditOversightRead).not.toHaveBeenCalled()
  })

  test.each(['owner', 'share'])('%s access passes', async (via) => {
    h.via = via
    const res = await requirePermission(req(), 'navigator:use', { projectId: 'P1', allowOversight: false })
    expect(res).not.toBeInstanceOf(NextResponse)
  })

  test('under act-as, oversight stays the 404 it was', async () => {
    h.actingAs = { id: 'alice' }
    const res = await requirePermission(req(), 'navigator:use', { projectId: 'P1', allowOversight: false })
    expect((res as NextResponse).status).toBe(404)
  })
})

describe('without the option, unchanged', () => {
  test('oversight passes and writes its row', async () => {
    const res = await requirePermission(req(), 'graph:read', { projectId: 'P1' })
    expect(res).not.toBeInstanceOf(NextResponse)
    expect(h.auditOversightRead).toHaveBeenCalledTimes(1)
  })

  test('break-glass passes', async () => {
    h.via = 'break_glass'
    const res = await requirePermission(req(), 'graph:read', { projectId: 'P1', allowOversight: true })
    expect(res).not.toBeInstanceOf(NextResponse)
  })
})
