/**
 * DELETE /api/agent/workspace/upload-sessions/[uploadId]
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuard = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))

import { DELETE } from './route'

let calls: string[]
const del = (id: string, pid = 'p1') =>
  DELETE(new NextRequest(`http://x/x?projectId=${pid}`, { method: 'DELETE' }), { params: Promise.resolve({ uploadId: id }) })

beforeEach(() => {
  calls = []
  mockGuard.mockReset().mockResolvedValue(null)
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    calls.push(String(url))
    return new Response(JSON.stringify({ aborted: true }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
})

describe('DELETE upload session', () => {
  test('aborts through the agent', async () => {
    const res = await del('e'.repeat(32))
    expect(await res.json()).toEqual({ aborted: true })
    expect(calls[0]).toContain(`/workspace/upload-sessions/${'e'.repeat(32)}?projectId=p1`)
  })

  test('a bad id is already gone; the agent is not called', async () => {
    const res = await del('nope')
    expect(await res.json()).toEqual({ aborted: true })
    expect(calls).toHaveLength(0)
  })

  test('denied project never reaches the agent', async () => {
    mockGuard.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await del('e'.repeat(32), 'victim')
    expect(res.status).toBe(404)
    expect(calls).toHaveLength(0)
  })
})
