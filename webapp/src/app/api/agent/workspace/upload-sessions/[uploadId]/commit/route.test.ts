/**
 * POST /api/agent/workspace/upload-sessions/[uploadId]/commit writes one audit
 * row per accepted commit, with the real actor and the agent's session facts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuard = vi.fn()
const mockAudit = vi.fn()
const mockSession = vi.fn()
const mockEffective = vi.fn()
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => mockAudit(...a) }))
vi.mock('@/lib/session', () => ({
  getSession: () => mockSession(),
  getEffectiveUser: () => mockEffective(),
}))

import { POST } from './route'

const ID = 'c'.repeat(32)
const JOB = 'd'.repeat(32)
const params = { params: Promise.resolve({ uploadId: ID }) }
let status: number
let calls: string[]

const req = (body: unknown) => new NextRequest('http://x/x', {
  method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
})

beforeEach(() => {
  calls = []
  status = 202
  mockGuard.mockReset().mockResolvedValue(null)
  mockAudit.mockReset()
  mockSession.mockReset().mockResolvedValue({ userId: 'u-admin', role: 'admin' })
  mockEffective.mockReset().mockResolvedValue({ userId: 'u-admin' })
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    calls.push(String(url))
    if (status !== 202) {
      return new Response(JSON.stringify({ error: 'The upload is not complete yet.', code: 'session_incomplete' }),
        { status, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(JSON.stringify({ jobId: JOB, destDir: 'uploads', name: 'site', kind: 'folder', size: 42 }),
      { status: 202, headers: { 'Content-Type': 'application/json' } })
  }))
})

describe('POST commit', () => {
  test('accepted commit writes one audit row with the session user as actor', async () => {
    const res = await POST(req({ projectId: 'p1', name: 'browser-said-this' }), params)
    expect(res.status).toBe(202)
    expect(mockAudit).toHaveBeenCalledTimes(1)
    expect(mockAudit.mock.calls[0][0]).toEqual({
      actorId: 'u-admin', action: 'workspace.upload', targetType: 'project', targetId: 'p1', source: 'ui',
      after: { kind: 'folder', destDir: 'uploads', name: 'site', size: 42, jobId: JOB },
    })
  })

  test('under act-as the audit row names both the admin and the simulated user', async () => {
    mockEffective.mockResolvedValue({ userId: 'u-target' })
    await POST(req({ projectId: 'p1' }), params)
    const row = mockAudit.mock.calls[0][0]
    expect(row.actorId).toBe('u-admin')
    expect(row.after.actingAsUserId).toBe('u-target')
  })

  test('a refused commit writes no audit row', async () => {
    status = 409
    const res = await POST(req({ projectId: 'p1' }), params)
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('session_incomplete')
    expect(mockAudit).not.toHaveBeenCalled()
  })

  test('denied project never reaches the agent', async () => {
    mockGuard.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await POST(req({ projectId: 'victim' }), params)
    expect(res.status).toBe(404)
    expect(calls).toHaveLength(0)
    expect(mockAudit).not.toHaveBeenCalled()
  })
})
