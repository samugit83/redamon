/**
 * Server-owned remediation fields are not client-writable (S10 / X11).
 *
 * A remediation is produced by a triage run and rewritten by the next one.
 * `PUT` used to spread the whole request body into the update, so any caller
 * who could reach one remediation could rewrite its severity, its priority, its
 * CVE list — or `targetRepo`, which decided where the CodeFix agent pushed.
 * `GET` passed `sort` straight into `orderBy`, making every column an ordering
 * oracle. Both now work from a whitelist.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockUpdate = vi.fn()
const mockFindMany = vi.fn()
const mockFindUnique = vi.fn()
const mockIsInternal = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()
const mockRequireProjectScopedResource = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    remediation: {
      update: (...a: unknown[]) => mockUpdate(...a),
      findMany: (...a: unknown[]) => mockFindMany(...a),
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      create: vi.fn(),
    },
  },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => mockIsInternal(...a) }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
  requireProjectScopedResource: (...a: unknown[]) => mockRequireProjectScopedResource(...a),
}))

import { PUT } from './[id]/route'
import { GET } from './route'

function put(body: unknown): NextRequest {
  return new NextRequest('http://x/api/remediations/r1', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function get(query: string): NextRequest {
  return new NextRequest(`http://x/api/remediations?${query}`)
}

const PARAMS = { params: Promise.resolve({ id: 'r1' }) }

beforeEach(() => {
  vi.clearAllMocks()
  mockIsInternal.mockReturnValue(true)
  mockUpdate.mockResolvedValue({ id: 'r1' })
  mockFindMany.mockResolvedValue([])
})

describe('PUT /api/remediations/[id] — writable field whitelist', () => {
  test('the CodeFix agent’s own update still goes through', async () => {
    const res = await PUT(put({
      status: 'pr_created',
      prUrl: 'https://github.com/o/r/pull/1',
      prStatus: 'open',
      fixBranch: 'redamon/fix-r1',
      fileChanges: [],
    }), PARAMS)
    expect(res.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalled()
  })

  test('the dashboard’s Dismiss still goes through', async () => {
    const res = await PUT(put({ status: 'dismissed' }), PARAMS)
    expect(res.status).toBe(200)
  })

  test('EXPLOIT: repointing targetRepo is rejected, nothing is written', async () => {
    const res = await PUT(put({ targetRepo: 'attacker/evil' }), PARAMS)
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ error: expect.stringContaining('targetRepo') })
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('EXPLOIT: rewriting the ranking is rejected', async () => {
    const res = await PUT(put({ priority: 1, severity: 'critical' }), PARAMS)
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('one bad field poisons the whole update, it is not silently dropped', async () => {
    const res = await PUT(put({ status: 'dismissed', cveIds: ['CVE-0000-0000'] }), PARAMS)
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('an unknown status is rejected', async () => {
    const res = await PUT(put({ status: 'totally-made-up' }), PARAMS)
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('an empty body is rejected rather than issuing a no-op write', async () => {
    const res = await PUT(put({}), PARAMS)
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a browser caller that does not own the project is still blocked first', async () => {
    mockIsInternal.mockReturnValue(false)
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireProjectScopedResource.mockResolvedValue(
      NextResponse.json({ error: 'Not found' }, { status: 404 })
    )
    const res = await PUT(put({ status: 'dismissed' }), PARAMS)
    expect(res.status).toBe(404)
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('GET /api/remediations — sort whitelist', () => {
  test('the default sort is the rank', async () => {
    const res = await GET(get('projectId=p1'))
    expect(res.status).toBe(200)
    expect(mockFindMany).toHaveBeenCalledWith(
      expect.objectContaining({ orderBy: { priority: 'asc' } })
    )
  })

  test('an allowed sort is honoured', async () => {
    await GET(get('projectId=p1&sort=updatedAt&order=desc'))
    expect(mockFindMany).toHaveBeenCalledWith(
      expect.objectContaining({ orderBy: { updatedAt: 'desc' } })
    )
  })

  test('EXPLOIT: an arbitrary column is rejected, nothing is queried', async () => {
    const res = await GET(get('projectId=p1&sort=agentNotes'))
    expect(res.status).toBe(400)
    expect(mockFindMany).not.toHaveBeenCalled()
  })

  test('a bogus order falls back to asc instead of reaching Prisma', async () => {
    await GET(get('projectId=p1&order=sideways'))
    expect(mockFindMany).toHaveBeenCalledWith(
      expect.objectContaining({ orderBy: { priority: 'asc' } })
    )
  })
})
