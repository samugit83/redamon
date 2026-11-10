/**
 * POST /api/projects applies the registry bounds create_project applies (R-7):
 * refused in the same words, never clamped. Before, the form's create (and an
 * LLM-parsed body) could store `nucleiRateLimit: 0`, which nuclei then ran at
 * its built-in rate.
 *
 * Same harness as route.jevEngine.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: { create: (...a: unknown[]) => mockProjectCreate(...a), update: vi.fn() },
    userLlmProvider: { findFirst: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }),
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { NextRequest } from 'next/server'
import { POST } from './route'
import { filterReconSettings } from '@/lib/reconSettings/filter'

const postReq = (body: Record<string, unknown>) =>
  new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

const base = { name: 'test', targetDomain: 'example.invalid' }

beforeEach(() => {
  vi.clearAllMocks()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  mockProjectCreate.mockResolvedValue({ id: 'p1', name: 'test', userId: 'user-1', targetDomain: 'example.invalid' })
})

const created = () => mockProjectCreate.mock.calls[0][0].data as Record<string, unknown>

describe('POST refuses what create_project refuses, in its words', () => {
  test('nucleiRateLimit: 0 is refused with 400 naming the bound, and no project is created', async () => {
    const res = await POST(postReq({ ...base, nucleiRateLimit: 0 }))
    expect(res.status).toBe(400)
    const body = await res.json()
    const mcp = filterReconSettings({ nucleiRateLimit: 0 }, { mode: 'create' })
    expect(mcp.ok).toBe(false)
    expect(body.error).toBe(mcp.ok ? null : mcp.error)
    expect(body).toMatchObject({ key: 'nucleiRateLimit', code: 'setting_rejected' })
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a number sent as text is judged after the route coerces it', async () => {
    const res = await POST(postReq({ ...base, nucleiRateLimit: '0' }))
    expect(res.status).toBe(400)
    expect((await res.json()).key).toBe('nucleiRateLimit')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test.each([
    ['nucleiRateLimit', -5],
    ['nucleiRateLimit', 5],
    ['graphqlRateLimit', 0],
    ['graphqlRateLimit', 101],
    ['takeoverRateLimit', 501],
    ['ffufRate', 0],
  ])('%s = %s gets the same verdict as create_project', async (key, value) => {
    const mcp = filterReconSettings({ [key]: value }, { mode: 'create' })
    const res = await POST(postReq({ ...base, [key]: value }))
    if (mcp.ok) {
      expect(res.status).toBeLessThan(400)
      expect(created()[key]).toBe(value)
    } else {
      expect(res.status).toBe(400)
      expect((await res.json()).error).toBe(mcp.error)
      expect(mockProjectCreate).not.toHaveBeenCalled()
    }
  })
})
