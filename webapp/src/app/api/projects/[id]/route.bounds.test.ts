/**
 * PUT /api/projects/[id] applies the registry bounds the MCP write tools apply
 * (R-7): the same refusal, in the same words, and never a clamp.
 *
 * Before, this route only picked Project columns, so `nucleiRateLimit: 0`,
 * which update_recon_settings refuses, was saved here and nuclei then ran at
 * its built-in rate under the engagement ceiling.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockUpdateMany = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
      updateMany: (...a: unknown[]) => mockUpdateMany(...a),
    },
    userLlmProvider: { findFirst: vi.fn() },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => ({ userId: 'owner', isAdmin: false }),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { PUT } from './route'
import { filterReconSettings } from '@/lib/reconSettings/filter'

const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test',
  ipMode: false, domainBatchMode: false,
  nucleiRateLimit: 100, graphqlRateLimit: 10, katanaDepth: 2, agentLport: 4444,
  updatedAt: new Date('2026-11-01T10:00:00.000Z'),
}

let stored: Record<string, unknown>

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/proj-1', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  stored = { ...STORED }
  mockFindUnique.mockImplementation(async (args?: { select?: Record<string, unknown> }) => {
    if (!args?.select) return { ...stored }
    return Object.fromEntries(Object.keys(args.select).filter(k => args.select![k]).map(k => [k, stored[k]]))
  })
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...stored, ...data }))
  mockUpdateMany.mockResolvedValue({ count: 1 })
})

describe('PUT refuses what the MCP tools refuse, in their words', () => {
  test('nucleiRateLimit: 0 is refused with 400 naming the bound, and nothing is written', async () => {
    const res = await put({ name: 'p', nucleiRateLimit: 0 })
    expect(res.status).toBe(400)
    const body = await res.json()
    const mcp = filterReconSettings({ nucleiRateLimit: 0 })
    expect(mcp.ok).toBe(false)
    expect(body.error).toBe(mcp.ok ? null : mcp.error)
    expect(body.error).toContain('must be between 1 and')
    expect(body.key).toBe('nucleiRateLimit')
    expect(body.code).toBe('setting_rejected')
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockUpdateMany).not.toHaveBeenCalled()
  })

  test('a value above the maximum is refused, not clamped', async () => {
    const res = await put({ name: 'p', graphqlRateLimit: 101 })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/^'graphqlRateLimit' must be between 0 and 100\. Note that 0 means UNLIMITED/)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a number sent as text is refused as MCP refuses it', async () => {
    const res = await put({ name: 'p', katanaDepth: '3' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("'katanaDepth' must be a number")
  })

  // The two doors agree value by value: every write MCP accepts is saved here,
  // every write it refuses is refused here.
  test.each([
    ['nucleiRateLimit', 0],
    ['nucleiRateLimit', -5],
    ['nucleiRateLimit', 5],
    ['graphqlRateLimit', 0],
    ['graphqlRateLimit', 2],
    ['ffufRate', 0],
    ['katanaDepth', 2.5],
  ])('%s = %s gets the same verdict as update_recon_settings', async (key, value) => {
    const mcp = filterReconSettings({ [key]: value })
    const res = await put({ name: 'p', [key]: value })
    expect(res.status).toBe(mcp.ok ? 200 : 400)
    if (!mcp.ok) expect((await res.json()).error).toBe(mcp.error)
    else expect(mockUpdate.mock.calls[0][0].data[key]).toBe(value)
  })
})

describe('PUT keeps whole-row saves of older projects working', () => {
  test('graphqlRateLimit: 0 is saved as written: 0 means unlimited and scan start caps it', async () => {
    const res = await put({ name: 'p', graphqlRateLimit: 0 })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.graphqlRateLimit).toBe(0)
  })

  test('a stored out-of-bounds number sent back unchanged does not block an unrelated edit', async () => {
    stored.nucleiRateLimit = 0
    // The form's whole-row save carries updatedAt, so it is a compare-and-swap.
    const res = await put({ ...STORED, nucleiRateLimit: 0, katanaDepth: 3 })
    expect(res.status).toBe(200)
    expect(mockUpdateMany.mock.calls[0][0].data).toMatchObject({ nucleiRateLimit: 0, katanaDepth: 3 })
  })

  test('changing that stored value to another out-of-bounds one is still refused', async () => {
    stored.nucleiRateLimit = 0
    const res = await put({ name: 'p', nucleiRateLimit: -1 })
    expect(res.status).toBe(400)
    expect((await res.json()).key).toBe('nucleiRateLimit')
  })

  test('an optional number may be cleared', async () => {
    const res = await put({ name: 'p', agentLport: null })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.agentLport).toBeNull()
  })
})
