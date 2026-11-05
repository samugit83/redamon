/**
 * PUT /api/projects/[id] and the Jev engine flags.
 *
 * A switch onto Jev or a changed non-null selection needs an explicit
 * owner-owned Jev provider. The form sends every field on every save, so a
 * legacy stored `true` must never block an unrelated save.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockUpdateMany = vi.fn()
const mockProviderFind = vi.fn()
const mockActor = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
      updateMany: (...a: unknown[]) => mockUpdateMany(...a),
    },
    userLlmProvider: { findFirst: (...a: unknown[]) => mockProviderFind(...a) },
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
    requireEffectiveUser: async () => mockActor(),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { PUT } from './route'

const JEV_ONLY = ['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth',
  'hakrawlerJevSeedOrder', 'serializedScanJevRank'] as const

const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test', jevProviderId: null,
  ipMode: false, domainBatchMode: false, katanaDepth: 2,
  ffufAiUseJev: false, nucleiTagsAiUseJev: false, wafAiUseJev: false, takeoverAiUseJev: false,
  ...Object.fromEntries(JEV_ONLY.map(k => [k, false])),
  updatedAt: new Date('2026-09-29T10:00:00.000Z'),
}

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

let stored: Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  stored = { ...STORED }
  mockActor.mockResolvedValue({ userId: 'owner', isAdmin: false })
  // Honour `select` the way Prisma does. Returning the whole row hid a route that
  // read only four engine fields: every Jev-only true read back as a switch-on.
  mockFindUnique.mockImplementation(async (args?: { select?: Record<string, unknown> }) => {
    if (!args?.select) return { ...stored }
    return Object.fromEntries(Object.keys(args.select).filter(k => args.select![k]).map(k => [k, stored[k]]))
  })
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...stored, ...data }))
  mockUpdateMany.mockResolvedValue({ count: 1 })
  mockProviderFind.mockResolvedValue(null)
})

describe('PUT: a switch onto Jev', () => {
  test('with an explicit provider selection on the owner\'s account it is written', async () => {
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    stored.jevProviderId = 'jev-selected'
    const res = await put({ name: 'p', ffufAiUseJev: true })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.ffufAiUseJev).toBe(true)
  })

  test('without a provider selection it is refused with 400 and nothing is written', async () => {
    const res = await put({ name: 'p', ffufAiUseJev: true, wafAiUseJev: true })
    expect(res.status).toBe(400)
    const { error } = await res.json()
    expect(error).toContain('ffufAiUseJev')
    expect(error).toContain('wafAiUseJev')
    expect(error).toContain('Settings')
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockUpdateMany).not.toHaveBeenCalled()
  })

  test('the selected provider is looked up for the project OWNER, not the admin acting on it', async () => {
    mockActor.mockResolvedValue({ userId: 'admin-1', isAdmin: true })
    mockProviderFind.mockResolvedValue(null)
    stored.jevProviderId = 'jev-selected'
    const res = await put({ name: 'p', ffufAiUseJev: true })
    expect(res.status).toBe(400)
    expect(mockProviderFind).toHaveBeenCalledWith({ where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } }, select: { id: true } })
  })

  test('it fails closed when the provider lookup throws', async () => {
    mockProviderFind.mockRejectedValue(new Error('db down'))
    stored.jevProviderId = 'jev-selected'
    const res = await put({ name: 'p', takeoverAiUseJev: true })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("Couldn't verify the project's Jev provider, try again.")
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('PUT: provider selection changes', () => {
  test('a changed non-null selection is validated and written without a switch-on', async () => {
    stored.jevProviderId = 'jev-before'
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    const res = await put({ name: 'p', jevProviderId: 'jev-selected' })
    expect(res.status).toBe(200)
    expect(mockProviderFind).toHaveBeenCalledWith({
      where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
    expect(mockUpdate.mock.calls[0][0].data.jevProviderId).toBe('jev-selected')
  })

  test('a changed unavailable selection is refused even with legacy enabled hooks', async () => {
    stored.ffufAiUseJev = true
    stored.jevProviderId = 'jev-before'
    const res = await put({ name: 'p', jevProviderId: 'jev-selected' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('does not belong to the project owner')
    expect(mockProviderFind).toHaveBeenCalledWith({
      where: { id: 'jev-selected', userId: 'owner', providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockUpdateMany).not.toHaveBeenCalled()
  })

  test('clearing a selection permits static fallback for an already enabled hook', async () => {
    stored.ffufAiUseJev = true
    stored.jevProviderId = 'jev-before'
    const res = await put({ name: 'p', jevProviderId: null })
    expect(res.status).toBe(200)
    expect(mockProviderFind).not.toHaveBeenCalled()
    expect(mockUpdate.mock.calls[0][0].data.jevProviderId).toBeNull()
  })

  test('an account provider cannot enable a hook with a null selection', async () => {
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    const res = await put({ name: 'p', ffufAiUseJev: true, jevProviderId: null })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('select an explicit Jev provider')
    expect(mockProviderFind).not.toHaveBeenCalled()
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockUpdateMany).not.toHaveBeenCalled()
  })
})

describe('PUT: a stored Jev choice is never a reason to refuse a save', () => {
  test('an unchanged true with no provider selection still saves an unrelated field', async () => {
    stored.ffufAiUseJev = true
    stored.wafAiUseJev = true
    const res = await put({ name: 'p', katanaDepth: 4, ffufAiUseJev: true, wafAiUseJev: true })
    expect(res.status).toBe(200)
    expect(mockProviderFind).not.toHaveBeenCalled()
    expect(mockUpdate.mock.calls[0][0].data.katanaDepth).toBe(4)
  })

  test.each(JEV_ONLY)('an unchanged Jev-only %s=true with no provider selection still saves an unrelated field', async (field) => {
    stored[field] = true
    const res = await put({ name: 'p', katanaDepth: 4, [field]: true })
    expect(res.status).toBe(200)
    expect(mockProviderFind).not.toHaveBeenCalled()
    expect(mockUpdate.mock.calls[0][0].data.katanaDepth).toBe(4)
  })

  test('switching a hook back to the LLM never needs a token', async () => {
    stored.ffufAiUseJev = true
    const res = await put({ name: 'p', ffufAiUseJev: false })
    expect(res.status).toBe(200)
    expect(mockProviderFind).not.toHaveBeenCalled()
  })

  test('a save that names no engine field never touches the provider table', async () => {
    const res = await put({ name: 'p', katanaDepth: 3 })
    expect(res.status).toBe(200)
    expect(mockProviderFind).not.toHaveBeenCalled()
  })
})

describe('PUT: turning on a Jev-only hook', () => {
  test('without a provider selection it is refused with 400 and nothing is written', async () => {
    const res = await put({ name: 'p', httpxJevPageType: true })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('httpxJevPageType (page-type labels)')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('with an explicit provider selection on the owner\'s account it is written', async () => {
    mockProviderFind.mockResolvedValue({ id: 'jev-selected' })
    stored.jevProviderId = 'jev-selected'
    const res = await put({ name: 'p', resourceEnumJevToolHealth: true })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.resourceEnumJevToolHealth).toBe(true)
  })
})
