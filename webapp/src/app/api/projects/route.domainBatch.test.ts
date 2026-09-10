/**
 * Domain batch, POST /api/projects: F1 (client-supplied project id) and F4
 * (the soft guardrail must see every root).
 *
 * F1: the id a client may supply becomes the project's primary key AND a
 * component of recon output filenames and of the orchestrator's
 * /project/<id>/files URL. It was accepted verbatim, so an id of `*` turned the
 * downstream batch-file lookup into a wildcard over every OTHER project's files.
 * The filesystem layer no longer globs, and this is the second lock: the id must
 * be a plain cuid-shaped token.
 *
 * F4: a batch's roots must reach the guardrail as a LIST. Joined into
 * target_domain they landed in a singular prompt that could approve the set
 * despite one blocked member.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()
const mockProjectUpdate = vi.fn()
const mockRun = vi.fn()
const mockFetch = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: {
      create: (...a: unknown[]) => mockProjectCreate(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: vi.fn() }),
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { POST } from './route'

function postReq(body: Record<string, unknown>) {
  return new Request('http://localhost/api/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

const BATCH_BASE = {
  userId: 'user-1',
  name: 'Batch Project',
  domainBatchMode: true,
  domainBatchHosts: ['sub1.domain1.com', 'sub2.domain2.it'],
}

beforeEach(() => {
  vi.clearAllMocks()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  mockProjectCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
    id: data.id ?? 'generated-id', userId: 'user-1', ...data,
  }))
  mockRun.mockResolvedValue({})
  vi.stubGlobal('fetch', mockFetch)
  mockFetch.mockResolvedValue({ ok: true, json: async () => ({ allowed: true }) })
})

describe('F1: the client-supplied project id is constrained', () => {
  const HOSTILE = ['*', '[a-z]*', '?abc', 'a/b', '../etc', 'a b', 'UPPER1234567890123456',
    'short', 'x'.repeat(40), '']

  test.each(HOSTILE.filter(Boolean))('an id of %o is refused', async (id) => {
    const res = await POST(postReq({ ...BATCH_BASE, targetGuardrailEnabled: false, id }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('Invalid project id')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a real cuid is accepted', async () => {
    const res = await POST(postReq({
      ...BATCH_BASE, targetGuardrailEnabled: false, id: 'cmnbt9q1c0001nq01nv1wp1si',
    }))
    expect(res.status).toBe(201)
    expect(mockProjectCreate.mock.calls[0][0].data.id).toBe('cmnbt9q1c0001nq01nv1wp1si')
  })

  test('omitting the id still works (the server generates one)', async () => {
    const res = await POST(postReq({ ...BATCH_BASE, targetGuardrailEnabled: false }))
    expect(res.status).toBe(201)
    expect(mockProjectCreate.mock.calls[0][0].data).not.toHaveProperty('id')
  })

  test('a hostile id cannot reach the recon filename pattern', async () => {
    // Nothing is created, so no `recon_*__*.json` path can ever be derived.
    await POST(postReq({ ...BATCH_BASE, targetGuardrailEnabled: false, id: '*' }))
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})

describe('F4: the soft guardrail receives the roots as a list', () => {
  async function guardrailBody() {
    await POST(postReq({ ...BATCH_BASE, targetGuardrailEnabled: true }))
    const call = mockFetch.mock.calls.find(c => String(c[0]).includes('/guardrail/check-target'))
    expect(call, 'guardrail was not called').toBeTruthy()
    return JSON.parse(call![1].body as string)
  }

  test('every root is sent in target_domains', async () => {
    const body = await guardrailBody()
    expect(body.target_domains).toEqual(['domain1.com', 'domain2.it'])
  })

  test('target_domain is NOT a comma-joined string', async () => {
    const body = await guardrailBody()
    expect(body.target_domain).toBe('')
    expect(String(body.target_domain)).not.toContain(',')
  })

  test('a single-domain project is unchanged', async () => {
    await POST(postReq({
      userId: 'user-1', name: 'Single', targetDomain: 'example.com', targetGuardrailEnabled: true,
    }))
    const call = mockFetch.mock.calls.find(c => String(c[0]).includes('/guardrail/check-target'))
    const body = JSON.parse(call![1].body as string)
    expect(body.target_domain).toBe('example.com')
    expect(body.target_domains).toEqual([])
  })

  test('a guardrail refusal still blocks creation', async () => {
    mockFetch.mockResolvedValue({
      ok: true, json: async () => ({ allowed: false, reason: 'domain2.it is a major company' }),
    })
    const res = await POST(postReq({ ...BATCH_BASE, targetGuardrailEnabled: true }))
    expect(res.status).toBe(403)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})

describe('the hard guardrail still checks every batch root', () => {
  test('a blocked root anywhere in the list refuses the create', async () => {
    const res = await POST(postReq({
      userId: 'user-1',
      name: 'Batch',
      domainBatchMode: true,
      targetGuardrailEnabled: false,
      domainBatchHosts: ['ok.example.com', 'www.whitehouse.gov', 'also-ok.example.com'],
    }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('whitehouse.gov')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})
