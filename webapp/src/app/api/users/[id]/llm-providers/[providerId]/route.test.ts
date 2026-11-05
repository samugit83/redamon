/**
 * STRIDE I1 (single-item closure) — GET/DELETE
 * /api/users/[id]/llm-providers/[providerId] ownership + unmask gating (wiring).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockFindFirst = vi.fn()
const mockDelete = vi.fn()
const mockProjectUpdateMany = vi.fn()
const mockTransaction = vi.fn()
const mockUpdate = vi.fn()
const mockRequireUserAccess = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    $transaction: (...a: unknown[]) => mockTransaction(...a),
    userLlmProvider: {
      findFirst: (...a: unknown[]) => mockFindFirst(...a),
      delete: (...a: unknown[]) => mockDelete(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
  },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
}))

import { GET, PUT, DELETE } from './route'

const SECRET = 'sk-PROVIDERSECRET1234'
const PROVIDER = { id: 'p1', userId: 'victim', apiKey: SECRET, awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '' }
const FORBIDDEN = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
function get(url: string): NextRequest { return new NextRequest(url) }
function del(): NextRequest { return new NextRequest('http://x/api/users/victim/llm-providers/p1', { method: 'DELETE' }) }
function put(body: unknown): NextRequest {
  return new NextRequest('http://x/api/users/victim/llm-providers/p1', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const params = (id: string, providerId: string) => ({ params: Promise.resolve({ id, providerId }) })

beforeEach(() => {
  mockFindFirst.mockReset().mockResolvedValue(PROVIDER)
  mockDelete.mockReset().mockResolvedValue({})
  mockProjectUpdateMany.mockReset().mockResolvedValue({ count: 0 })
  mockTransaction.mockReset().mockImplementation(async fn => fn({ project: { updateMany: mockProjectUpdateMany }, userLlmProvider: { delete: mockDelete } }))
  mockUpdate.mockReset().mockResolvedValue(PROVIDER)
  mockRequireUserAccess.mockReset()
  mockIsInternal.mockReset()
})

describe('PUT provider — reasoning controls', () => {
  test('owner updates reasoning enabled state and effort', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    const res = await PUT(
      put({ providerType: 'openai_compatible', reasoningEnabled: true, reasoningEffort: 'medium' }),
      params('victim', 'p1'),
    )

    expect(res.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        reasoningEnabled: true,
        reasoningEffort: 'medium',
      }),
    }))
  })

  test('non-compat provider cannot persist reasoning controls', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue({ ...PROVIDER, providerType: 'anthropic' })
    const res = await PUT(
      put({ providerType: 'anthropic', reasoningEnabled: true, reasoningEffort: 'medium' }),
      params('victim', 'p1'),
    )

    expect(res.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        reasoningEnabled: false,
        reasoningEffort: 'high',
      }),
    }))
  })

  test('rejects invalid effort without updating', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    const res = await PUT(put({ reasoningEnabled: true, reasoningEffort: 'extreme' }), params('victim', 'p1'))

    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('GET provider — I1', () => {
  test('EXPLOIT: guard denies (cross-user) → 403, no secret, no DB read', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1?internal=true'), params('victim', 'p1'))
    expect(res.status).toBe(403)
    expect(await res.text()).not.toContain(SECRET)
    expect(mockFindFirst).not.toHaveBeenCalled()
  })

  test('owner, no internal-key header → 200 masked (never cleartext for browser)', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1?internal=true'), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain(SECRET)
  })

  test('internal-key header → 200 unmasked', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(true)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1'), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(await res.text()).toContain(SECRET)
  })
})

describe('DELETE provider — ownership', () => {
  test('EXPLOIT: guard denies (cross-user) → 403, no write', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    const res = await DELETE(del(), params('victim', 'p1'))
    expect(res.status).toBe(403)
    expect(mockDelete).not.toHaveBeenCalled()
  })

  test('owner delete → 200', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    const res = await DELETE(del(), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockDelete).toHaveBeenCalled()
  })
})

describe('PUT provider - TypeSafe Jev type lock', () => {
  const JEV_ROW = { ...PROVIDER, providerType: 'jev', apiKey: 'apikey_stored_key', baseUrl: '', modelIdentifier: 'jev-1.13.0' }

  test('a stored Jev row cannot become a chat provider', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue(JEV_ROW)
    const res = await PUT(
      put({ providerType: 'openai_compatible', baseUrl: 'http://evil.example/v1', apiKey: '••••••••_key' }),
      params('victim', 'p1'),
    )
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a chat provider cannot become a Jev row', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue({ ...PROVIDER, providerType: 'openai' })
    const res = await PUT(put({ providerType: 'jev' }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a Jev update writes name and key; transport stays pinned', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue(JEV_ROW)
    const res = await PUT(
      put({
        providerType: 'jev', apiKey: ' apikey_new_key ', baseUrl: 'http://evil.example/v1',
        defaultHeaders: { 'X-Leak': '1' }, modelIdentifier: 'jev-latest', name: 'renamed',
      }),
      params('victim', 'p1'),
    )
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).toMatchObject({ apiKey: 'apikey_new_key', name: 'renamed', baseUrl: 'https://api.typesafe.ai', defaultHeaders: {}, modelIdentifier: 'jev-1.13.0', timeout: 5, sslVerify: true })
  })

  test('a masked key keeps the stored one', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue(JEV_ROW)
    await PUT(put({ providerType: 'jev', apiKey: '••••••••_key' }), params('victim', 'p1'))
    expect(mockUpdate.mock.calls[0][0].data).toMatchObject({ apiKey: 'apikey_stored_key' })
  })

  test('an empty key is refused', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue(JEV_ROW)
    const res = await PUT(put({ apiKey: '  ' }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('Jev backend protection and deletion', () => {
  test.each([
    ['jev', 'jev_openrouter'], ['jev_openrouter', 'jev'],
    ['jev_openrouter', 'openai'], ['openrouter', 'jev_openrouter'],
  ])('cannot convert %s to %s', async (from, to) => {
    mockFindFirst.mockResolvedValue({ ...PROVIDER, providerType: from })
    const res = await PUT(put({ providerType: to }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    expect(mockUpdate).not.toHaveBeenCalled()
  })
  test('OpenRouter transport is pinned despite malicious legacy or submitted fields', async () => {
    mockFindFirst.mockResolvedValue({ ...PROVIDER, providerType: 'jev_openrouter' })
    const res = await PUT(put({ name: 'New name', baseUrl: 'https://evil.example', modelIdentifier: 'chat', defaultHeaders: { leak: 'yes' }, timeout: 500, sslVerify: false }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).toMatchObject({ name: 'New name', providerType: 'jev_openrouter', baseUrl: 'https://openrouter.ai/api/v1', modelIdentifier: 'typesafe/jev-1.13', defaultHeaders: {}, timeout: 5, sslVerify: true })
  })
  test('deletion clears selections through Prisma before deleting and returns a warning', async () => {
    mockProjectUpdateMany.mockResolvedValue({ count: 2 })
    const res = await DELETE(del(), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockProjectUpdateMany).toHaveBeenCalledWith({ where: { jevProviderId: 'p1' }, data: { jevProviderId: null, updatedAt: expect.any(Date) } })
    expect(mockProjectUpdateMany.mock.invocationCallOrder[0]).toBeLessThan(mockDelete.mock.invocationCallOrder[0])
    expect(await res.json()).toMatchObject({ success: true, affectedProjects: 2, warning: expect.stringContaining('fallbacks') })
  })
  test('failed selection update prevents deletion', async () => {
    mockProjectUpdateMany.mockRejectedValue(new Error('database unavailable'))
    const res = await DELETE(del(), params('victim', 'p1'))
    expect(res.status).toBe(500)
    expect(mockDelete).not.toHaveBeenCalled()
  })
})
