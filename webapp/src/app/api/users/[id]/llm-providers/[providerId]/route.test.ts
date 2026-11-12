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

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
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

// The step-up's own outcomes are proved in stepUp.test.ts; here the double answers as
// requireStepUp does: no password 403 step_up_required, a wrong one 403 step_up_failed.
const mockStepUp = vi.hoisted(() => vi.fn(async (_req: unknown, password: unknown) => {
  const { NextResponse } = await import('next/server')
  if (password === 'right-password') return null
  return password
    ? NextResponse.json({ error: 'Password is incorrect', code: 'step_up_failed' }, { status: 403 })
    : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: mockStepUp }))

import { GET, PUT, DELETE } from './route'

const SECRET = 'sk-PROVIDERSECRET1234'
// A stored row always has a type (and a base URL for openai_compatible): the re-entry
// rule (HD-24) compares the body's against them.
const PROVIDER = {
  id: 'p1', userId: 'victim', providerType: 'openai_compatible', baseUrl: 'https://llm.example.com/v1',
  apiKey: SECRET, awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '',
}
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

describe('the access mode by method (HD-23)', () => {
  test('GET asks for the read rule; PUT and DELETE for the write rule', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    await GET(get('http://x/api/users/victim/llm-providers/p1'), params('victim', 'p1'))
    await PUT(put({ name: 'x' }), params('victim', 'p1'))
    await DELETE(del(), params('victim', 'p1'))
    expect(mockRequireUserAccess.mock.calls.map(c => c[2])).toEqual([{ mode: 'read' }, { mode: 'write' }, { mode: 'write' }])
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockDelete).not.toHaveBeenCalled()
  })
})

describe('PUT provider - a new endpoint needs the key typed again (HD-24)', () => {
  beforeEach(() => mockRequireUserAccess.mockResolvedValue(null))

  test.each([
    ['omitted', {}],
    ['sent back masked', { apiKey: '••••••••1234' }],
  ])('a new base URL with the key %s is 400 secret_reentry_required naming apiKey; nothing is written', async (_l, key) => {
    const res = await PUT(put({ ...PROVIDER, baseUrl: 'https://elsewhere.example.net/v1', ...key, apiKey: (key as { apiKey?: string }).apiKey }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'secret_reentry_required', field: 'apiKey', endpoint: 'baseUrl' })
    expect(JSON.stringify(body)).not.toContain(SECRET)
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a new base URL with the key typed again is saved with that key', async () => {
    // ID-25: re-pointing also takes the signed-in user's password (review of 1.6)
    const res = await PUT(put({ baseUrl: 'https://elsewhere.example.net/v1', apiKey: 'sk-typed-again', stepUpPassword: 'right-password' }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).toMatchObject({ baseUrl: 'https://elsewhere.example.net/v1', apiKey: 'sk-typed-again' })
  })

  test('a new type is an endpoint change too', async () => {
    mockFindFirst.mockResolvedValue({ ...PROVIDER, providerType: 'openai', baseUrl: '' })
    const res = await PUT(put({ providerType: 'openai_compatible', baseUrl: 'https://elsewhere.example.net/v1', apiKey: '••••••••1234' }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    expect((await res.json()).endpoint).toBe('providerType')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('the same endpoint keeps the masked key (the account itself, every save)', async () => {
    const res = await PUT(put({ ...PROVIDER, apiKey: '••••••••1234', temperature: 0.2 }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.apiKey).toBe(SECRET)
  })
})


describe('PUT provider - only the row\'s own settings reach the update (review of 1.6)', () => {
  beforeEach(() => mockRequireUserAccess.mockResolvedValue(null))

  test('a relation input, a foreign key, the actor columns and unknown keys never reach prisma.update', async () => {
    const res = await PUT(put({
      name: 'renamed', temperature: 0.3,
      // nested writes Prisma would apply: move the row to another account, or select it in other projects
      user: { connect: { id: 'attacker' } },
      jevProjects: { connect: [{ id: 'victim-project' }] },
      userId: 'attacker', id: 'p-other', createdById: 'attacker', updatedById: 'attacker',
      createdAt: '2020-01-01T00:00:00Z', updatedAt: '2020-01-01T00:00:00Z',
      somethingElse: 'x',
    }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    const { where, data } = mockUpdate.mock.calls[0][0]
    expect(where).toEqual({ id: 'p1' })
    expect(data).toMatchObject({ name: 'renamed', temperature: 0.3 })
    for (const key of ['user', 'jevProjects', 'userId', 'id', 'createdById', 'updatedById', 'createdAt', 'updatedAt', 'somethingElse']) {
      expect(key in data, key).toBe(false)
    }
  })

  test('every setting the form edits still reaches the update', async () => {
    const form = {
      providerType: 'openai_compatible', name: 'n', apiKey: 'sk-typed', baseUrl: PROVIDER.baseUrl,
      modelIdentifier: 'm', defaultHeaders: { 'X-A': 'b' }, timeout: 30, temperature: 0.1, maxTokens: 100,
      sslVerify: false, reasoningEnabled: true, reasoningEffort: 'low', awsRegion: 'eu-west-1',
      awsAccessKeyId: 'AK', awsSecretKey: 'SK', awsBearerToken: 'BT',
    }
    const res = await PUT(put(form), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data).toEqual(form)
  })
})

describe('Extra Headers values: masked on read, kept when sent back masked, re-entered on a new endpoint (review of 1.6)', () => {
  const HEADER = 'Bearer hdr-SECRET-77770001'
  const WITH_HEADERS = { ...PROVIDER, defaultHeaders: { Authorization: HEADER } }
  beforeEach(() => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockFindFirst.mockResolvedValue(WITH_HEADERS)
    mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...WITH_HEADERS, ...data }))
  })

  test('GET masks every header value for a browser caller', async () => {
    mockIsInternal.mockReturnValue(false)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1'), params('victim', 'p1'))
    const text = await res.text()
    expect(text).not.toContain(HEADER)
    expect(JSON.parse(text).defaultHeaders).toEqual({ Authorization: '••••••••0001' })
  })

  test('a save that sends the header back masked keeps the stored value, and answers it masked', async () => {
    const res = await PUT(put({ name: 'renamed', defaultHeaders: { Authorization: '••••••••0001', 'X-New': 'typed' } }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.defaultHeaders).toEqual({ Authorization: HEADER, 'X-New': 'typed' })
    expect(await res.text()).not.toContain(HEADER)
  })

  test('a new base URL with the header sent back masked is 400 naming it; nothing is written', async () => {
    const res = await PUT(put({ baseUrl: 'https://elsewhere.example.net/v1', defaultHeaders: { Authorization: '••••••••0001' } }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(JSON.parse(text)).toMatchObject({ code: 'secret_reentry_required', fields: ['apiKey', 'defaultHeaders.Authorization'] })
    expect(text).not.toContain(HEADER)
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('PUT provider - re-pointing a saved provider takes the password too (ID-25, review of 1.6)', () => {
  beforeEach(() => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    mockStepUp.mockClear()
  })

  test('a new base URL with a new key and no password: 403 step_up_required, nothing written', async () => {
    const res = await PUT(put({ baseUrl: 'https://collector.example.net/v1', apiKey: 'sk-junk' }), params('victim', 'p1'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_required')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a wrong password: 403 step_up_failed, nothing written', async () => {
    const res = await PUT(put({ baseUrl: 'https://collector.example.net/v1', apiKey: 'sk-junk', stepUpPassword: 'guess' }), params('victim', 'p1'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_failed')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('a new type is re-pointing too; the right password saves, and is never written', async () => {
    mockFindFirst.mockResolvedValue({ ...PROVIDER, providerType: 'openai', baseUrl: '', apiKey: '' })
    expect((await PUT(put({ providerType: 'openai_compatible', baseUrl: 'https://llm.example.net/v1' }), params('victim', 'p1'))).status).toBe(403)
    const res = await PUT(put({ providerType: 'openai_compatible', baseUrl: 'https://llm.example.net/v1', stepUpPassword: 'right-password' }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect('stepUpPassword' in mockUpdate.mock.calls[0][0].data).toBe(false)
  })

  test('re-entry is asked first: a masked key with a new base URL is 400 before any password', async () => {
    const res = await PUT(put({ baseUrl: 'https://collector.example.net/v1', apiKey: '••••••••1234' }), params('victim', 'p1'))
    expect(res.status).toBe(400)
    expect(mockStepUp).not.toHaveBeenCalled()
  })

  test('a save that keeps the endpoint asks for no password', async () => {
    const res = await PUT(put({ ...PROVIDER, apiKey: '••••••••1234', name: 'renamed' }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockStepUp).not.toHaveBeenCalled()
  })

  test('the internal key has no password to give: it re-points without one', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await PUT(put({ baseUrl: 'https://llm.example.net/v1', apiKey: 'sk-new' }), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockStepUp).not.toHaveBeenCalled()
  })
})
