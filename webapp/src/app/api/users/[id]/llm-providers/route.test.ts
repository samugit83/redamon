/**
 * Unit tests for GET/POST /api/users/[id]/llm-providers — STRIDE I1.
 *
 * I1: any logged-in user could read ANOTHER user's UNMASKED provider secrets by
 * appending `?internal=true`. The fix gates unmasked rows on a valid
 * `X-Internal-Key` header (the agent) and forces browser/JWT callers to own the
 * account (or be admin), always masked. prisma + session are mocked so the
 * handler runs with no DB and no cookies.
 *
 * Run: npx vitest run "src/app/api/users/[id]/llm-providers/route.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindMany = vi.fn()
const mockCreate = vi.fn()
const mockCount = vi.fn()
const mockTransaction = vi.fn()
const mockUserFindUnique = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: {
      findMany: (...args: unknown[]) => mockFindMany(...args),
      create: (...args: unknown[]) => mockCreate(...args),
      count: (...args: unknown[]) => mockCount(...args),
    },
    $transaction: (...args: unknown[]) => mockTransaction(...args),
    user: {
      findUnique: (...args: unknown[]) => mockUserFindUnique(...args),
    },
  },
}))

vi.mock('@/lib/session', () => ({
  getSession: (...args: unknown[]) => mockGetSession(...args),
  isInternalRequest: (...args: unknown[]) => mockIsInternal(...args),
}))

import { GET, POST } from './route'

const SECRET = 'sk-SECRETKEY123456'
const PROVIDER = {
  id: 'p1',
  userId: 'victim',
  providerType: 'openai',
  name: 'OpenAI',
  apiKey: SECRET,
  awsAccessKeyId: 'AKIAEXAMPLE12345',
  awsSecretKey: 'awssecretvalue999',
  awsBearerToken: 'bearer-secret-888',
}

function req(url: string): NextRequest {
  return new NextRequest(url)
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  mockFindMany.mockReset().mockResolvedValue([PROVIDER])
  mockCreate.mockReset().mockResolvedValue({ ...PROVIDER })
  mockCount.mockReset().mockResolvedValue(0)
  // The interactive transaction hands the callback a client whose provider calls are
  // the same mocks, so the Jev POST tests below see one behaviour either way.
  mockTransaction.mockReset().mockImplementation(async (fn: (tx: unknown) => unknown) =>
    fn({ userLlmProvider: { count: mockCount, create: mockCreate } }))
  mockUserFindUnique.mockReset().mockResolvedValue({ id: 'victim' })
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
})

function postReq(id: string, body: unknown): NextRequest {
  return new NextRequest(`http://x/api/users/${id}/llm-providers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const NEW_PROVIDER = { providerType: 'openai', name: 'mine', apiKey: 'k' }

describe('GET /api/users/[id]/llm-providers — I1', () => {
  test('internal-key caller with ?internal=true → UNMASKED secrets', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/llm-providers?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(200)
    expect(text).toContain(SECRET) // agent path still works
  })

  test('internal-key caller WITHOUT ?internal=true → masked', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    const text = await res.text()
    expect(text).not.toContain(SECRET)
  })

  test('EXPLOIT: browser user requests ANOTHER user with ?internal=true → 403, no secrets', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'attacker', role: 'user' })
    const res = await GET(req('http://x/api/users/victim/llm-providers?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(403)
    expect(text).not.toContain(SECRET)
  })

  test('browser user requests OWN id → 200 masked, never the raw secret', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await GET(req('http://x/api/users/victim/llm-providers?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(200)
    expect(text).not.toContain(SECRET) // browser NEVER gets unmasked
    expect(text).toContain('3456') // masked tail present
  })

  test('admin requests another user → 200 masked', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain(SECRET)
  })

  test('no session, no internal key → 401', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue(null)
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    expect(res.status).toBe(401)
    expect(mockFindMany).not.toHaveBeenCalled()
  })
})

describe('POST /api/users/[id]/llm-providers — I1 ownership', () => {
  test('EXPLOIT: user creates a provider under ANOTHER user id → 403, no write', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'attacker', role: 'user' })
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('owner creates their own provider → 201', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalled()
  })

  test('owner persists Ollama reasoning controls', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', {
      providerType: 'openai_compatible',
      name: 'Ollama',
      baseUrl: 'http://host.docker.internal:11434/v1',
      modelIdentifier: 'gemma4:latest',
      reasoningEnabled: true,
      reasoningEffort: 'max',
    }), params('victim'))

    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        reasoningEnabled: true,
        reasoningEffort: 'max',
      }),
    }))
  })

  test('rejects an invalid reasoning effort before writing', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', {
      providerType: 'openai_compatible',
      name: 'Ollama',
      baseUrl: 'http://host.docker.internal:11434/v1',
      modelIdentifier: 'gemma4:latest',
      reasoningEnabled: true,
      reasoningEffort: 'extreme',
    }), params('victim'))

    expect(res.status).toBe(400)
    expect(mockCreate).not.toHaveBeenCalled()
    expect((await res.json()).error).toContain('low, medium, high, max')
  })

  test('S2/E2: internal-key caller can NO LONGER create providers (bypass removed) → 401, no write', async () => {
    // Was 201 (internal key bypassed ownership). Now key possession alone must
    // not be able to attach a harvestable secret to an arbitrary account.
    mockIsInternal.mockReturnValue(true)
    mockGetSession.mockResolvedValue(null)
    const res = await POST(postReq('anyuser', NEW_PROVIDER), params('anyuser'))
    expect(res.status).toBe(401)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('no session, no key → 401, no write', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue(null)
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(401)
    expect(mockCreate).not.toHaveBeenCalled()
  })
})

// Issue #173: an admin whose browser held a stale `redamon-current-user` wrote
// providers against a user id that no longer existed. The admin bypass let the
// request through, prisma raised P2003 on user_llm_providers_user_id_fkey and the
// catch-all turned it into an opaque 500 ("Failed to save provider" in the UI).
describe('POST /api/users/[id]/llm-providers — ghost user id (#173)', () => {
  test('admin writes to a user id that does not exist → 404, no write, no 500', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue(null)

    const res = await POST(postReq('ghost', NEW_PROVIDER), params('ghost'))

    expect(res.status).toBe(404)
    expect(mockCreate).not.toHaveBeenCalled()
    expect((await res.json()).error).toContain('User not found')
  })

  test('user deleted between the check and the insert (P2003) → 404, not 500', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    mockUserFindUnique.mockResolvedValue({ id: 'victim' })
    mockCreate.mockRejectedValue(Object.assign(new Error('FK violated'), { code: 'P2003' }))

    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))

    expect(res.status).toBe(404)
    expect((await res.json()).error).toContain('User not found')
  })

  test('the existence check runs AFTER the ownership gate (no id probing)', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'attacker', role: 'user' })

    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))

    expect(res.status).toBe(403)
    expect(mockUserFindUnique).not.toHaveBeenCalled()
  })
})

describe('POST /api/users/[id]/llm-providers - TypeSafe Jev', () => {
  const JEV_BODY = {
    providerType: 'jev', name: 'whatever', apiKey: '  apikey_abc_def  ',
    baseUrl: 'http://evil.example/v1', modelIdentifier: 'jev-latest',
    defaultHeaders: { 'X-Leak': '1' },
  }

  test.each(['jev', 'jev_openrouter'])('multiple named %s entries are allowed', async providerType => {
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    mockCount.mockResolvedValue(3)
    const res = await POST(postReq('victim', { ...JEV_BODY, providerType, name: 'Second entry' }), params('victim'))
    expect(res.status).toBe(201)
    expect(mockCount).not.toHaveBeenCalled()
    expect(mockCreate.mock.calls[0][0].data).toMatchObject({
      name: 'Second entry', providerType,
      baseUrl: providerType === 'jev' ? 'https://api.typesafe.ai' : 'https://openrouter.ai/api/v1',
      modelIdentifier: providerType === 'jev' ? 'jev-1.13.0' : 'typesafe/jev-1.13',
      defaultHeaders: {}, timeout: 5, sslVerify: true,
    })
  })

  test('model, transport and headers are forced; name is editable and key trimmed', async () => {
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', JEV_BODY), params('victim'))
    expect(res.status).toBe(201)
    const data = mockCreate.mock.calls[0][0].data
    expect(data).toMatchObject({
      userId: 'victim', providerType: 'jev', name: 'whatever', apiKey: 'apikey_abc_def',
      baseUrl: 'https://api.typesafe.ai', modelIdentifier: 'jev-1.13.0', defaultHeaders: {}, timeout: 5, sslVerify: true,
    })
  })

  test('a Jev row without a key is refused with 400', async () => {
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', { ...JEV_BODY, apiKey: '   ' }), params('victim'))
    expect(res.status).toBe(400)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('chat providers are not counted or limited', async () => {
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(201)
    expect(mockCount).not.toHaveBeenCalled()
  })
})

describe('POST /api/users/[id]/llm-providers - safe database failures', () => {
  test('a database failure answers its Prisma code, never the message', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    mockCreate.mockRejectedValue(Object.assign(new Error('value too long for column "apiKey" = sk-live'), { code: 'P2000' }))
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to create LLM provider', code: 'P2000' })
  })

  test('a chat provider pays for no transaction', async () => {
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(201)
    expect(mockTransaction).not.toHaveBeenCalled()
  })
})

describe('GET /api/users/[id]/llm-providers — failure', () => {
  test('a database failure answers its code, so the list says why it is empty', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    mockIsInternal.mockReturnValue(false)
    mockFindMany.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to fetch LLM providers', code: 'P1001' })
  })
})
