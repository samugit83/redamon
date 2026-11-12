/**
 * Tests for POST /api/users/[id]/tradecraft-resources/[resourceId]/verify.
 *
 * This route proxies to the agent's /tradecraft/verify endpoint. The new
 * behavior is that it forwards the resource's persisted `llmModel` as the
 * agent's `model` field — that's the load-bearing wire that prevents the
 * agent from falling back to its (potentially broken) default chat model
 * after a container restart (the 401 bug we hit).
 *
 * What this asserts:
 *   1. The fetch to the agent includes `model: <existing.llmModel>`.
 *   2. When the persisted llmModel is empty (legacy row), `model: ''` is
 *      sent — the agent then falls back to orchestrator.llm via the
 *      back-compat branch. (Same Python-side behavior covered in
 *      agentic/tests/test_tradecraft_verify_model_param.py.)
 *   3. The verify response from the agent is persisted back to Prisma
 *      (summary / sitemap / resource_type / lastVerifiedAt).
 *   4. Resource not owned by the user → 404.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const mockFindFirst = vi.fn()
const mockUpdate = vi.fn()
const mockUserSettingsFindUnique = vi.fn()

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn().mockResolvedValue(null), isInternalRequest: vi.fn().mockReturnValue(false) }))

vi.mock('@/lib/prisma', () => ({
  default: {
    userTradecraftResource: {
      findFirst: (...a: unknown[]) => mockFindFirst(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
    },
    userSettings: {
      findUnique: (...a: unknown[]) => mockUserSettingsFindUnique(...a),
    },
  },
}))

import { NextRequest } from 'next/server'
import * as route from './route'

const PARAMS = (resId = 'res-1') => ({
  params: Promise.resolve({ id: 'user-1', resourceId: resId }),
})

function makePost(body: unknown = {}): NextRequest {
  return new NextRequest(
    'http://webapp.test/api/users/user-1/tradecraft-resources/res-1/verify',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  )
}

const EXISTING_WITH_MODEL = {
  id: 'res-1', userId: 'user-1', slug: 'hacktricks',
  name: 'HackTricks', url: 'https://book.hacktricks.wiki',
  llmModel: 'bedrock/minimax.minimax-m2.5',
  githubTokenOverride: '',
  resourceType: 'mkdocs-wiki', summary: '', sitemap: {},
  crawlStoppedBecause: '', crawlStats: {},
  enabled: true, lastError: '',
}

const EXISTING_LEGACY_NO_MODEL = {
  ...EXISTING_WITH_MODEL,
  id: 'res-legacy',
  llmModel: '', // legacy row, written before the column existed
}

const EXISTING_WITH_GH_TOKEN = {
  ...EXISTING_WITH_MODEL,
  id: 'res-gh',
  githubTokenOverride: 'ghp_per_resource_token',
}

let capturedFetch: { url: string; init: RequestInit } | null = null

function installFetchStub(response: unknown, ok = true): void {
  capturedFetch = null
  global.fetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    capturedFetch = { url: String(url), init: init ?? {} }
    return new Response(JSON.stringify(response), {
      status: ok ? 200 : 503,
      headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch
}

beforeEach(() => {
  mockFindFirst.mockReset()
  mockUpdate.mockReset().mockImplementation(async (args: unknown) => {
    const { where, data } = args as { where: { id: string }; data: Record<string, unknown> }
    return { id: where.id, ...data }
  })
  mockUserSettingsFindUnique.mockReset().mockResolvedValue(null)
  capturedFetch = null
})

afterEach(() => {
  vi.restoreAllMocks()
})

// -------------------------------------------------------------------------
// Forwarding the model field
// -------------------------------------------------------------------------

describe('verify route forwards model field to agent', () => {
  test('agent /tradecraft/verify receives model = existing.llmModel', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    installFetchStub({
      summary: 's', resource_type: 'mkdocs-wiki', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(200)
    expect(capturedFetch).not.toBeNull()
    expect(capturedFetch!.url).toContain('/tradecraft/verify')
    const body = JSON.parse(String(capturedFetch!.init.body))
    expect(body.model).toBe('bedrock/minimax.minimax-m2.5')
    expect(body.url).toBe('https://book.hacktricks.wiki')
    expect(body.user_id).toBe('user-1')
  })

  test('legacy row with empty llmModel forwards model="" to agent (back-compat)', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_LEGACY_NO_MODEL)
    installFetchStub({
      summary: 's', resource_type: 'mkdocs-wiki', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const r = await route.POST(makePost() as never, PARAMS('res-legacy') as never)
    expect(r.status).toBe(200)
    const body = JSON.parse(String(capturedFetch!.init.body))
    expect(body.model).toBe('')
  })

  test('force flag is propagated', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    installFetchStub({
      summary: 's', resource_type: 'mkdocs-wiki', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const r = await route.POST(makePost({ force: true }) as never, PARAMS() as never)
    expect(r.status).toBe(200)
    const body = JSON.parse(String(capturedFetch!.init.body))
    expect(body.force).toBe(true)
  })

  test('agent call carries the internal key the agent route now requires', async () => {
    vi.stubEnv('INTERNAL_API_KEY', 'test-internal-key')
    try {
      mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
      installFetchStub({
        summary: 's', resource_type: 'mkdocs-wiki', sitemap: {},
        crawl_stopped_because: '', crawl_stats: {}, last_error: '',
      })
      const r = await route.POST(makePost() as never, PARAMS() as never)
      expect(r.status).toBe(200)
      const headers = capturedFetch!.init.headers as Record<string, string>
      expect(headers['x-internal-key']).toBe('test-internal-key')
      expect(headers['Content-Type']).toBe('application/json')
    } finally {
      vi.unstubAllEnvs()
    }
  })
})

// -------------------------------------------------------------------------
// GitHub token resolution (regression — was already there but now lives
// alongside the model field, so we lock the contract in)
// -------------------------------------------------------------------------

describe('verify route github_token resolution', () => {
  test('per-resource override token takes precedence', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_GH_TOKEN)
    mockUserSettingsFindUnique.mockResolvedValueOnce({
      githubAccessToken: 'user-level-token-should-not-be-used',
    })
    installFetchStub({
      summary: '', resource_type: 'github-repo', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const r = await route.POST(makePost() as never, PARAMS('res-gh') as never)
    expect(r.status).toBe(200)
    const body = JSON.parse(String(capturedFetch!.init.body))
    expect(body.github_token).toBe('ghp_per_resource_token')
  })

  test('falls back to user-level github token when no override', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    mockUserSettingsFindUnique.mockResolvedValueOnce({
      githubAccessToken: 'user-level-token',
    })
    installFetchStub({
      summary: '', resource_type: 'github-repo', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(200)
    const body = JSON.parse(String(capturedFetch!.init.body))
    expect(body.github_token).toBe('user-level-token')
  })

  test('empty string when neither token is configured', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    mockUserSettingsFindUnique.mockResolvedValueOnce(null)
    installFetchStub({
      summary: '', resource_type: 'mkdocs-wiki', sitemap: {},
      crawl_stopped_because: '', crawl_stats: {}, last_error: '',
    })
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(200)
    const body = JSON.parse(String(capturedFetch!.init.body))
    expect(body.github_token).toBe('')
  })
})

// -------------------------------------------------------------------------
// Agent response handling
// -------------------------------------------------------------------------

describe('verify route persists agent response', () => {
  test('successful verify writes summary + sitemap + resource_type + lastVerifiedAt', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    installFetchStub({
      summary: 'Big summary text',
      resource_type: 'agentic-crawl',
      sitemap: { links: [{ title: 't', path: '/p' }] },
      crawl_stopped_because: 'frontier empty',
      crawl_stats: { pages_fetched: 5 },
      last_error: '',
    })
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(200)
    expect(mockUpdate).toHaveBeenCalledTimes(1)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.summary).toBe('Big summary text')
    expect(args.data.resourceType).toBe('agentic-crawl')
    expect(args.data.crawlStoppedBecause).toBe('frontier empty')
    expect(args.data.lastVerifiedAt).toBeInstanceOf(Date)
  })

  test('agent 5xx response writes a safe lastError and answers 502 with the agent status', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    installFetchStub({ error: 'LLM not configured: Error code: 401 - key sk-live-abc invalid' }, /*ok=*/false)
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(502)
    expect(await r.json()).toEqual({
      error: 'The agent could not verify this resource', code: 'agent_error', upstreamStatus: 503,
    })
    expect(mockUpdate).toHaveBeenCalledTimes(1)
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    // The list renders lastError; the agent's own text can quote a provider key.
    expect(args.data.lastError).toBe('verify failed (agent_error, agent HTTP 503)')
  })

  test('an agent that never answered: 503 with the errno, and the row says why', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    const err = new TypeError('fetch failed')
    ;(err as TypeError & { cause?: unknown }).cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
    global.fetch = vi.fn(async () => { throw err }) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(503)
    expect(await r.json()).toEqual({
      error: 'Failed to verify tradecraft resource', code: 'agent_unreachable', cause: 'ECONNREFUSED',
    })
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.lastError).toBe('verify failed (agent_unreachable, ECONNREFUSED)')
  })

  test('a verify that timed out: 504, and the row says so', async () => {
    mockFindFirst.mockResolvedValueOnce(EXISTING_WITH_MODEL)
    global.fetch = vi.fn(async () => { throw new DOMException('The operation was aborted due to timeout', 'TimeoutError') }) as typeof fetch
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const r = await route.POST(makePost() as never, PARAMS() as never)
    expect(r.status).toBe(504)
    expect((await r.json()).code).toBe('agent_timeout')
    const args = mockUpdate.mock.calls[0]?.[0] as { data: Record<string, unknown> }
    expect(args.data.lastError).toBe('verify failed (agent_timeout)')
  })

  test('resource not found returns 404', async () => {
    mockFindFirst.mockResolvedValueOnce(null)
    const r = await route.POST(makePost() as never, PARAMS('missing') as never)
    expect(r.status).toBe(404)
  })
})
