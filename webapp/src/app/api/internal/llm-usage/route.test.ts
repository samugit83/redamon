/**
 * /api/internal/llm-usage (step 6.11, GV-12): the agent reads a person's daily budget on instance LLM
 * providers and reports its counts, each for the person who ran the calls.
 *
 * - the usage route answers with the allowlist enforced: master key only (the scanner key, a browser
 *   and no key are 401), and its two methods are on the middleware's INTERNAL_ALLOWLIST;
 * - usage reported and attributed: each entry adds to that person's row of the day, created when
 *   missing; an account deleted since is dropped, not an error; malformed reports are 400;
 * - the budget is the person's `llmDailyCalls` quota and the day's stored count;
 * - switch off: unlimited, nothing read or written.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/internal/llm-usage/route.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  rows: new Map<string, number>(),
  users: new Set(['alice', 'bob']),
  limits: new Map<string, number | null>(),
  now: new Date('2026-11-13T12:00:00.000Z'),
}))
const key = (w: { userId: string; day: Date; kind: string }) => `${w.userId}|${w.day.toISOString().slice(0, 10)}|${w.kind}`

vi.mock('@/lib/authz/clock', () => ({ now: () => h.now }))
vi.mock('@/lib/authz/quotas', () => ({ quotaLimit: vi.fn(async (id: string) => h.limits.get(id) ?? null) }))
vi.mock('@/lib/prisma', async () => {
  const { Prisma } = await import('@prisma/client')
  return {
    default: {
      quotaUsage: {
        findUnique: vi.fn(async ({ where }: { where: { userId_day_kind: { userId: string; day: Date; kind: string } } }) => {
          const n = h.rows.get(key(where.userId_day_kind))
          return n === undefined ? null : { count: n }
        }),
        upsert: vi.fn(async ({ where, create, update }: {
          where: { userId_day_kind: { userId: string; day: Date; kind: string } }
          create: { count: number }
          update: { count: { increment: number } }
        }) => {
          const w = where.userId_day_kind
          if (!h.users.has(w.userId)) throw new Prisma.PrismaClientKnownRequestError('Foreign key constraint failed', { code: 'P2003', clientVersion: 'test' })
          const k = key(w)
          h.rows.set(k, h.rows.has(k) ? h.rows.get(k)! + update.count.increment : create.count)
          return {}
        }),
      },
    },
  }
})

import prisma from '@/lib/prisma'
import { setFlagsForTests } from '@/lib/authz/flags'
import { internalKeyRouteAllowed } from '@/middleware'
import { GET, POST } from './route'

const MASTER = 'master-key-for-tests-0123456789'
const req = (method: string, query = '', body?: unknown, headers: Record<string, string> = { 'x-internal-key': MASTER }) =>
  new NextRequest(`http://webapp/api/internal/llm-usage${query}`, {
    method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })

beforeEach(() => {
  h.rows = new Map()
  h.limits = new Map([['alice', 3]])
  vi.stubEnv('INTERNAL_API_KEY', MASTER)
  vi.stubEnv('SCANNER_API_KEY', 'scanner-key-for-tests-012345')
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  vi.mocked(prisma.quotaUsage.findUnique).mockClear()
  vi.mocked(prisma.quotaUsage.upsert).mockClear()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe('the usage route answers with the allowlist enforced', () => {
  test.each([
    ['no key', {}],
    ['the scanner key', { 'x-internal-key': 'scanner-key-for-tests-012345' }],
    ['a wrong key', { 'x-internal-key': 'nope' }],
  ])('%s: 401 for both methods, nothing read or written', async (_n, headers) => {
    expect((await GET(req('GET', '?userId=alice', undefined, headers))).status).toBe(401)
    expect((await POST(req('POST', '', { counts: [] }, headers))).status).toBe(401)
    expect(prisma.quotaUsage.findUnique).not.toHaveBeenCalled()
    expect(prisma.quotaUsage.upsert).not.toHaveBeenCalled()
  })

  test('both methods are on the internal-key allowlist', () => {
    expect(internalKeyRouteAllowed('GET', '/api/internal/llm-usage')).toBe(true)
    expect(internalKeyRouteAllowed('POST', '/api/internal/llm-usage')).toBe(true)
  })
})

describe('the budget', () => {
  test("the person's llmDailyCalls and today's stored count", async () => {
    h.rows.set('alice|2026-11-13|llm_instance_calls', 2)
    h.rows.set('alice|2026-11-12|llm_instance_calls', 40)
    expect(await (await GET(req('GET', '?userId=alice'))).json()).toEqual({ limit: 3, used: 2 })
    expect(await (await GET(req('GET', '?userId=bob'))).json()).toEqual({ limit: null, used: 0 })
  })

  test('no userId: 400', async () => {
    expect((await GET(req('GET', ''))).status).toBe(400)
  })
})

describe('usage reported and attributed', () => {
  test('each entry adds to its person\'s row of the day, created when missing', async () => {
    h.rows.set('alice|2026-11-13|llm_instance_calls', 2)
    const res = await POST(req('POST', '', { counts: [
      { userId: 'alice', day: '2026-11-13', count: 3 },
      { userId: 'bob', day: '2026-11-12', count: 1 },
    ] }))
    expect(await res.json()).toEqual({ recorded: 2 })
    expect(h.rows.get('alice|2026-11-13|llm_instance_calls')).toBe(5)
    expect(h.rows.get('bob|2026-11-12|llm_instance_calls')).toBe(1)
  })

  test('an account deleted since is dropped and logged, the rest recorded', async () => {
    const res = await POST(req('POST', '', { counts: [
      { userId: 'gone', day: '2026-11-13', count: 4 },
      { userId: 'alice', day: '2026-11-13', count: 1 },
    ] }))
    expect(await res.json()).toEqual({ recorded: 1 })
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] llm_usage_dropped: account gone'))
  })

  test.each([
    ['no list', {}],
    ['an old day', { counts: [{ userId: 'alice', day: '2026-11-01', count: 1 }] }],
    ['a future day', { counts: [{ userId: 'alice', day: '2026-11-14', count: 1 }] }],
    ['a zero count', { counts: [{ userId: 'alice', day: '2026-11-13', count: 0 }] }],
    ['a fractional count', { counts: [{ userId: 'alice', day: '2026-11-13', count: 1.5 }] }],
    ['no person', { counts: [{ day: '2026-11-13', count: 1 }] }],
  ])('%s: 400, nothing written', async (_n, body) => {
    const res = await POST(req('POST', '', body))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('invalid_usage')
    expect(prisma.quotaUsage.upsert).not.toHaveBeenCalled()
  })
})

describe('switch off', () => {
  test('unlimited and nothing read; a report records nothing', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    expect(await (await GET(req('GET', '?userId=alice'))).json()).toEqual({ limit: null, used: 0 })
    expect(await (await POST(req('POST', '', { counts: [{ userId: 'alice', day: '2026-11-13', count: 1 }] }))).json()).toEqual({ recorded: 0 })
    expect(prisma.quotaUsage.findUnique).not.toHaveBeenCalled()
    expect(prisma.quotaUsage.upsert).not.toHaveBeenCalled()
  })
})
