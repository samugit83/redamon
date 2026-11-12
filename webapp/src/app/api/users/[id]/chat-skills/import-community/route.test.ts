/**
 * Import-community caps repro — POST /api/users/[id]/chat-skills/import-community.
 *
 * The bug: bulk community import wrote skills straight to the DB, bypassing the
 * content-size, per-user-count, and description-length caps the manual POST
 * path enforces. Fix: mirror those caps in the import loop.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireUserAccess = vi.fn()
const mockFindMany = vi.fn()
const mockCreate = vi.fn()
const mockFetch = vi.fn()

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userChatSkill: {
      findMany: (...a: unknown[]) => mockFindMany(...a),
      create: (...a: unknown[]) => mockCreate(...a),
    },
  },
}))

import { MAX_CHAT_SKILL_CONTENT_SIZE } from '@/lib/userSkills'
import { POST } from './route'

const params = (id: string) => ({ params: Promise.resolve({ id }) })
function post(): NextRequest {
  return new NextRequest('http://x/api/users/u1/chat-skills/import-community', { method: 'POST' })
}

// catalog: 2 skills; content per id supplied by the test.
function wireFetch(catalog: Array<{ id: string; name: string }>, content: Record<string, unknown>) {
  mockFetch.mockImplementation((url: string) => {
    if (/\/skills$/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ skills: catalog }) })
    }
    const id = decodeURIComponent(url.split('/').pop() as string)
    return Promise.resolve({ ok: true, json: async () => content[id] ?? {} })
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', mockFetch)
  mockRequireUserAccess.mockResolvedValue(null) // allowed
  mockCreate.mockResolvedValue({})
})

describe('POST chat-skills/import-community — caps', () => {
  test('skips a skill whose content exceeds MAX_CHAT_SKILL_CONTENT_SIZE', async () => {
    mockFindMany.mockResolvedValue([])
    wireFetch(
      [{ id: 'big', name: 'Big' }, { id: 'ok', name: 'Ok' }],
      {
        big: { name: 'Big', description: 'd', content: 'X'.repeat(MAX_CHAT_SKILL_CONTENT_SIZE + 1) },
        ok: { name: 'Ok', description: 'd', content: 'small' },
      },
    )
    const res = await POST(post(), params('u1'))
    const body = await res.json()
    expect(body.imported).toBe(1) // only 'ok'
    expect(body.skipped).toBe(1) // 'big'
    expect(mockCreate).toHaveBeenCalledTimes(1)
    expect(mockCreate.mock.calls[0][0].data.name).toBe('Ok')
  })

  test('stops importing once the per-user ceiling (50) is reached', async () => {
    // 50 existing skills -> already at the cap, nothing new may be created.
    mockFindMany.mockResolvedValue(
      Array.from({ length: 50 }, (_, i) => ({ name: `existing-${i}` })),
    )
    wireFetch(
      [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }],
      { a: { content: 'x' }, b: { content: 'y' } },
    )
    const res = await POST(post(), params('u1'))
    const body = await res.json()
    expect(body.imported).toBe(0)
    expect(body.skipped).toBe(2)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('truncates an over-long description to 500 chars', async () => {
    mockFindMany.mockResolvedValue([])
    wireFetch(
      [{ id: 'a', name: 'A' }],
      { a: { name: 'A', description: 'D'.repeat(600), content: 'ok' } },
    )
    await POST(post(), params('u1'))
    expect(mockCreate).toHaveBeenCalledTimes(1)
    expect(mockCreate.mock.calls[0][0].data.description).toHaveLength(500)
  })

  test('each skip is counted by its reason, and skipped is their total', async () => {
    mockFindMany.mockResolvedValue([{ name: 'Dup' }])
    wireFetch(
      [{ id: 'dup', name: 'Dup' }, { id: 'big', name: 'Big' }, { id: 'empty', name: 'Empty' }, { id: 'ok', name: 'Ok' }],
      {
        big: { content: 'X'.repeat(MAX_CHAT_SKILL_CONTENT_SIZE + 1) },
        empty: { content: '' },
        ok: { content: 'small' },
      },
    )
    const body = await (await POST(post(), params('u1'))).json()
    expect(body).toEqual({
      imported: 1,
      skipped: 3,
      skippedBy: { duplicate: 1, limit: 0, fetchFailed: 0, tooLarge: 1, invalid: 1, saveFailed: 0 },
      total: 4,
    })
  })

  test('a fetch that fails is fetchFailed; a save that fails is saveFailed, logged by its code only', async () => {
    mockFindMany.mockResolvedValue([])
    mockFetch.mockImplementation((url: string) => {
      if (/\/skills$/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => ({ skills: [{ id: 'down', name: 'Down' }, { id: 'bad', name: 'Bad' }] }) })
      }
      if (url.endsWith('/down')) return Promise.resolve({ ok: false, status: 500, json: async () => ({}) })
      return Promise.resolve({ ok: true, json: async () => ({ content: 'SECRET-SKILL-TEXT' }) })
    })
    mockCreate.mockRejectedValue(Object.assign(new Error('Unique constraint on SECRET-SKILL-TEXT'), { code: 'P2002' }))
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const body = await (await POST(post(), params('u1'))).json()
    expect(body.skippedBy).toMatchObject({ fetchFailed: 1, saveFailed: 1 })
    expect(body).toMatchObject({ imported: 0, skipped: 2 })
    expect(log).toHaveBeenCalledWith('Failed to save a community chat skill:', 'P2002')
    expect(JSON.stringify(log.mock.calls)).not.toContain('SECRET-SKILL-TEXT')
    log.mockRestore()
  })

  test('the catalog failing is 502 with the agent status; nothing is created', async () => {
    mockFindMany.mockResolvedValue([])
    mockFetch.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await POST(post(), params('u1'))
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      error: 'Failed to fetch skills catalog from agent service',
      code: 'agent_error',
      upstreamStatus: 500,
    })
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('an agent that never answers is 503 agent_unreachable with the errno', async () => {
    mockFindMany.mockResolvedValue([])
    mockFetch.mockRejectedValue(Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
    }))
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await POST(post(), params('u1'))
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to fetch skills catalog from agent service',
      code: 'agent_unreachable',
      cause: 'ECONNREFUSED',
    })
    log.mockRestore()
  })

  test('a database failure is 500 with its Prisma code, never its message', async () => {
    mockFindMany.mockRejectedValue(Object.assign(new Error('SELECT secret'), { code: 'P1001' }))
    wireFetch([{ id: 'a', name: 'A' }], { a: { content: 'x' } })
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await POST(post(), params('u1'))
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error: 'Failed to import community chat skills', code: 'P1001' })
    expect(text).not.toContain('SELECT')
    log.mockRestore()
  })

  test('rejects a cross-user caller (ownership guard)', async () => {
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'forbidden' }, { status: 403 }))
    const res = await POST(post(), params('u1'))
    expect(res.status).toBe(403)
    expect(mockFetch).not.toHaveBeenCalled()
    expect(mockCreate).not.toHaveBeenCalled()
  })
})
