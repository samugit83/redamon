/**
 * Traffic routes on a DB or body-store failure: a fixed sentence plus the Prisma
 * code or errno, never the raw message (it can quote a filter value, a host or a
 * captured body path).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/traffic/[projectId]/trafficRouteErrors.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const { db, readBody } = vi.hoisted(() => ({
  db: {
    capturedHttpTransaction: {
      findMany: vi.fn(),
      count: vi.fn(),
      findFirst: vi.fn(),
      deleteMany: vi.fn(),
    },
  },
  readBody: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({ default: db }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }),
  requireProjectAccess: vi.fn().mockResolvedValue({ project: { id: 'p1', userId: 'u1' } }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))
vi.mock('@/lib/captureBodies', () => ({
  gcOrphanBodies: vi.fn().mockResolvedValue({ deleted: 0 }),
  readCapturedBody: (...a: unknown[]) => readBody(...a),
}))

import { GET as LIST, DELETE } from './route'
import { GET as DETAIL } from './[id]/route'
import { GET as FACETS } from './facets/route'
import { GET as EXPORT } from './export/route'
import { gcOrphanBodies } from '@/lib/captureBodies'

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const P2024 = () => Object.assign(new Error('Timed out fetching a new connection; host=secret.target.example'), { code: 'P2024' })

beforeEach(() => {
  vi.clearAllMocks()
  for (const mock of Object.values(db.capturedHttpTransaction)) mock.mockReset()
  readBody.mockReset()
  vi.mocked(gcOrphanBodies).mockReset()
  vi.mocked(gcOrphanBodies).mockResolvedValue({ deleted: 0 })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('traffic routes answer {error, code}', () => {
  test('list: a statement timeout on the body search keeps the fixed message and adds the Prisma code', async () => {
    db.capturedHttpTransaction.findMany.mockRejectedValue(P2024())
    db.capturedHttpTransaction.count.mockResolvedValue(0)
    const res = await LIST(new NextRequest('http://x/api/traffic/p1?bodyq=secret.target.example'), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to list traffic', code: 'P2024' })
    expect(JSON.stringify(body)).not.toContain('target.example')
  })

  test('delete: the Prisma code reaches the client', async () => {
    db.capturedHttpTransaction.findMany.mockRejectedValue(P2024())
    const res = await DELETE(new NextRequest('http://x', { method: 'DELETE', body: JSON.stringify({ ids: ['a'] }) }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete traffic', code: 'P2024' })
  })

  test('detail: a body-store read failure carries the errno', async () => {
    db.capturedHttpTransaction.findFirst.mockResolvedValue({ id: 't1', reqBody: null, reqBodyRef: 'abc', respBody: 'x', respBodyRef: null })
    readBody.mockRejectedValue(Object.assign(new Error("ENOENT: no such file '/data/bodies/abc'"), { code: 'ENOENT' }))
    const res = await DETAIL(new NextRequest('http://x'), { params: Promise.resolve({ projectId: 'p1', id: 't1' }) })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to load transaction', code: 'ENOENT' })
  })

  test('facets: the Prisma code reaches the client', async () => {
    db.capturedHttpTransaction.findMany.mockRejectedValue(P2024())
    const res = await FACETS(new NextRequest('http://x'), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to load facets', code: 'P2024' })
  })
})

function remove(body?: unknown) {
  return DELETE(new NextRequest('http://x', {
    method: 'DELETE',
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }), params)
}

function exportTraffic(format: string) {
  return EXPORT(new NextRequest(`http://x?format=${format}`), params)
}

describe('strict traffic delete bodies', () => {
  const invalidBodies: unknown[] = [
    undefined, {}, null, [], { ids: [] }, { ids: [1] }, { ids: ['a', null] },
    { ids: [''] }, { ids: Array(1001).fill('a') }, { filter: {} },
    { filter: [] }, { filter: { typo: 'x' } }, { filter: { host: 1 } },
    { filter: { host: '' } }, { filter: { source: 'both' } },
    { filter: { only5xx: 'false' } }, { filter: { only5xx: true } },
    { filter: { statusClass: '6xx' } }, { filter: { from: 'invalid' } },
    { filter: { tool: ', , ' } }, { filter: { page: '1' } },
    { ids: ['a'], extra: true }, { ids: ['a'], all: true }, { all: false },
    { all: true, userId: 'other' },
  ]
  test.each(invalidBodies.map(body => [body]))('rejects invalid body %j without touching data', async body => {
    const res = await remove(body)
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_delete_body' })
    expect(db.capturedHttpTransaction.findMany).not.toHaveBeenCalled()
    expect(db.capturedHttpTransaction.deleteMany).not.toHaveBeenCalled()
    expect(gcOrphanBodies).not.toHaveBeenCalled()
  })

  test('malformed JSON cannot delete data', async () => {
    const res = await DELETE(new NextRequest('http://x', { method: 'DELETE', body: '{' }), params)
    expect(res.status).toBe(400)
    expect(db.capturedHttpTransaction.deleteMany).not.toHaveBeenCalled()
  })

  test.each([{ all: true }, { ids: ['a'] }, { filter: { host: 'fixture.example' } }])('accepts explicit selection %j', async body => {
    db.capturedHttpTransaction.findMany.mockResolvedValue([])
    const res = await remove(body)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ deleted: 0, blobsDeleted: 0 })
    expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ projectId: 'p1', userId: 'u1' }),
    }))
  })
})

describe('paged traffic exports', () => {
  test.each(['json', 'csv'])('keeps sensitive exceptions out of %s, including after a page', async format => {
    const secret = 'SYNTHETIC_PRIVATE_VALUE_123'
    const error = new Error(secret)
    db.capturedHttpTransaction.findMany
      .mockResolvedValueOnce(Array.from({ length: 1000 }, (_, i) => ({ id: `row-${i}` })))
      .mockRejectedValueOnce(error)
    const res = await exportTraffic(format)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain(secret)
    expect(text).toContain('export_failed')
    expect(text).toContain('Failed to export traffic')
    if (format === 'json') {
      expect(JSON.parse(text)).toMatchObject({ count: 1000, truncated: false, error: 'Failed to export traffic', code: 'export_failed' })
    }
    expect(console.error).toHaveBeenCalledWith('Failed to export traffic:', error)
  })

  test.each(['json', 'csv'])('empty %s export stays valid', async format => {
    db.capturedHttpTransaction.findMany.mockResolvedValue([])
    const res = await exportTraffic(format)
    const text = await res.text()
    if (format === 'json') expect(JSON.parse(text)).toEqual({ rows: [], count: 0, truncated: false })
    else expect(text).toMatch(/^id,startedAt,source,/)
  })

  test('CSV selects only exported columns and still escapes cells', async () => {
    db.capturedHttpTransaction.findMany.mockResolvedValue([{ id: 'a', host: '=fixture', path: '/a,b' }])
    const text = await (await exportTraffic('csv')).text()
    const { select } = db.capturedHttpTransaction.findMany.mock.calls[0][0]
    expect(Object.keys(select)).toEqual(text.split('\n')[0].split(','))
    expect(select).not.toHaveProperty('reqBody')
    expect(select).not.toHaveProperty('respBody')
    expect(text).toContain("'=fixture")
    expect(text).toContain('"/a,b"')
  })

  test('waits for demand and stops fetching after cancellation between pages', async () => {
    db.capturedHttpTransaction.findMany.mockResolvedValue(Array.from({ length: 1000 }, (_, i) => ({ id: `row-${i}` })))
    const res = await exportTraffic('json')
    expect(db.capturedHttpTransaction.findMany).not.toHaveBeenCalled()
    const reader = res.body!.getReader()
    await reader.read()
    expect(db.capturedHttpTransaction.findMany).not.toHaveBeenCalled()
    await reader.read()
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledTimes(1)
    await reader.cancel()
    expect(await reader.read()).toEqual({ done: true, value: undefined })
    expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledTimes(1)
  })

  test('cancellation during an in-flight page discards its result', async () => {
    let resolvePage!: (rows: { id: string }[]) => void
    db.capturedHttpTransaction.findMany.mockImplementation(() => new Promise(resolve => { resolvePage = resolve }))
    const reader = (await exportTraffic('json')).body!.getReader()
    await reader.read()
    const pendingRead = reader.read()
    await vi.waitFor(() => expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledTimes(1))
    await reader.cancel()
    resolvePage([{ id: 'discarded' }])
    expect(await pendingRead).toEqual({ done: true, value: undefined })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledTimes(1)
    expect(console.error).not.toHaveBeenCalled()
  })

  test.each(['json', 'csv'])('caps %s at 50000 rows and marks truncation', async format => {
    let page = 0
    db.capturedHttpTransaction.findMany.mockImplementation(async () => {
      const rows = Array.from({ length: 1000 }, (_, i) => ({ id: `row-${page * 1000 + i}` }))
      page++
      return rows
    })
    const text = await (await exportTraffic(format)).text()
    expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledTimes(50)
    expect(db.capturedHttpTransaction.findMany.mock.calls[1][0]).toMatchObject({ cursor: { id: 'row-999' }, skip: 1 })
    if (format === 'json') {
      const body = JSON.parse(text)
      expect(body.rows).toHaveLength(50000)
      expect(body).toMatchObject({ count: 50000, truncated: true })
    } else expect(text).toContain('# TRUNCATED at 50000 rows')
  })
})

describe('bounded traffic deletion', () => {
  test('deletes and garbage-collects more than one batch with a stable seek after deletion', async () => {
    let remaining = Array.from({ length: 501 }, (_, i) => ({
      id: `row-${String(i).padStart(4, '0')}`, reqBodyRef: `req-${i}`, respBodyRef: null,
    }))
    db.capturedHttpTransaction.findMany.mockImplementation(async ({ where, take }) => {
      const cursor = where.AND?.[1].id.gt
      return remaining.filter(r => !cursor || r.id > cursor).slice(0, take)
    })
    db.capturedHttpTransaction.deleteMany.mockImplementation(async ({ where }) => {
      const ids = where.id.in as string[]
      remaining = remaining.filter(r => !ids.includes(r.id))
      return { count: ids.length }
    })
    vi.mocked(gcOrphanBodies).mockImplementation(async shas => {
      expect(remaining.some(r => shas!.includes(r.reqBodyRef))).toBe(false)
      return { deleted: shas!.filter(Boolean).length }
    })
    const res = await remove({ all: true })
    expect(await res.json()).toEqual({ deleted: 501, blobsDeleted: 501 })
    expect(remaining).toEqual([])
    expect(db.capturedHttpTransaction.findMany).toHaveBeenCalledTimes(2)
    expect(db.capturedHttpTransaction.findMany.mock.calls[1][0]).toMatchObject({
      where: { AND: [{ projectId: 'p1', userId: 'u1' }, { id: { gt: 'row-0499' } }] },
      take: 500, select: { id: true, reqBodyRef: true, respBodyRef: true },
    })
    expect(db.capturedHttpTransaction.deleteMany.mock.calls.map(([args]) => args.where.id.in.length)).toEqual([500, 1])
    expect(vi.mocked(gcOrphanBodies).mock.calls.map(([shas]) => shas!.length)).toEqual([1000, 2])
    for (const [args] of db.capturedHttpTransaction.deleteMany.mock.calls) {
      expect(args.where).toMatchObject({ projectId: 'p1', userId: 'u1' })
    }
  })

  test('a failed GC leaves no live rows pointing at removed bodies and later batches continue', async () => {
    const batch = Array.from({ length: 500 }, (_, i) => ({ id: `row-${i}`, reqBodyRef: 'body', respBodyRef: null }))
    db.capturedHttpTransaction.findMany.mockResolvedValueOnce(batch)
      .mockResolvedValueOnce([{ id: 'zz-last', reqBodyRef: 'last-body', respBodyRef: null }])
    db.capturedHttpTransaction.deleteMany.mockResolvedValueOnce({ count: 500 }).mockResolvedValueOnce({ count: 1 })
    vi.mocked(gcOrphanBodies).mockRejectedValueOnce(new Error('SYNTHETIC_GC_SECRET')).mockResolvedValueOnce({ deleted: 1 })
    const res = await remove({ all: true })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ deleted: 501, blobsDeleted: 1 })
    expect(db.capturedHttpTransaction.deleteMany).toHaveBeenCalledTimes(2)
    expect(db.capturedHttpTransaction.deleteMany.mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(gcOrphanBodies).mock.invocationCallOrder[0])
  })

  test('a failed row deletion never removes bodies', async () => {
    db.capturedHttpTransaction.findMany.mockResolvedValue([{ id: 'a', reqBodyRef: 'body', respBodyRef: null }])
    db.capturedHttpTransaction.deleteMany.mockRejectedValue(P2024())
    const res = await remove({ ids: ['a'] })
    expect(res.status).toBe(500)
    expect(gcOrphanBodies).not.toHaveBeenCalled()
  })
})
