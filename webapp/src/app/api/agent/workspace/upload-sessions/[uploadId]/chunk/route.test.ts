/**
 * PUT /api/agent/workspace/upload-sessions/[uploadId]/chunk
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuard = vi.fn()
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))

import { PUT } from './route'

const ID = 'b'.repeat(32)
const params = (uploadId: string) => ({ params: Promise.resolve({ uploadId }) })
let calls: { url: string; init?: RequestInit }[]
let answer: () => Response

const put = (body: BodyInit, qs = 'projectId=p1&offset=0') =>
  new NextRequest(`http://x/x?${qs}`, { method: 'PUT', body })

beforeEach(() => {
  calls = []
  mockGuard.mockReset().mockResolvedValue(null)
  answer = () => new Response(JSON.stringify({ received: 3 }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return answer()
  }))
})

describe('PUT chunk', () => {
  test('forwards the bytes as octet-stream', async () => {
    const res = await PUT(put(new Uint8Array([1, 2, 3])), params(ID))
    expect(res.status).toBe(200)
    expect(calls[0].url).toContain(`/workspace/upload-sessions/${ID}/chunk?projectId=p1&offset=0`)
    expect((calls[0].init?.headers as Record<string, string>)['Content-Type']).toBe('application/octet-stream')
    expect(new Uint8Array(calls[0].init?.body as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]))
  })

  test('denied project never reaches the agent', async () => {
    mockGuard.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await PUT(put(new Uint8Array([1])), params(ID))
    expect(res.status).toBe(404)
    expect(calls).toHaveLength(0)
  })

  test('oversized chunk is 413 without calling the agent', async () => {
    const res = await PUT(put(new Uint8Array(16 * 1024 * 1024 + 1)), params(ID))
    expect(res.status).toBe(413)
    expect((await res.json()).code).toBe('chunk_too_large')
    expect(calls).toHaveLength(0)
  })

  test('bad upload id is 404', async () => {
    const res = await PUT(put(new Uint8Array([1])), params('../x'))
    expect(res.status).toBe(404)
    expect((await res.json()).code).toBe('session_not_found')
    expect(calls).toHaveLength(0)
  })

  test('agent 409 offset_mismatch passes through with its code', async () => {
    answer = () => new Response(JSON.stringify({ error: 'The chunk does not continue the upload where it stands.',
      code: 'offset_mismatch', expectedOffset: 8388608 }), { status: 409, headers: { 'Content-Type': 'application/json' } })
    const res = await PUT(put(new Uint8Array([1])), params(ID))
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.code).toBe('offset_mismatch')
    expect(body.expectedOffset).toBe(8388608)
  })
})
