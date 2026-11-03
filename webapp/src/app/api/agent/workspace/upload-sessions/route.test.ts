/**
 * POST /api/agent/workspace/upload-sessions
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuard = vi.fn()
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))

import { POST } from './route'

let calls: { url: string; init?: RequestInit }[]
const req = (body: unknown) => new NextRequest('http://x/x', {
  method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
})

beforeEach(() => {
  calls = []
  mockGuard.mockReset().mockResolvedValue(null)
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(JSON.stringify({ uploadId: 'a'.repeat(32), chunkSize: 8388608, maxBytes: 2147483648 }),
      { status: 201, headers: { 'Content-Type': 'application/json' } })
  }))
})

describe('POST upload-sessions', () => {
  test('creates the session through the agent', async () => {
    const res = await POST(req({ projectId: 'p1', destDir: 'uploads', name: 'site', size: 10, kind: 'folder' }))
    expect(res.status).toBe(201)
    expect(calls[0].url).toContain('/workspace/upload-sessions')
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      projectId: 'p1', destDir: 'uploads', name: 'site', size: 10, kind: 'folder', onConflict: 'keep_both',
    })
  })

  test('denied project never reaches the agent', async () => {
    mockGuard.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await POST(req({ projectId: 'victim', name: 'a', size: 1, kind: 'file' }))
    expect(res.status).toBe(404)
    expect(calls).toHaveLength(0)
  })

  test('invalid body is 400 with a code', async () => {
    for (const body of [{ projectId: 'p1' }, { projectId: 'p1', name: 'a', size: '1', kind: 'file' }]) {
      const res = await POST(req(body))
      expect(res.status).toBe(400)
      expect((await res.json()).code).toBe('invalid_request')
    }
    expect(calls).toHaveLength(0)
  })
})
