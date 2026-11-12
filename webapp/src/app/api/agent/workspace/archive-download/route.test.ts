/**
 * Folder archive download: streamed, always an attachment, with a long wait for
 * the first byte (the agent builds the archive before answering).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn(async () => null) }))

import { GET } from './route'

let agentBody: ReadableStream<Uint8Array>
let agentHeaders: Record<string, string>

beforeEach(() => {
  agentBody = new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1, 2, 3])); c.close() } })
  agentHeaders = { 'Content-Type': 'application/gzip', 'Content-Disposition': 'inline; filename="x.html"' }
  vi.stubGlobal('fetch', vi.fn(async () => new Response(agentBody, { status: 200, headers: agentHeaders })))
})

describe('GET /api/agent/workspace/archive-download', () => {
  test('streams agent body without buffering', async () => {
    const res = await GET(new NextRequest('http://x/x?projectId=p1&path=uploads/site'))
    expect(res.status).toBe(200)
    expect(res.body).toBe(agentBody)
  })

  test('agent Content-Disposition is never forwarded; attachment with nosniff', async () => {
    const res = await GET(new NextRequest('http://x/x?projectId=p1&path=uploads/site&format=zip'))
    expect(res.headers.get('Content-Disposition')).toMatch(/^attachment; filename="site\.zip"/)
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
  })

  test('the root folder gets a fallback name', async () => {
    const res = await GET(new NextRequest('http://x/x?projectId=p1&path=.'))
    expect(res.headers.get('Content-Disposition')).toMatch(/^attachment; filename="workspace\.tar\.gz"/)
  })
})
