/**
 * Bulk archive download: streamed, always an attachment.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn(async () => null) }))

import { POST } from './route'

let agentBody: ReadableStream<Uint8Array>

const req = (body: unknown) => new NextRequest('http://x/x', {
  method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
})

beforeEach(() => {
  agentBody = new ReadableStream({ start(c) { c.enqueue(new Uint8Array([9])); c.close() } })
  vi.stubGlobal('fetch', vi.fn(async () => new Response(agentBody, {
    status: 200, headers: { 'Content-Type': 'image/svg+xml', 'Content-Disposition': 'inline' },
  })))
})

describe('POST /api/agent/workspace/bulk-archive', () => {
  test('streams agent body without buffering', async () => {
    const res = await POST(req({ projectId: 'p1', paths: ['a'] }))
    expect(res.body).toBe(agentBody)
  })

  test('agent Content-Disposition is never forwarded; attachment with nosniff', async () => {
    const res = await POST(req({ projectId: 'p1', paths: ['a'], archiveName: '../x"y', format: 'zip' }))
    expect(res.headers.get('Content-Disposition')).toMatch(/^attachment; filename="xy\.zip"/)
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
  })
})
