/**
 * agent/files download proxy — the projectId is OPTIONAL:
 *  - with projectId: enforce project ownership (guardProject)
 *  - without projectId: legacy /tmp in-chat download must still work (no 400 from
 *    the project guard)  <- regression for the scripted-guard over-block bug
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuardProject = vi.fn()
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuardProject(...a) }))

import { GET } from './route'

let fetchCalls: string[]
let fetchInits: (RequestInit | undefined)[]
let agentHeaders: Record<string, string>
let agentBody: ReadableStream<Uint8Array>
const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })

function bodyOf(text: string): ReadableStream<Uint8Array> {
  return new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(text)); c.close() } })
}

beforeEach(() => {
  fetchCalls = []
  fetchInits = []
  agentHeaders = {}
  agentBody = bodyOf('abc')
  mockGuardProject.mockReset()
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    fetchCalls.push(String(url))
    fetchInits.push(init)
    return new Response(agentBody, { status: 200, headers: agentHeaders })
  }))
})

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('GET /api/agent/files', () => {
  test('LEGACY: no projectId + valid path → guard skipped, proxies to /files', async () => {
    const res = await GET(new NextRequest('http://x/api/agent/files?path=/tmp/out.txt'))
    expect(res.status).toBe(200)
    expect(mockGuardProject).not.toHaveBeenCalled()
    expect(fetchCalls.some(u => u.includes('/files?path='))).toBe(true)
  })

  test('with projectId, owner → guard passes, proxies to workspace/download', async () => {
    mockGuardProject.mockResolvedValue(null)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=/a'))
    expect(res.status).toBe(200)
    expect(mockGuardProject).toHaveBeenCalledWith('p1')
    expect(fetchCalls.some(u => u.includes('/workspace/download?projectId=p1'))).toBe(true)
  })

  test('EXPLOIT: with projectId, cross-user → 404, no proxy', async () => {
    mockGuardProject.mockResolvedValue(NOT_FOUND)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=victimProj&path=/a'))
    expect(res.status).toBe(404)
    expect(fetchCalls).toHaveLength(0)
  })

  test('forwards the internal API key to the now-authenticated /files endpoint', async () => {
    // The legacy /files endpoint now requires require_internal_auth_only, so the
    // proxy must attach x-internal-key or it 401s once the secret is set.
    vi.stubEnv('INTERNAL_API_KEY', 'test-key-123')
    const res = await GET(new NextRequest('http://x/api/agent/files?path=/tmp/out.txt'))
    expect(res.status).toBe(200)
    const headers = (fetchInits[0]?.headers ?? {}) as Record<string, string>
    expect(headers['x-internal-key']).toBe('test-key-123')
  })
})

describe('GET /api/agent/files streams safely', () => {
  test('streams agent body without buffering', async () => {
    agentHeaders = { 'Content-Type': 'application/octet-stream', 'Content-Length': '3' }
    const res = await GET(new NextRequest('http://x/api/agent/files?path=/tmp/out.bin'))
    expect(res.body).toBe(agentBody)  // the upstream stream itself, never read into memory
    expect(res.headers.get('Content-Length')).toBe('3')
    expect(await res.text()).toBe('abc')
  })

  test.each([
    ['legacy /files branch', 'http://x/api/agent/files?path=/tmp/evil.html'],
    ['projectId branch', 'http://x/api/agent/files?projectId=p1&path=uploads/site/evil.svg'],
  ])('html and svg downloads are attachment with nosniff (%s)', async (_name, url) => {
    mockGuardProject.mockResolvedValue(null)
    agentHeaders = { 'Content-Type': url.endsWith('.svg') ? 'image/svg+xml' : 'text/html' }
    const res = await GET(new NextRequest(url))
    expect(res.headers.get('Content-Disposition')).toMatch(/^attachment; filename="evil\.(html|svg)"/)
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
  })

  test('agent Content-Disposition is never forwarded', async () => {
    mockGuardProject.mockResolvedValue(null)
    agentHeaders = { 'Content-Disposition': 'inline; filename="x.html"' }
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=uploads/a"b\r\nc.html'))
    const cd = res.headers.get('Content-Disposition') || ''
    expect(cd.startsWith('attachment;')).toBe(true)
    expect(cd).not.toContain('inline')
    expect(cd).not.toMatch(/[\r\n]/)
  })

  test('the agent call carries the browser request signal', async () => {
    await GET(new NextRequest('http://x/api/agent/files?path=/tmp/a'))
    expect(fetchInits[0]?.signal).toBeInstanceOf(AbortSignal)
  })
})
