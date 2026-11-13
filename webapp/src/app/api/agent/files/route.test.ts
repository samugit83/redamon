/**
 * agent/files download proxy (4.9 review): a download names its project and a path inside that
 * project's workspace, and the caller needs workspace:read (R*) on it.
 *  - with projectId: the project guard decides (guardProject); the path is workspace-relative, or
 *    absolute under /workspace/<projectId>/, and goes to the agent's project-scoped
 *    /workspace/download, which confines it to the project's workspace;
 *  - without projectId: 400 before any guard (there is no project to check); with a path outside
 *    the project's workspace (/tmp/..., another project's /workspace/<id>/..., a `..` segment):
 *    400 after the project guard, before any agent call. The legacy /tmp flow read any file under
 *    the shared sandbox's /tmp with no project or user scope.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuardProject = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProjectOrCapability()))
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
  test('no projectId: 400 before any guard or agent call (the legacy /tmp flow is gone)', async () => {
    const res = await GET(new NextRequest('http://x/api/agent/files?path=/tmp/out.txt'))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/projectId/)
    expect(mockGuardProject).not.toHaveBeenCalled()
    expect(fetchCalls).toHaveLength(0)
  })

  test.each([
    ['a file under the shared sandbox /tmp', '/tmp/payload.exe'],
    ['another project\'s workspace', '/workspace/victimProj/loot/creds.txt'],
    ['an absolute path elsewhere', '/etc/passwd'],
    ['a parent segment', 'uploads/../../victimProj/a.txt'],
    ['a parent segment under the project\'s own prefix', '/workspace/p1/../victimProj/a.txt'],
    ['a backslash parent segment', 'uploads\\..\\..\\a.txt'],
    ['an empty path', ''],
  ])('with projectId, %s: 400 after the project guard, before any agent call', async (_what, path) => {
    mockGuardProject.mockResolvedValue(null)
    const res = await GET(new NextRequest(`http://x/api/agent/files?projectId=p1&path=${encodeURIComponent(path)}`))
    expect(res.status).toBe(400)
    expect(mockGuardProject).toHaveBeenCalledWith('p1')
    expect(fetchCalls).toHaveLength(0)
  })

  test('a project the caller cannot see answers 404 whatever the path', async () => {
    mockGuardProject.mockResolvedValue(NOT_FOUND)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=victimProj&path=/tmp/payload.exe'))
    expect(res.status).toBe(404)
    expect(fetchCalls).toHaveLength(0)
  })

  test('with projectId, an absolute path under /workspace/<projectId>/ goes to the agent workspace-relative', async () => {
    mockGuardProject.mockResolvedValue(null)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=/workspace/p1/loot/report.txt'))
    expect(res.status).toBe(200)
    expect(fetchCalls).toHaveLength(1)
    expect(fetchCalls[0]).toContain('/workspace/download?projectId=p1&path=loot%2Freport.txt')
    expect(fetchCalls[0]).not.toContain('/files?')
  })

  test('with projectId, owner → guard passes, proxies to workspace/download', async () => {
    mockGuardProject.mockResolvedValue(null)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=a'))
    expect(res.status).toBe(200)
    expect(mockGuardProject).toHaveBeenCalledWith('p1')
    expect(fetchCalls.some(u => u.includes('/workspace/download?projectId=p1'))).toBe(true)
  })

  test('EXPLOIT: with projectId, cross-user → 404, no proxy', async () => {
    mockGuardProject.mockResolvedValue(NOT_FOUND)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=victimProj&path=a'))
    expect(res.status).toBe(404)
    expect(fetchCalls).toHaveLength(0)
  })

  test('forwards the internal API key to the agent', async () => {
    mockGuardProject.mockResolvedValue(null)
    vi.stubEnv('INTERNAL_API_KEY', 'test-key-123')
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=out.txt'))
    expect(res.status).toBe(200)
    const headers = (fetchInits[0]?.headers ?? {}) as Record<string, string>
    expect(headers['x-internal-key']).toBe('test-key-123')
  })
})

describe('GET /api/agent/files streams safely', () => {
  test('streams agent body without buffering', async () => {
    mockGuardProject.mockResolvedValue(null)
    agentHeaders = { 'Content-Type': 'application/octet-stream', 'Content-Length': '3' }
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=out.bin'))
    expect(res.body).toBe(agentBody)  // the upstream stream itself, never read into memory
    expect(res.headers.get('Content-Length')).toBe('3')
    expect(await res.text()).toBe('abc')
  })

  test.each([
    ['an absolute path in the project\'s workspace', 'http://x/api/agent/files?projectId=p1&path=/workspace/p1/uploads/evil.html'],
    ['a workspace-relative path', 'http://x/api/agent/files?projectId=p1&path=uploads/site/evil.svg'],
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
    mockGuardProject.mockResolvedValue(null)
    await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=a'))
    expect(fetchInits[0]?.signal).toBeInstanceOf(AbortSignal)
  })
})
