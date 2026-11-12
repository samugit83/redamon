/**
 * Route tests for the transcript drill-down (§9c). Mocks neo4j (ownership check)
 * and fs (stat/readFile) so the route's guards + headers are exercised directly.
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

let ownedCount = 0
const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      return { records: [{ get: () => ownedCount }] }   // count query always returns a row
    },
    close: async () => {},
  }),
}))

// Ownership is covered by the BOLA + live E2E tests; stub the guard open here.
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

let statResult: { isFile: () => boolean; size: number } | null = null
let fileBody = Buffer.from('')
let readError: Error | null = null
vi.mock('fs', () => ({
  promises: {
    stat: async () => { if (!statResult) throw new Error('ENOENT'); return statResult },
    readFile: async () => { if (readError) throw readError; return fileBody },
  },
}))

const route = await import('./route')

const ROOT = '/app/ai_attack_surface_scan/output'
const REF = `${ROOT}/run1/promptfoo/slug/promptfoo_results.json`

function req(ref: string) {
  return { nextUrl: { searchParams: new URLSearchParams(ref ? { ref } : {}) } } as never
}
const params = (projectId: string) => ({ params: Promise.resolve({ projectId }) }) as never

beforeEach(() => {
  runCalls.length = 0
  ownedCount = 1
  statResult = { isFile: () => true, size: 1024 }
  fileBody = Buffer.from('{"ok":true}')
  readError = null
})

describe('transcript route', () => {
  test('400 on an invalid / traversal ref (never touches the DB or fs)', async () => {
    const res = await route.GET(req(`${ROOT}/../../etc/passwd.json`), params('p1'))
    expect(res.status).toBe(400)
    expect(runCalls).toHaveLength(0)
  })

  test('400 when ref is missing', async () => {
    const res = await route.GET(req(''), params('p1'))
    expect(res.status).toBe(400)
  })

  test('404 when no Vulnerability in the project owns the ref', async () => {
    ownedCount = 0
    const res = await route.GET(req(REF), params('p1'))
    expect(res.status).toBe(404)
    // ownership is checked with the project id + the exact ref
    expect(runCalls[0].params).toEqual({ pid: 'p1', ref: REF })
  })

  test('404 when the file is missing on disk', async () => {
    statResult = null
    const res = await route.GET(req(REF), params('p1'))
    expect(res.status).toBe(404)
  })

  test('413 when the file exceeds the size cap', async () => {
    statResult = { isFile: () => true, size: 9 * 1024 * 1024 }
    const res = await route.GET(req(REF), params('p1'))
    expect(res.status).toBe(413)
  })

  test('200 serves json inline with nosniff', async () => {
    const res = await route.GET(req(REF), params('p1'))
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('application/json')
    expect(res.headers.get('Content-Disposition')).toMatch(/^inline; filename="promptfoo_results.json"/)
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(await res.text()).toBe('{"ok":true}')
  })

  test('XSS guard: html is served as inert text AND forced to download', async () => {
    const htmlRef = `${ROOT}/run1/garak/slug/garak_run.report.html`
    fileBody = Buffer.from('<script>alert(1)</script>')
    const res = await route.GET(req(htmlRef), params('p1'))
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('text/plain')          // NOT text/html
    expect(res.headers.get('Content-Disposition')).toMatch(/^attachment;/)  // download, not render
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
  })

  test('a read failure answers the errno, never the path or the message', async () => {
    readError = Object.assign(new Error(`EACCES: permission denied, open '${REF}'`), { code: 'EACCES' })
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await route.GET(req(REF), params('p1'))
    spy.mockRestore()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to read transcript', code: 'EACCES' })
    expect(JSON.stringify(body)).not.toContain('promptfoo_results')
  })
})
