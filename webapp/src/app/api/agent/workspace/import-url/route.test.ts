/**
 * The three URL-import proxies: project access, URL checks, the GitHub token
 * (GitHub links only, never under act-as, never in a response) and audit rows.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const TOKEN = 'TEST-SENTINEL-TOKEN-0000'
const h = vi.hoisted(() => ({
  effective: vi.fn(), access: vi.fn(), session: vi.fn(), audit: vi.fn(), findUnique: vi.fn(),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.effective(),
  requireProjectAccess: (...a: unknown[]) => h.access(...a),
}))
vi.mock('@/lib/session', () => ({ getSession: () => h.session(), getEffectiveUser: () => h.effective() }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { userSettings: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))

import { POST as importPost } from './route'
import { POST as resolvePost } from './resolve/route'
import { POST as resyncPost } from './resync/route'

interface Sent { url: string; body: Record<string, unknown> | null }
let sent: Sent[]
let agent: (url: string) => Response

const req = (body: unknown) => new NextRequest('http://x/x', {
  method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
})
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  sent = []
  h.effective.mockReset().mockResolvedValue({ userId: 'u-admin' })
  h.session.mockReset().mockResolvedValue({ userId: 'u-admin', role: 'admin' })
  h.access.mockReset().mockResolvedValue({ project: { id: 'p1', userId: 'u-admin' } })
  h.audit.mockReset()
  h.findUnique.mockReset().mockResolvedValue({ githubAccessToken: TOKEN })
  agent = (url) => {
    if (url.includes('/workspace/properties')) return json({ type: 'dir', import: { kind: 'github-repo', host: 'github.com', sourcePath: '/o/r' } })
    if (url.endsWith('/resolve')) return json({ kind: 'github-repo', url: 'https://github.com/o/r', supported: true })
    return json({ jobId: 'j'.repeat(32), kind: 'github-repo', destDir: 'uploads', name: 'r' }, 202)
  }
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    sent.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) : null })
    return agent(String(url))
  }))
})

const agentBodies = (path: string) => sent.filter(s => s.url.endsWith(path)).map(s => s.body!)

describe('URL import proxies', () => {
  test('token added only for GitHub-family hosts', async () => {
    await resolvePost(req({ projectId: 'p1', url: 'https://github.com/o/r' }))
    await resolvePost(req({ projectId: 'p1', url: 'https://gitlab.com/g/p' }))
    const bodies = agentBodies('/workspace/import-url/resolve')
    expect(bodies[0].githubToken).toBe(TOKEN)
    expect(bodies[1]).not.toHaveProperty('githubToken')
  })

  test('lookalike host gets no token', async () => {
    await importPost(req({ projectId: 'p1', url: 'https://github.com.example.test/o/r', destDir: 'uploads' }))
    expect(agentBodies('/workspace/import-url')[0]).not.toHaveProperty('githubToken')
  })

  test('token never in the response', async () => {
    for (const res of [
      await resolvePost(req({ projectId: 'p1', url: 'https://github.com/o/r' })),
      await importPost(req({ projectId: 'p1', url: 'https://github.com/o/r', destDir: 'uploads' })),
      await resyncPost(req({ projectId: 'p1', path: 'uploads/r' })),
    ]) {
      expect(await res.text()).not.toContain(TOKEN)
    }
  })

  test('denied project never reaches the agent', async () => {
    h.access.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    for (const call of [
      () => resolvePost(req({ projectId: 'victim', url: 'https://github.com/o/r' })),
      () => importPost(req({ projectId: 'victim', url: 'https://github.com/o/r' })),
      () => resyncPost(req({ projectId: 'victim', path: 'uploads/r' })),
    ]) {
      expect((await call()).status).toBe(404)
    }
    expect(sent).toHaveLength(0)
  })

  test('invalid URL is 400 with a code', async () => {
    for (const [url, code] of [['not a url', 'invalid_url'], ['ftp://x.test/a', 'unsupported_scheme'],
      ['https://user:pass@example.test/a.zip', 'credentials_in_url'], [42, 'invalid_url']] as const) {
      const res = await importPost(req({ projectId: 'p1', url }))
      expect(res.status).toBe(400)
      expect((await res.json()).code).toBe(code)
    }
    expect(sent).toHaveLength(0)
  })

  test('resync reads properties first and sends the token only for a GitHub import', async () => {
    await resyncPost(req({ projectId: 'p1', path: 'uploads/r' }))
    expect(sent[0].url).toContain('/workspace/properties?projectId=p1&path=uploads%2Fr')
    expect(agentBodies('/workspace/import-url/resync')[0].githubToken).toBe(TOKEN)
    sent = []
    agent = (url) => url.includes('/properties')
      ? json({ type: 'dir', import: { kind: 'gitlab-repo', host: 'gitlab.com', sourcePath: '/g/p' } })
      : json({ jobId: 'j'.repeat(32), kind: 'gitlab-repo', destDir: 'uploads', name: 'p' }, 202)
    await resyncPost(req({ projectId: 'p1', path: 'uploads/p' }))
    expect(agentBodies('/workspace/import-url/resync')[0]).not.toHaveProperty('githubToken')
  })

  test('under act-as no token is sent, for resolve, import and resync', async () => {
    h.effective.mockResolvedValue({ userId: 'u-target' })
    await resolvePost(req({ projectId: 'p1', url: 'https://github.com/o/r' }))
    await importPost(req({ projectId: 'p1', url: 'https://github.com/o/r', destDir: 'uploads' }))
    await resyncPost(req({ projectId: 'p1', path: 'uploads/r' }))
    for (const s of sent.filter(s => s.body)) expect(s.body).not.toHaveProperty('githubToken')
    expect(h.findUnique).not.toHaveBeenCalled()
  })

  test('accepted import and resync write one audit row with redacted URL and tokenUsed', async () => {
    await importPost(req({ projectId: 'p1', url: 'https://github.com/o/r?tab=readme#x', destDir: 'uploads' }))
    await resyncPost(req({ projectId: 'p1', path: 'uploads/r' }))
    expect(h.audit).toHaveBeenCalledTimes(2)
    const [imp, res] = h.audit.mock.calls.map(c => c[0])
    expect(imp).toMatchObject({ actorId: 'u-admin', action: 'workspace.import', targetType: 'project', targetId: 'p1',
      source: 'ui', after: { kind: 'github-repo', destDir: 'uploads', name: 'r', url: 'https://github.com/o/r', tokenUsed: true } })
    expect(res).toMatchObject({ action: 'workspace.resync', after: { url: 'https://github.com/o/r', tokenUsed: true } })
    expect(JSON.stringify(h.audit.mock.calls)).not.toContain(TOKEN)
  })

  test('under act-as the audit row names the admin as actor and the simulated user', async () => {
    h.effective.mockResolvedValue({ userId: 'u-target' })
    await importPost(req({ projectId: 'p1', url: 'https://github.com/o/r', destDir: 'uploads' }))
    expect(h.audit.mock.calls[0][0]).toMatchObject({ actorId: 'u-admin', after: { actingAsUserId: 'u-target', tokenUsed: false } })
  })

  test('resolve writes no audit row; a refused import writes none', async () => {
    await resolvePost(req({ projectId: 'p1', url: 'https://github.com/o/r' }))
    agent = () => json({ error: 'This project already has 2 imports running.', code: 'too_many_imports' }, 429)
    const res = await importPost(req({ projectId: 'p1', url: 'https://github.com/o/r', destDir: 'uploads' }))
    expect((await res.json()).code).toBe('too_many_imports')
    expect(h.audit).not.toHaveBeenCalled()
  })
})
