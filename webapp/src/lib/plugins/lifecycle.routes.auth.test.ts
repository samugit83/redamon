/**
 * The lifecycle routes put code on the host, so (README.PLUGINS.md §7.1, RV-11):
 * - admin only, with the role READ FROM THE DATABASE on every request: the role inside
 *   the 7-day JWT stays "admin" for a week after a demotion;
 * - an admin acting as a standard user keeps admin rights here (the login session is the
 *   admin's; "act as" narrows data access, not platform administration), and is the actor;
 * - same-origin and JSON-only bodies for every POST (no CSRF tokens exist, R-29);
 * - a lease conflict is 409 plugin_busy.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as { userId: string; role: string } | null,
  eff: null as { userId: string } | null,
  audit: [] as Record<string, unknown>[],
  calls: [] as unknown[][],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getSession: async () => h.session,
  getEffectiveUser: async () => h.eff,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async (e: Record<string, unknown>) => void h.audit.push(e)) }))
vi.mock('./lifecycle', async (orig) => {
  const real = (await orig()) as Record<string, unknown>
  const spy = (name: string) => async (...args: unknown[]) => {
    h.calls.push([name, ...args])
    if (args[0] === 'busy') {
      const { LifecycleError } = await import('./lifecycleCommon')
      throw new LifecycleError(409, 'plugin_busy', 'Plugin busy: another operation is in progress.')
    }
    return { plugin: { pluginId: args[0], status: 'ready' } }
  }
  return {
    ...real,
    install: spy('install'),
    enable: spy('enable'),
    disable: spy('disable'),
    uninstall: spy('uninstall'),
    update: spy('update'),
    rollback: spy('rollback'),
  }
})

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { POST as installRoute } from '@/app/api/plugins/[pluginId]/install/route'
import { POST as enableRoute } from '@/app/api/plugins/[pluginId]/enable/route'
import { POST as disableRoute } from '@/app/api/plugins/[pluginId]/disable/route'
import { POST as uninstallRoute } from '@/app/api/plugins/[pluginId]/uninstall/route'
import { POST as updateRoute } from '@/app/api/plugins/[pluginId]/update/route'
import { POST as rollbackRoute } from '@/app/api/plugins/[pluginId]/rollback/route'
import { GET as exportRoute } from '@/app/api/plugins/[pluginId]/export/route'
import { GET as logsRoute } from '@/app/api/plugins/[pluginId]/logs/route'

const APP = 'http://localhost:3000'
let db: FakePrisma

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.audit = []
  h.calls = []
  db.seed('user', [
    { id: 'user-admin', email: 'admin@example.com', role: 'admin' },
    { id: 'user-alice', email: 'alice@example.com', role: 'standard' },
    { id: 'user-demoted', email: 'demoted@example.com', role: 'standard' },
  ])
  db.seed('pluginInstall', [{ pluginId: 'echo', status: 'ready', enabled: true, activeVersion: '1.0.0' }])
  h.session = { userId: 'user-admin', role: 'admin' }
  h.eff = { userId: 'user-admin' }
  for (const m of ['warn', 'error', 'log'] as const) vi.spyOn(console, m).mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

type Post = (r: NextRequest, c: { params: Promise<{ pluginId: string }>}) => Promise<Response>
const ctx = (pluginId: string) => ({ params: Promise.resolve({ pluginId }) })

function post(path: string, body: unknown, opts: { origin?: string; contentType?: string | null; raw?: string } = {}) {
  const headers = new Headers({ host: 'localhost:3000' })
  if (opts.contentType !== null) headers.set('content-type', opts.contentType ?? 'application/json')
  if (opts.origin) headers.set('origin', opts.origin)
  return new NextRequest(`${APP}${path}`, { method: 'POST', headers, body: opts.raw ?? JSON.stringify(body) })
}
const get = (path: string) => new NextRequest(`${APP}${path}`, { headers: { host: 'localhost:3000' } })

const POSTS: Array<[string, Post, unknown]> = [
  ['install', installRoute as Post, { version: '1.0.0', acceptedPermissions: [] }],
  ['enable', enableRoute as Post, {}],
  ['disable', disableRoute as Post, {}],
  ['uninstall', uninstallRoute as Post, { mode: 'keep', confirm: 'echo' }],
  ['update', updateRoute as Post, { version: '1.1.0', acceptedPermissions: [] }],
  ['rollback', rollbackRoute as Post, {}],
]

describe.each(POSTS)('POST /api/plugins/[pluginId]/%s', (name, route, body) => {
  const call = (opts?: Parameters<typeof post>[2], pluginId = 'echo') => route(post(`/api/plugins/${pluginId}/${name}`, body, opts), ctx(pluginId))

  test('401 without a session', async () => {
    h.session = null
    expect((await call()).status).toBe(401)
    expect(h.calls).toEqual([])
  })

  test('403 for a standard user', async () => {
    h.session = { userId: 'user-alice', role: 'standard' }
    h.eff = { userId: 'user-alice' }
    const res = await call()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'admin_required', permission: 'platform:plugins' })
    expect(h.calls).toEqual([])
  })

  test('403 for an admin token whose user was demoted in the database', async () => {
    h.session = { userId: 'user-demoted', role: 'admin' }
    expect((await call()).status).toBe(403)
    expect(h.calls).toEqual([])
  })

  test('403 for a token whose user no longer exists', async () => {
    h.session = { userId: 'user-gone', role: 'admin' }
    expect((await call()).status).toBe(403)
  })

  test('an admin acting as a standard user keeps admin rights and is the actor', async () => {
    h.eff = { userId: 'user-alice' }
    const res = await call()
    expect(res.status).toBe(200)
    expect(h.calls[0]).toContain('user-admin')
    expect(h.calls[0]).not.toContain('user-alice')
  })

  test('403 cross_origin for a browser POST from another site', async () => {
    const res = await call({ origin: 'https://evil.example' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(h.calls).toEqual([])
  })

  test('same-origin passes', async () => {
    expect((await call({ origin: 'http://localhost:3000' })).status).toBe(200)
  })

  test('415 for a form body, 400 for a body that is not JSON', async () => {
    expect((await call({ contentType: 'application/x-www-form-urlencoded', raw: 'a=1' })).status).toBe(415)
    expect((await call({ raw: '{nope' })).status).toBe(400)
    expect(h.calls).toEqual([])
  })

  test('409 plugin_busy on a lease conflict, with the code', async () => {
    const res = await call(undefined, 'busy')
    expect(res.status).toBe(409)
    expect((await res.json())).toMatchObject({ code: 'plugin_busy' })
  })
})

describe('the routes hand the body to the lifecycle', () => {
  test('install', async () => {
    await installRoute(post('/api/plugins/echo/install', { version: '1.0.0', acceptedPermissions: ['session:read'], restoreOverrides: true }), ctx('echo'))
    expect(h.calls[0].slice(0, 4)).toEqual(['install', 'echo', { version: '1.0.0', acceptedPermissions: ['session:read'], restoreOverrides: true }, 'user-admin'])
  })

  test('update', async () => {
    await updateRoute(post('/api/plugins/echo/update', { version: '1.1.0', acceptedPermissions: ['session:read'] }), ctx('echo'))
    expect(h.calls[0].slice(0, 4)).toEqual(['update', 'echo', { version: '1.1.0', acceptedPermissions: ['session:read'] }, 'user-admin'])
  })

  test('rollback', async () => {
    await rollbackRoute(post('/api/plugins/echo/rollback', {}), ctx('echo'))
    expect(h.calls[0].slice(0, 3)).toEqual(['rollback', 'echo', 'user-admin'])
  })

  test('uninstall', async () => {
    await uninstallRoute(post('/api/plugins/echo/uninstall', { mode: 'purge', confirm: 'echo' }), ctx('echo'))
    expect(h.calls[0].slice(0, 4)).toEqual(['uninstall', 'echo', { mode: 'purge', confirm: 'echo' }, 'user-admin'])
  })
})

describe('GET export and logs', () => {
  test.each([
    ['export', exportRoute],
    ['logs', logsRoute],
  ])('%s: 401, 403 for a standard or demoted user', async (name, route) => {
    const call = () => (route as (r: NextRequest, c: unknown) => Promise<Response>)(get(`/api/plugins/echo/${name}`), ctx('echo'))
    h.session = null
    expect((await call()).status).toBe(401)
    h.session = { userId: 'user-alice', role: 'standard' }
    const refused = await call()
    expect(refused.status).toBe(403)
    // The live matrix proves a refusal by the permission named in the body.
    expect(await refused.json()).toMatchObject({ code: 'admin_required', permission: 'platform:plugins' })
    h.session = { userId: 'user-demoted', role: 'admin' }
    expect((await call()).status).toBe(403)
  })

  test('logs: the runner ring buffer for an admin; 503 runner_unavailable when it is down', async () => {
    const { startFakeRunner } = await import('./__testing__/fakeRunner')
    const runner = await startFakeRunner({ runnerKey: 'k'.repeat(64), logs: { echo: ['one', 'two', 'three'] } })
    vi.stubEnv('PLUGIN_RUNNER_URL', runner.baseUrl)
    vi.stubEnv('PLUGIN_RUNNER_KEY', 'k'.repeat(64))
    try {
      const res = await logsRoute(get('/api/plugins/echo/logs?lines=2'), ctx('echo'))
      expect(res.status).toBe(200)
      expect(await res.json()).toEqual({ lines: ['two', 'three'] })
    } finally {
      await runner.close()
    }
    const down = await logsRoute(get('/api/plugins/echo/logs'), ctx('echo'))
    expect(down.status).toBe(503)
    expect((await down.json()).code).toBe('runner_unavailable')
  })

  test('logs: an invalid plugin id is 400', async () => {
    expect((await logsRoute(get('/api/plugins/BAD/logs'), ctx('BAD'))).status).toBe(400)
  })
})
