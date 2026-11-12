/**
 * GET /api/plugins and GET /api/plugins/[pluginId]: the Plugins page model. One entry per
 * catalog plugin merged with the installed rows (an installed plugin the catalog no longer
 * lists is still shown and manageable), the catalog's state in words a person can act on,
 * and the card state of each plugin. Every signed-in user may read it; only an admin (the
 * role read from the database) sees errors, versions on disk, data usage and rollback.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as { userId: string; role: string } | null,
  catalog: null as unknown,
  catalogError: null as unknown,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getSession: async () => h.session,
  getEffectiveUser: async () => (h.session ? { userId: h.session.userId } : null),
}))
vi.mock('@/lib/plugins/catalog', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  loadCatalog: async () => {
    if (h.catalogError) throw h.catalogError
    return h.catalog
  },
}))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { setNowForTests } from '@/lib/plugins/clock'
import { CatalogError, type LoadedCatalog } from '@/lib/plugins/catalog'
import { GET as listRoute } from './route'
import { GET as detailRoute } from './[pluginId]/route'

const NOW = new Date('2026-10-10T12:00:00Z')
let db: FakePrisma

const rel = (version: string, extra: Record<string, unknown> = {}) => ({
  version,
  platform: '>=1.0.0 <2.0.0',
  dataVersion: 1,
  url: `https://github.com/example/redamon-plugins/releases/download/echo-v${version}/echo-${version}.tar.gz`,
  sha256: 'a'.repeat(64),
  permissions: ['session:read', 'llm:invoke'],
  ...extra,
})

function catalog(plugins: unknown[], extra: Partial<LoadedCatalog> = {}, revoked: unknown[] = []): LoadedCatalog {
  return {
    catalog: { catalogVersion: 1, serial: 3, plugins, revoked } as LoadedCatalog['catalog'],
    keyId: 'redamon-2026',
    official: true,
    serial: 3,
    warnings: [],
    ...extra,
  }
}

const echo = (releases = [rel('1.0.0'), rel('1.1.0'), rel('2.0.0', { platform: '>=2.0.0' })]) => ({
  id: 'echo', displayName: 'Echo', description: 'The test fixture.', releases,
})

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.session = { userId: 'user-alice', role: 'standard' }
  h.catalog = catalog([echo()])
  h.catalogError = null
  setNowForTests(() => NOW)
  db.seed('user', [
    { id: 'user-admin', email: 'admin@example.com', role: 'admin' },
    { id: 'user-alice', email: 'alice@example.com', role: 'standard' },
  ])
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  setNowForTests(null)
  vi.restoreAllMocks()
})

const list = async () => {
  const res = await listRoute()
  return { status: res.status, body: await res.json() }
}
const detail = async (id = 'echo') => {
  const res = await detailRoute(new NextRequest(`http://localhost:3000/api/plugins/${id}`), { params: Promise.resolve({ pluginId: id }) })
  return { status: res.status, body: await res.json() }
}
const install = (over: Record<string, unknown> = {}) =>
  db.seed('pluginInstall', [{
    pluginId: 'echo', status: 'ready', enabled: true, activeVersion: '1.0.0', dataVersion: 1,
    grantedPermissions: ['session:read', 'llm:invoke'], lastError: null, revokedReason: null,
    manifest: { id: 'echo', version: '1.0.0', permissions: ['session:read', 'llm:invoke'] }, ...over,
  }])

describe('GET /api/plugins', () => {
  test('401 without a session', async () => {
    h.session = null
    expect((await list()).status).toBe(401)
  })

  test('a plugin not installed: the newest release this platform can run, with consent text', async () => {
    const { status, body } = await list()
    expect(status).toBe(200)
    expect(body).toMatchObject({ platformVersion: '1.1.0', managesPlugins: false, catalog: { state: 'ok', official: true } })
    expect(body.plugins).toHaveLength(1)
    const e = body.plugins[0]
    expect(e).toMatchObject({ id: 'echo', displayName: 'Echo', inCatalog: true, state: 'not_installed', installed: null, installBlocked: null })
    expect(e.available.version).toBe('1.1.0')
    expect(e.available.permissions.map((p: { id: string }) => p.id)).toEqual(['session:read', 'llm:invoke'])
    expect(e.available.permissions[0].consent).toMatch(/target data/)
  })

  test('the role comes from the database: a standard token of an admin is an admin', async () => {
    h.session = { userId: 'user-admin', role: 'standard' }
    expect((await list()).body.managesPlugins).toBe(true)
    h.session = { userId: 'user-alice', role: 'admin' }
    expect((await list()).body.managesPlugins).toBe(false)
  })

  test.each([
    [{ status: 'ready', enabled: true }, 'ready'],
    [{ status: 'ready', enabled: false }, 'disabled'],
    [{ status: 'failed', enabled: true }, 'failed'],
    [{ status: 'incompatible', enabled: true }, 'incompatible'],
    [{ status: 'installing' }, 'installing'],
    [{ status: 'updating' }, 'updating'],
    [{ status: 'uninstalling' }, 'uninstalling'],
    [{ status: 'available', activeVersion: null }, 'not_installed'],
    [{ status: 'ready', revokedReason: 'Leaks data.' }, 'revoked'],
  ])('installed row %j → card state %s', async (over, state) => {
    install(over)
    expect((await list()).body.plugins[0].state).toBe(state)
  })

  test('an update: the newer compatible release, the permissions it adds', async () => {
    install()
    h.catalog = catalog([echo([rel('1.0.0'), rel('1.2.0', { permissions: ['session:read', 'llm:invoke', 'override:skill.text'], dataVersion: 2 })])])
    const e = (await list()).body.plugins[0]
    expect(e.update).toEqual({ version: '1.2.0', newPermissions: ['override:skill.text'], migratesData: true })
  })

  test('no update when the newest compatible release is the installed one', async () => {
    install({ activeVersion: '1.1.0' })
    expect((await list()).body.plugins[0].update).toBeNull()
  })

  test('lastError is for admins only', async () => {
    install({ status: 'failed', lastError: 'worker_failed: the worker is failed' })
    expect((await list()).body.plugins[0].installed.lastError).toBeUndefined()
    h.session = { userId: 'user-admin', role: 'admin' }
    expect((await list()).body.plugins[0].installed.lastError).toBe('worker_failed: the worker is failed')
  })

  test('an installed plugin the catalog no longer lists is still shown', async () => {
    install()
    h.catalog = catalog([])
    const body = (await list()).body
    expect(body.plugins).toHaveLength(1)
    expect(body.plugins[0]).toMatchObject({ id: 'echo', inCatalog: false, state: 'ready', available: null })
  })

  test('kept data of a plugin uninstalled with "keep" is flagged for admins only, listed or not', async () => {
    install({ status: 'available', enabled: false, activeVersion: null })
    db.seed('pluginData', [{ pluginId: 'echo', namespace: 'live', ownerType: 'user', ownerId: 'user-alice', userId: 'user-alice', collection: 'items', key: 'a', value: 1, sizeBytes: 1 }])
    h.session = { userId: 'user-admin', role: 'admin' }
    expect((await list()).body.plugins[0]).toMatchObject({ id: 'echo', state: 'not_installed', keptData: true })
    h.catalog = catalog([])
    expect((await list()).body.plugins[0]).toMatchObject({ id: 'echo', keptData: true })
    h.catalog = catalog([echo()])
    h.session = { userId: 'user-alice', role: 'standard' }
    expect((await list()).body.plugins[0].keptData).toBeUndefined()
  })

  test('a row that keeps nothing, of a plugin the catalog does not list, is not shown (nothing to manage)', async () => {
    install({ status: 'available', enabled: false, activeVersion: null, lastError: 'sha256_mismatch: an earlier attempt' })
    h.catalog = catalog([])
    h.session = { userId: 'user-admin', role: 'admin' }
    expect((await list()).body.plugins).toEqual([])
    h.catalog = catalog([echo()])
    expect((await list()).body.plugins.map((p: { id: string }) => p.id)).toEqual(['echo'])
  })

  test('unreachable: the message says Install from file is for an admin', async () => {
    h.catalogError = new CatalogError('catalog_unreachable', 'detail')
    expect((await list()).body.catalog.message).toMatch(/an admin can install one now with Install from file/)
  })

  test('only internal rows (usage, jobs) are not kept data', async () => {
    install({ status: 'available', enabled: false, activeVersion: null })
    db.seed('pluginData', [{ pluginId: 'echo', namespace: 'live', ownerType: 'user', ownerId: 'user-alice', userId: 'user-alice', collection: '__usage', key: 'a', value: 1, sizeBytes: 1 }])
    h.session = { userId: 'user-admin', role: 'admin' }
    expect((await list()).body.plugins[0].keptData).toBeUndefined()
  })

  test('an empty catalog and nothing installed: no plugins', async () => {
    h.catalog = catalog([])
    expect((await list()).body.plugins).toEqual([])
  })

  test.each([
    ['catalog_unreachable', 'unreachable', /could not be reached/],
    ['signature_invalid', 'invalid', /signature/],
    ['schema_invalid', 'invalid', /not a valid/],
    ['unknown_key', 'untrusted', /not trust/],
  ] as const)('a catalog that fails with %s: state %s, installed plugins still listed, Install blocked', async (code, state, message) => {
    install()
    h.catalogError = new CatalogError(code, 'detail')
    const body = (await list()).body
    expect(body.catalog.state).toBe(state)
    expect(body.catalog.message).toMatch(message)
    expect(body.plugins.map((p: { id: string; state: string }) => [p.id, p.state])).toEqual([['echo', 'ready']])
    expect(body.plugins[0].update).toBeNull()
    // Unknown, not "no longer listed": the catalog was not read.
    expect(body.plugins[0].inCatalog).toBeNull()
  })

  test("an admin sees why the catalog is not used: the check's own sentence and the first schema errors", async () => {
    h.session = { userId: 'user-admin', role: 'admin' }
    h.catalogError = new CatalogError(
      'catalog_unreachable',
      'The plugin catalog could not be downloaded (catalog.json.sig): The plugin download answered HTTP 404.',
      undefined,
      'http_error',
    )
    expect((await list()).body.catalog).toMatchObject({
      state: 'unreachable',
      detail: 'The plugin catalog could not be downloaded (catalog.json.sig): The plugin download answered HTTP 404.',
    })
    const paths = Array.from({ length: 8 }, (_, i) => `/plugins/${i}/releases/0/sha256: must match pattern`)
    h.catalogError = new CatalogError('schema_invalid', 'The signed catalog does not match the catalog schema.', paths)
    const c = (await list()).body.catalog
    expect(c.detail).toBe('The signed catalog does not match the catalog schema.')
    expect(c.details).toEqual(paths.slice(0, 5))
    h.catalogError = new CatalogError('unknown_key', 'The catalog is signed with key "rotated-2025", which this RedAmon does not trust.')
    expect((await list()).body.catalog.detail).toContain('"rotated-2025"')
  })

  test('a standard user gets the advice without the detail', async () => {
    h.catalogError = new CatalogError('schema_invalid', 'The signed catalog does not match the catalog schema.', ['/plugins/0: x'])
    const c = (await list()).body.catalog
    expect(c.message).toMatch(/not a valid catalog/)
    expect('detail' in c).toBe(false)
    expect('details' in c).toBe(false)
  })

  test('an extra-key catalog is flagged; the view carries no expiry', async () => {
    h.catalog = catalog([echo()], { official: false, warnings: ['extra_key'] })
    const c = (await list()).body.catalog
    expect(c).toMatchObject({ state: 'ok', official: false, extraKey: true })
    expect(Object.keys(c).filter((k) => /expir/i.test(k))).toEqual([])
  })

  test('a revoked release is not offered; a plugin with nothing compatible says why', async () => {
    h.catalog = catalog([echo([rel('1.0.0'), rel('1.1.0')])], {}, [{ id: 'echo', version: '1.1.0', reason: 'x' }])
    expect((await list()).body.plugins[0].available.version).toBe('1.0.0')
    h.catalog = catalog([echo([rel('3.0.0', { platform: '>=3.0.0' })])])
    const e = (await list()).body.plugins[0]
    expect(e.available).toBeNull()
    expect(e.installBlocked).toMatch(/newer RedAmon/)
  })

  test('every release this RedAmon can run is revoked: Install is blocked with the reason, not "newer RedAmon"', async () => {
    h.catalog = catalog([echo([rel('1.0.0'), rel('1.1.0'), rel('3.0.0', { platform: '>=3.0.0' })])], {}, [
      { id: 'echo', version: '1.0.0', reason: 'old' },
      { id: 'echo', version: '1.1.0', reason: 'Sends transcripts out.' },
    ])
    const e = (await list()).body.plugins[0]
    expect(e.available).toBeNull()
    expect(e.installBlocked).toBe('Every release of this plugin that runs on this RedAmon was revoked: Sends transcripts out.')
  })

  test('a revoked installed plugin is offered the newer release that is not revoked', async () => {
    install({ revokedReason: 'Sends transcripts out.' })
    h.catalog = catalog([echo([rel('1.0.0'), rel('1.1.0')])], {}, [{ id: 'echo', version: '1.0.0', reason: 'Sends transcripts out.' }])
    const e = (await list()).body.plugins[0]
    expect(e.state).toBe('revoked')
    expect(e.update).toMatchObject({ version: '1.1.0' })
  })
})

describe('GET /api/plugins/[pluginId]', () => {
  test('a standard user gets the entry without the admin details', async () => {
    install()
    const { status, body } = await detail()
    expect(status).toBe(200)
    expect(body.plugin.id).toBe('echo')
    expect(body.admin).toBeUndefined()
  })

  test('an admin gets versions on disk, data usage, dormant versions and the rollback check', async () => {
    install({ enabled: false })
    db.seed('pluginData', [
      { pluginId: 'echo', ownerType: 'user', ownerId: 'user-alice', userId: 'user-alice', collection: 'items', key: 'a', value: 1, sizeBytes: 10 },
      { pluginId: 'echo', ownerType: 'user', ownerId: 'user-alice', userId: 'user-alice', collection: '__jobs', key: 'j', value: 1, sizeBytes: 99 },
    ])
    db.seed('pluginOverride', [{
      pluginId: 'echo', extensionPoint: 'skill.text', scopeType: 'user', scopeId: 'user-alice', userId: 'user-alice', targetGroup: 'sqli',
      targetKey: 'sqli/workflow', changeSetId: 'cs-1', revision: 2, value: 'v', baseSha256: 'a'.repeat(64), status: 'active', createdBy: 'user-alice',
    }])
    h.session = { userId: 'user-admin', role: 'admin' }
    const { body } = await detail()
    expect(body.admin).toMatchObject({
      versionsOnDisk: [],
      data: { rows: 1, bytes: 10, maxRows: 10_000, maxBytes: 52_428_800 },
      activeVersions: 1,
      dormantVersions: 1,
      rollback: { possible: false, reason: 'no_previous_version' },
    })
    expect(body.admin.grantedPermissions.map((p: { id: string }) => p.id)).toEqual(['session:read', 'llm:invoke'])
  })

  test('an unknown plugin is 404; an invalid id 400', async () => {
    expect((await detail('nobody')).status).toBe(404)
    expect((await detail('BAD')).status).toBe(400)
  })
})
