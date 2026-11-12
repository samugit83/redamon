/**
 * Update side by side (README.PLUGINS.md §9.5): the new release is downloaded, checked and
 * renamed into versions/ beside the active one, which keeps serving its run-list entry and
 * contributions while the plugin is `updating` (actions are paused, overrides keep
 * applying); then the row switches to the new version in one write. New permissions need
 * consent again. A disabled plugin can be updated. Only the active and previous versions
 * stay on disk.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import path from 'node:path'
import fs from 'node:fs/promises'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  audit: [] as Record<string, unknown>[],
  eff: { userId: 'user-alice' } as { userId: string } | null,
  session: { userId: 'user-alice', role: 'standard' } as { userId: string; role: string } | null,
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async (e: Record<string, unknown>) => void h.audit.push(e)) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => h.eff,
  getSession: async () => h.session,
}))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { echoManifest } from './__testing__/echoArchive'
import { ADMIN, NOW, exists, startLifecycleWorld, type LifecycleWorld } from './__testing__/lifecycleHarness'
import { setNowForTests } from './clock'
import { LifecycleError, disable, install, update } from './lifecycle'
import * as ov from './overrides'
import { versionPath } from './staging'
import { POST as runActionRoute } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'

let db: FakePrisma
let w: LifecycleWorld
const FULL = ['session:read', 'llm:invoke', 'override:skill.text', 'override:user_skill.text']
const SHA = 'a'.repeat(64)

// 1.0.0 asks for two permissions (no skill versions, no skill pick); 1.1.0 for all of them.
const contributesWithout = () => {
  const c = echoManifest().contributes as Record<string, unknown[]>
  return { ...c, 'chat.session.actions': (c['chat.session.actions'] as Record<string, unknown>[]).filter((x) => !x.coreScreen && !x.pick) }
}
const RELEASES = [
  { manifest: { version: '1.0.0', permissions: ['session:read', 'llm:invoke'], contributes: contributesWithout() } },
  { manifest: { version: '1.0.1', permissions: ['session:read', 'llm:invoke'], contributes: contributesWithout() } },
  { manifest: { version: '1.0.2', permissions: ['session:read', 'llm:invoke'], contributes: contributesWithout() } },
  { manifest: { version: '1.1.0' } },
  { manifest: { version: '1.1.1' } },
]

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.audit = []
  setNowForTests(() => NOW)
  for (const m of ['warn', 'error', 'log'] as const) vi.spyOn(console, m).mockImplementation(() => {})
  db.seed('user', [
    { id: ADMIN, email: 'admin@example.com', role: 'admin' },
    { id: 'user-alice', email: 'alice@example.com', role: 'standard' },
  ])
  db.seed('project', [{ id: 'project-alice', userId: 'user-alice', name: 'P' }])
  w = await startLifecycleWorld(() => db, RELEASES)
  await install('echo', { version: '1.0.0', acceptedPermissions: ['session:read', 'llm:invoke'] }, ADMIN, w.deps)
  h.audit = []
})

afterEach(async () => {
  await w.close()
  setNowForTests(null)
  vi.restoreAllMocks()
})

const row = () => db.rows('pluginInstall').find((r) => r.pluginId === 'echo')!
const go = (version: string, perms = ['session:read', 'llm:invoke']) =>
  update('echo', { version, acceptedPermissions: perms }, ADMIN, w.deps)

async function refusal(p: Promise<unknown>): Promise<LifecycleError> {
  const e = await p.then(
    () => {
      throw new Error('expected a refusal')
    },
    (err) => err,
  )
  expect(e).toBeInstanceOf(LifecycleError)
  return e as LifecycleError
}

describe('an update', () => {
  test('without new permissions: the new version active, the old one kept as previous, both on disk', async () => {
    const out = await go('1.0.1')
    expect(out.plugin).toMatchObject({ status: 'ready', activeVersion: '1.0.1', previousVersion: '1.0.0', pendingVersion: null })
    const r = row()
    expect((r.manifest as { version: string }).version).toBe('1.0.1')
    expect(r.catalogEntry).toMatchObject({ version: '1.0.1', previous: { version: '1.0.0' } })
    expect(await exists(versionPath('echo', '1.0.0'))).toBe(true)
    expect(await exists(versionPath('echo', '1.0.1'))).toBe(true)
    expect(w.runner.options.workers?.map((x) => x.version)).toEqual(['1.0.1'])
    const a = h.audit.find((e) => e.action === 'plugin.update')!
    expect(a).toMatchObject({ actorId: ADMIN, targetId: 'echo' })
    expect(a.before).toMatchObject({ activeVersion: '1.0.0' })
    expect(a.after).toMatchObject({ activeVersion: '1.0.1', previousVersion: '1.0.0' })
    expect(h.audit.map((e) => e.action)).not.toContain('plugin.permissions_granted')
  })

  test('from a revoked version to a fixed release: it runs, unrevoked', async () => {
    db.tables.pluginInstall.set('echo', { ...row(), revokedReason: 'Sends transcripts out.' })
    const out = await go('1.0.1')
    expect(out.plugin).toMatchObject({ status: 'ready', activeVersion: '1.0.1', revokedReason: null })
  })

  test('a new permission that was not accepted → 400, nothing changes, nothing is downloaded', async () => {
    const before = JSON.stringify(row())
    const downloads = w.downloads.length
    const e = await refusal(go('1.1.0'))
    expect([e.status, e.code]).toEqual([400, 'permissions_mismatch'])
    expect(JSON.stringify(row())).toBe(before)
    expect(w.downloads.length).toBe(downloads)
  })

  test('the new permission accepted: granted, audited', async () => {
    const out = await go('1.1.0', FULL)
    expect(out.plugin.grantedPermissions).toEqual(FULL)
    expect(h.audit.find((e) => e.action === 'plugin.permissions_granted')).toMatchObject({
      after: { version: '1.1.0', permissions: FULL, added: ['override:skill.text', 'override:user_skill.text'] },
    })
  })

  test('only the active and the previous versions stay on disk', async () => {
    await go('1.0.1')
    await go('1.0.2')
    const versions = await fs.readdir(path.join(w.root, 'echo', 'versions'))
    expect(versions.sort()).toEqual(['1.0.1', '1.0.2'])
    expect(row()).toMatchObject({ activeVersion: '1.0.2', previousVersion: '1.0.1' })
  })

  test('a disabled plugin can be updated, and stays disabled without a worker', async () => {
    await disable('echo', ADMIN)
    const out = await go('1.0.1')
    expect(out.plugin).toMatchObject({ status: 'ready', enabled: false, activeVersion: '1.0.1' })
    expect(w.runner.options.workers).toEqual([])
  })

  test('a failed check leaves the old version active, lastError set, the new folder absent', async () => {
    w.archives.get('1.0.1')!.release.sha256 = 'f'.repeat(64)
    const e = await refusal(go('1.0.1'))
    expect([e.status, e.code]).toEqual([422, 'sha256_mismatch'])
    expect(row()).toMatchObject({ status: 'ready', activeVersion: '1.0.0', pendingVersion: null, operationId: null })
    expect(String(row().lastError)).toMatch(/^sha256_mismatch/)
    expect(await exists(versionPath('echo', '1.0.1'))).toBe(false)
  })

  test('a failed check on a failed plugin leaves it failed', async () => {
    db.tables.pluginInstall.set('echo', { ...row(), status: 'failed', lastError: 'worker_failed: x' })
    w.archives.get('1.0.1')!.release.sha256 = 'f'.repeat(64)
    await refusal(go('1.0.1'))
    expect(row().status).toBe('failed')
  })

  test('a new version whose worker cannot start: active, but failed', async () => {
    w.failing.add('echo@1.0.1')
    const out = await go('1.0.1')
    expect(out.plugin).toMatchObject({ status: 'failed', activeVersion: '1.0.1' })
    expect(String(out.plugin.lastError)).toMatch(/^worker_failed/)
  })

  test.each([
    ['the same version', '1.0.0', 'not_newer'],
    ['an older version (that is a rollback)', '0.9.0', 'release_not_found'],
  ])('%s is refused', async (_n, version, code) => {
    const e = await refusal(go(version))
    expect(e.code).toBe(code)
  })

  test('a plugin that is not installed cannot be updated', async () => {
    db.tables.pluginInstall.set('echo', { ...row(), status: 'available', activeVersion: null })
    expect((await refusal(go('1.0.1'))).code).toBe('not_installed')
  })
})

describe('while it runs', () => {
  test('actions answer 409, the active version keeps its run-list entry, overrides keep applying', async () => {
    await update('echo', { version: '1.1.0', acceptedPermissions: FULL }, ADMIN, w.deps)
    const { changeSetId } = await ov.propose({
      pluginId: 'echo',
      point: 'skill.text',
      scope: { type: 'user', id: 'user-alice' },
      targetGroup: 'sqli',
      parts: [{ targetKey: 'sqli/workflow', value: 'better', baseSha256: SHA }],
      createdBy: 'user-alice',
    })
    await ov.approve(changeSetId, 'user-alice', { 'sqli/workflow': SHA })

    let release!: () => void
    const gate = new Promise<void>((r) => (release = r))
    const realFetch = w.deps.fetchArchive!
    w.deps.fetchArchive = async (url) => {
      await gate
      return realFetch(url)
    }
    const running = update('echo', { version: '1.1.1', acceptedPermissions: FULL }, ADMIN, w.deps).catch((e) => e)
    await new Promise((r) => setTimeout(r, 30))
    try {
      expect(row()).toMatchObject({ status: 'updating', activeVersion: '1.1.0', pendingVersion: '1.1.1' })
      expect((row().manifest as { version: string }).version).toBe('1.1.0')
      vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', 'g'.repeat(64))
      const req = new NextRequest('http://localhost:3000/api/plugins/echo/actions/echo', {
        method: 'POST',
        headers: { 'content-type': 'application/json', host: 'localhost:3000' },
        body: JSON.stringify({ context: { projectId: 'project-alice' }, params: {} }),
      })
      const res = await runActionRoute(req, { params: Promise.resolve({ pluginId: 'echo', actionId: 'echo' }) })
      expect(res.status).toBe(409)
      expect((await res.json()).code).toBe('plugin_updating')
      expect(Object.keys(await ov.resolveForProject('project-alice'))).toEqual(['sqli/workflow'])
    } finally {
      release()
      vi.unstubAllEnvs()
    }
    const out = await running
    expect(out).not.toBeInstanceOf(Error)
    expect(row()).toMatchObject({ status: 'ready', activeVersion: '1.1.1' })
  })

  test('two updates at once: one wins', async () => {
    const results = await Promise.allSettled([go('1.0.1'), go('1.0.2')])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    const bad = results.find((r): r is PromiseRejectedResult => r.status === 'rejected')!
    expect((bad.reason as LifecycleError).code).toBe('plugin_busy')
  })
})
