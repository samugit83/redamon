/**
 * POST /api/plugins/overrides/reset (design §6; TD-18, OQ-23): the scope's active version
 * becomes cleared. Core UI, so it works with the plugin disabled or uninstalled-keep; only
 * the scope owner (or an admin acting as them); a user-scope reset carries the scope owner id.
 *
 * @vitest-environment node
 */
import { test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, session: null as unknown, effective: '', managed: new Set<string>(), audits: [] as Record<string, unknown>[] }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
// The account write rule (HD-23) over the session double: an admin acting as the owner
// writes a user scope only while the owner is a passwordless managed account (h.managed).
vi.mock('@/lib/session', async () => {
  const { accountWriteDouble } = await import('@/lib/plugins/__testing__/accountWriteDouble')
  return {
    getSession: async () => h.session,
    getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null),
    requireAccountWrite: accountWriteDouble(() => h),
  }
})
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: async () => new Response('{}', { status: 404 }) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { projectScope, seedProposal, seedWorld, sha256, userScope, FACTORY } from '@/lib/plugins/__testing__/reviewHarness'
import * as ov from '@/lib/plugins/overrides'
import { POST } from './route'

let db: FakePrisma
const H = () => ({ 'ssrf/workflow': sha256(FACTORY.workflow) })

const reset = (data: Record<string, unknown>, origin = 'http://localhost:3000') =>
  POST(new Request('http://localhost:3000/api/plugins/overrides/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', origin, host: 'localhost:3000' },
    body: JSON.stringify(data),
  }) as never)

async function activeUserVersion(): Promise<string> {
  const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  return cs
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.session = { userId: 'alice', role: 'standard' }
  h.effective = 'alice'
  h.managed = new Set()
  h.audits = []
})

test('clears the active user-scope version and audits', async () => {
  const cs = await activeUserVersion()
  const res = await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice' })
  expect(res.status).toBe(200)
  expect((await res.json()).cleared).toBe(true)
  expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('cleared')
  expect(h.audits.some((a) => a.action === 'plugin.override.reset')).toBe(true)
})

test('reset with the plugin disabled still works (it never touches the plugin)', async () => {
  const cs = await activeUserVersion()
  await db.pluginInstall.update({ where: { pluginId: 'skiller' }, data: { enabled: false } })
  const res = await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice' })
  expect(res.status).toBe(200)
  expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('cleared')
})

test('reset with the plugin uninstalled-keep still works', async () => {
  const cs = await activeUserVersion()
  await db.pluginInstall.update({ where: { pluginId: 'skiller' }, data: { status: 'available', enabled: false } })
  const res = await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice' })
  expect(res.status).toBe(200)
  expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('cleared')
})

test('nothing active: cleared is false', async () => {
  const res = await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice' })
  expect(res.status).toBe(200)
  expect((await res.json()).cleared).toBe(false)
})

test('a user-scope scopeOwnerId other than the effective user: 404', async () => {
  await activeUserVersion()
  expect((await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'bob' })).status).toBe(404)
})

test('a project reset the caller does not own: 404', async () => {
  const cs = await seedProposal(projectScope('p-bob'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  expect((await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'project', projectId: 'p-bob' })).status).toBe(404)
})

test('a project reset the caller owns clears it', async () => {
  const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
  await ov.approve(cs, 'alice', H())
  const res = await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'project', projectId: 'p-alice' })
  expect(res.status).toBe(200)
  expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('cleared')
})

test('an admin acting as the owner, a passwordless managed account, can reset; the audit actor is the admin', async () => {
  const cs = await activeUserVersion()
  h.session = { userId: 'admin-1', role: 'admin' }
  h.effective = 'alice'
  h.managed = new Set(['alice'])
  const res = await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice' })
  expect(res.status).toBe(200)
  expect(db.rows('pluginOverride').find((r) => r.changeSetId === cs)!.status).toBe('cleared')
  expect(h.audits.find((a) => a.action === 'plugin.override.reset')!.actorId).toBe('admin-1')
})

test('cross-origin: 403', async () => {
  await activeUserVersion()
  expect((await reset({ point: 'skill.text', group: 'ssrf', scopeType: 'user', scopeOwnerId: 'alice' }, 'https://evil.example')).status).toBe(403)
})

test('bad point or unknown skill: 400', async () => {
  expect((await reset({ point: 'nav', group: 'ssrf', scopeType: 'user' })).status).toBe(400)
  expect((await reset({ point: 'skill.text', group: 'nope', scopeType: 'user' })).status).toBe(400)
})
