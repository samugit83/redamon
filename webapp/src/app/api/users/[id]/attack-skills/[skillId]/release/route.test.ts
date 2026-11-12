/**
 * POST /api/users/[id]/attack-skills/[skillId]/release (plan 4.10): only the owner, by a
 * strict match on the session user (not requireUserAccess's admin bypass), same-origin, and
 * only a quarantined skill.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as { userId: string; role: string } | null,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
// requireUserAccess lets any admin through; the route must not rely on it.
vi.mock('@/lib/session', () => ({
  getSession: async () => h.session,
  requireUserAccess: async () => null,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { POST } from './route'

let db: FakePrisma
const QUARANTINED_AT = new Date('2026-10-01T00:00:00Z')

function release(skillId: string, { id = 'alice', origin = 'http://localhost:3000' as string | null } = {}) {
  const headers: Record<string, string> = { host: 'localhost:3000' }
  if (origin) headers.origin = origin
  return POST(
    new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills/${skillId}/release`, { method: 'POST', headers }),
    { params: Promise.resolve({ id, skillId }) },
  )
}
const skill = (id: string) => db.rows('userAttackSkill').find((r) => r.id === id)!

beforeEach(() => {
  vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.session = { userId: 'alice', role: 'standard' }
  h.audits = []
  db.seed('userAttackSkill', [
    { id: 'sk_q', userId: 'alice', name: 'Revoked flow', content: 'x', quarantinedAt: QUARANTINED_AT, quarantineReason: 'plugin_version_revoked' },
    { id: 'sk_clean', userId: 'alice', name: 'Clean flow', content: 'x' },
    { id: 'sk_bob_q', userId: 'bob', name: 'Bob revoked', content: 'x', quarantinedAt: QUARANTINED_AT, quarantineReason: 'plugin_version_revoked' },
  ])
})

describe('release', () => {
  test('the owner, same origin: the quarantine is cleared and audited as the owner', async () => {
    const res = await release('sk_q')
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ id: 'sk_q', quarantinedAt: null, quarantineReason: null })
    expect(skill('sk_q')).toMatchObject({ quarantinedAt: null, quarantineReason: null })
    expect(h.audits).toEqual([expect.objectContaining({ actorId: 'alice', action: 'user_attack_skill.release', targetId: 'sk_q' })])
    expect(h.audits[0].after).not.toHaveProperty('onBehalfOf')
  })

  test('a request without Origin (not a browser) passes the origin check', async () => {
    expect((await release('sk_q', { origin: null })).status).toBe(200)
  })

  test('an admin session for another user is 403 owner_only, though requireUserAccess would admit it', async () => {
    h.session = { userId: 'admin1', role: 'admin' }
    const res = await release('sk_q')
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('owner_only')
    expect(skill('sk_q').quarantinedAt).toEqual(QUARANTINED_AT)
    expect(h.audits).toEqual([])
  })

  test('another standard user is 403 owner_only', async () => {
    h.session = { userId: 'bob', role: 'standard' }
    expect((await (await release('sk_q')).json()).code).toBe('owner_only')
  })

  test('no session is 401', async () => {
    h.session = null
    expect((await release('sk_q')).status).toBe(401)
    expect(skill('sk_q').quarantinedAt).toEqual(QUARANTINED_AT)
  })

  test('a cross-origin request is refused before anything is read', async () => {
    const res = await release('sk_q', { origin: 'https://evil.example' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(skill('sk_q').quarantinedAt).toEqual(QUARANTINED_AT)
    expect(db.transactions).toBe(0)
  })

  test('a malformed Origin is refused', async () => {
    expect((await release('sk_q', { origin: 'not a url' })).status).toBe(403)
  })

  test('409 not_quarantined for a skill that is not quarantined', async () => {
    const res = await release('sk_clean')
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('not_quarantined')
  })

  test("404 for an unknown skill and for another user's, from the owner's path", async () => {
    for (const id of ['sk_nope', 'sk_bob_q']) {
      const res = await release(id)
      expect(res.status).toBe(404)
      expect((await res.json()).code).toBe('not_found')
    }
    expect(skill('sk_bob_q').quarantinedAt).toEqual(QUARANTINED_AT)
  })
})
