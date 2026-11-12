/**
 * GET /api/plugins/llm-features: the plugins a user can choose a model for in Models by
 * feature (TD-10, F-16): installed, enabled, holding `llm:invoke` granted and declared,
 * with an `llmFeature` description in the manifest.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, eff: null as unknown }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => h.eff }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { GET } from './route'

let db: FakePrisma

function row(pluginId: string, over: Record<string, unknown> = {}, manifest: Record<string, unknown> = {}) {
  return {
    pluginId,
    enabled: true,
    status: 'ready',
    activeVersion: '1.0.0',
    grantedPermissions: ['llm:invoke', 'session:read'],
    manifest: {
      id: pluginId,
      displayName: pluginId[0].toUpperCase() + pluginId.slice(1),
      permissions: ['llm:invoke', 'session:read'],
      llmFeature: { description: `${pluginId} analyses sessions` },
      ...manifest,
    },
    ...over,
  }
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.eff = { userId: 'user-1' }
})

test('no session: 401', async () => {
  h.eff = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  expect((await GET(new NextRequest('http://localhost/api/plugins/llm-features'))).status).toBe(401)
})

describe('the list', () => {
  test('only qualifying plugins, by id, with the manifest label and description', async () => {
    db.seed('pluginInstall', [
      row('skiller'),
      row('updating', { status: 'updating' }),
      row('disabled', { enabled: false }),
      row('revoked', { revokedReason: 'revoked' }),
      row('failed', { status: 'failed' }),
      row('notgranted', { grantedPermissions: ['session:read'] }),
      row('notdeclared', {}, { permissions: ['session:read'] }),
      row('nofeature', {}, { llmFeature: undefined }),
      row('nomanifest', { manifest: null }),
      row('available', { status: 'available', enabled: false }),
    ])
    const res = await GET(new NextRequest('http://localhost/api/plugins/llm-features'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual([
      { featureId: 'plugin:skiller', pluginId: 'skiller', label: 'Skiller', description: 'skiller analyses sessions' },
      { featureId: 'plugin:updating', pluginId: 'updating', label: 'Updating', description: 'updating analyses sessions' },
    ])
  })

  test('none installed: an empty list', async () => {
    expect(await (await GET(new NextRequest('http://localhost/api/plugins/llm-features'))).json()).toEqual([])
  })
})
