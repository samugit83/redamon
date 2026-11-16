/**
 * The project owner's catalog as a collaborator's project form reads it (§6.6 "A resource with a
 * login is used only by its owner", R-154): the owner's Tradecraft resources without a login, so
 * the Tool Matrix's "nothing to use" warning counts what the collaborator's runs can use. A
 * resource with a login is left out entirely, its name included; one the flag missed too.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({
  default: new Proxy({}, {
    get: (_t, k) => (k === 'userLlmProvider' ? { findMany: async () => [] } : (h.db.prisma as Record<string | symbol, unknown>)[k]),
  }),
}))

import { ownerCatalog } from './ownerCatalog'

beforeEach(() => {
  h.db = createTradecraftDb()
  h.db.seed('userTradecraftResource', { id: 'pub', userId: 'owner', name: 'Public wiki', slug: 'pub', url: 'https://pub.example.test/', enabled: true })
  h.db.seed('userTradecraftResource', {
    id: 'kb', userId: 'owner', name: 'Company KB', slug: 'kb', url: 'https://kb.example.test/', enabled: true,
    credentials: { cookie: 'session=fake-session' }, hasLogin: true,
  })
  h.db.seed('userTradecraftResource', {
    id: 'flagless', userId: 'owner', name: 'Old KB', slug: 'old', url: 'https://old.example.test/', enabled: true,
    credentials: { headers: [{ name: 'X-Api-Key', value: 'fake-key' }] }, hasLogin: false,
  })
  h.db.seed('userTradecraftResource', { id: 'off', userId: 'owner', name: 'Disabled', slug: 'off', url: 'https://off.example.test/', enabled: false })
  h.db.seed('userTradecraftResource', { id: 'theirs', userId: 'other', name: 'Not the owner', slug: 'x', url: 'https://x.example.test/' })
})

describe('ownerCatalog: tradecraft resources', () => {
  test('tradecraft_excludes_logins: only the owner\'s resources without a login, by name and Enabled', async () => {
    const catalog = await ownerCatalog('owner')
    expect(catalog.tradecraftResources).toEqual([
      { id: 'pub', name: 'Public wiki', enabled: true },
      { id: 'off', name: 'Disabled', enabled: false },
    ])
    expect(JSON.stringify(catalog)).not.toMatch(/Company KB|Old KB|fake-|example\.test/)
  })

  test('an owner whose only enabled resource has a login offers the matrix nothing to use', async () => {
    h.db.tables.userTradecraftResource = h.db.tables.userTradecraftResource.filter(r => r.id === 'kb' || r.id === 'off')
    expect((await ownerCatalog('owner')).tradecraftResources.some(r => r.enabled)).toBe(false)
  })
})
