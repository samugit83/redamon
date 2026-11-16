/**
 * The one lookup of a resource by id and account (D-27), and the 1.x column list (D-44).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import fixture from '@/lib/authz/__fixtures__/schema-7.7.2-fields.json'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { LEGACY_SELECT, loadOwnLegacyResource, loadOwnResource, lockOwnResource } from './resourceAccess'

beforeEach(() => {
  h.db = createTradecraftDb()
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/',
    githubTokenOverride: 'ghp_fake_1', credentials: { cookie: 'session=fake-session' }, hasLogin: true,
    overrides: { 'crawl.maxPages': 50 }, settingsSnapshot: { values: {} }, storageMode: 'stored',
  })
})

describe('resourceAccess', () => {
  test('LEGACY_SELECT is exactly the 7.7.2 columns of user_tradecraft_resources', () => {
    const scalar = Object.entries((fixture as { models: Record<string, { fields: Record<string, { type: string }> }> }).models.UserTradecraftResource.fields)
      .filter(([, f]) => f.type !== 'User').map(([name]) => name).sort()
    expect(Object.keys(LEGACY_SELECT).sort()).toEqual(scalar)
  })

  test('loadOwnResource: the whole row of the account, nothing of another account', async () => {
    expect((await loadOwnResource('owner', 'r1'))?.credentials).toEqual({ cookie: 'session=fake-session' })
    expect(await loadOwnResource('other', 'r1')).toBeNull()
    expect(await loadOwnResource('owner', 'missing')).toBeNull()
  })

  test('loadOwnLegacyResource: the 1.x columns only', async () => {
    const row = await loadOwnLegacyResource('owner', 'r1')
    expect(Object.keys(row!).sort()).toEqual(Object.keys(LEGACY_SELECT).sort())
    for (const col of ['credentials', 'hasLogin', 'overrides', 'settingsSnapshot', 'storageMode']) expect(row).not.toHaveProperty(col)
    expect(await loadOwnLegacyResource('other', 'r1')).toBeNull()
  })

  test('lockOwnResource locks the row by id and account', async () => {
    const transaction = h.db.prisma.$transaction as (fn: (tx: never) => Promise<void>) => Promise<void>
    await transaction(async (tx: never) => {
      expect(await lockOwnResource(tx, 'owner', 'r1')).toBe(true)
      expect(await lockOwnResource(tx, 'other', 'r1')).toBe(false)
    })
    expect(h.db.raw.map(r => r.values)).toEqual([['r1', 'owner'], ['r1', 'other']])
    expect(h.db.raw[0].sql).toMatch(/FOR UPDATE$/)
  })
})
