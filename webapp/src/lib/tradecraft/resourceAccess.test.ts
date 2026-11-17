/**
 * The one lookup of a resource by id and account (D-27), and the 1.x column list (D-44).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { loadOwnResource, lockOwnResource } from './resourceAccess'

beforeEach(() => {
  h.db = createTradecraftDb()
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/',
    githubTokenOverride: 'ghp_fake_1', credentials: { cookie: 'session=fake-session' }, hasLogin: true,
    overrides: { 'crawl.maxPages': 50 }, settingsSnapshot: { values: {} }, storageMode: 'stored',
  })
})

describe('resourceAccess', () => {
  test('loadOwnResource: the whole row of the account, nothing of another account', async () => {
    expect((await loadOwnResource('owner', 'r1'))?.credentials).toEqual({ cookie: 'session=fake-session' })
    expect(await loadOwnResource('other', 'r1')).toBeNull()
    expect(await loadOwnResource('owner', 'missing')).toBeNull()
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
