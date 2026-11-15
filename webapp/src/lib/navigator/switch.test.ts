/**
 * Root's AI Navigator switch (plan §5.5): identity off reads on; a row answers its value; a failed
 * read throws, never reads as on.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ row: null as null | { navigatorEnabled: boolean } | 'throw' }))
vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => {
    if (h.row === 'throw') throw new Error('db down')
    return h.row
  },
}))
import { navigatorEnabled } from './switch'

beforeEach(() => { h.row = null })

describe('navigatorEnabled', () => {
  test('no row (identity off, or before the backfill): on', async () => {
    expect(await navigatorEnabled()).toBe(true)
  })
  test('a row answers its value', async () => {
    h.row = { navigatorEnabled: false }
    expect(await navigatorEnabled()).toBe(false)
    h.row = { navigatorEnabled: true }
    expect(await navigatorEnabled()).toBe(true)
  })
  test('a failed read throws', async () => {
    h.row = 'throw'
    await expect(navigatorEnabled()).rejects.toThrow()
  })
})
