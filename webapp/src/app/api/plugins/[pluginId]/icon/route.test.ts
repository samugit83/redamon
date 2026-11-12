/**
 * GET /api/plugins/[pluginId]/icon: the avatar the Plugins page shows, served from this origin
 * (the plugin pages' CSP allows no other image source) only to a signed-in user.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({ eff: null as unknown, icon: null as unknown, calls: [] as string[] }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => h.eff }))
vi.mock('@/lib/plugins/pluginIcon', () => ({
  loadPluginIcon: async (id: string) => {
    h.calls.push(id)
    return h.icon
  },
}))

import { GET } from './route'

const BYTES = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3])
const SHA = 'ab'.repeat(32)

function get(pluginId: string, query = '') {
  return GET(new NextRequest(`http://localhost/api/plugins/${pluginId}/icon${query}`), { params: Promise.resolve({ pluginId }) })
}

beforeEach(() => {
  h.eff = { userId: 'user-1' }
  h.icon = { bytes: BYTES, type: 'image/jpeg', sha256: SHA }
  h.calls = []
})

test('no session: 401, and nothing is loaded', async () => {
  h.eff = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  expect((await get('echo')).status).toBe(401)
  expect(h.calls).toEqual([])
})

describe('the image', () => {
  test('the bytes, as the sniffed type, never sniffed again by the browser', async () => {
    const res = await get('echo', `?v=${SHA.slice(0, 16)}`)
    expect(res.status).toBe(200)
    expect(Buffer.from(await res.arrayBuffer())).toEqual(BYTES)
    expect(res.headers.get('content-type')).toBe('image/jpeg')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('cache-control')).toMatch(/immutable/)
  })

  test('a version that is not the signed image any more: 404, so no old URL caches the new image', async () => {
    const res = await get('echo', `?v=${'cd'.repeat(8)}`)
    expect(res.status).toBe(404)
    expect(res.headers.get('cache-control')).toBe('no-store')
  })

  test('no icon: 404, so the card shows its placeholder', async () => {
    h.icon = null
    expect((await get('echo')).status).toBe(404)
  })

  test('an invalid plugin id is never looked up', async () => {
    expect((await get('..%2Fetc')).status).toBe(404)
    expect(h.calls).toEqual([])
  })
})
