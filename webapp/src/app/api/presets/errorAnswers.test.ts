/**
 * The recon preset routes answer a failure they did not expect with a fixed sentence and the
 * cause's code. They used to answer the exception's own message, which for Prisma quotes the
 * query: a preset's settings, and through them a target or a credential.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => {
  const dbError = () => Object.assign(
    new Error('Invalid `prisma.userProjectPreset.create()` invocation: { settings: { target: "SECRET-TARGET" } }'),
    { name: 'PrismaClientKnownRequestError', code: 'P2024' },
  )
  const down: unknown = new Proxy(function failing() {}, {
    get: () => down,
    apply: () => { throw dbError() },
  })
  return { down }
})

vi.mock('@/lib/prisma', () => ({ default: h.down }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'u1' }),
  assertOwner: () => null,
  ownerScope: () => ({ userId: 'u1' }),
}))

import { GET as listPresets, POST as createPreset } from './route'
import { GET as getPreset, DELETE as deletePreset } from './[id]/route'

const one = { params: Promise.resolve({ id: 'up1' }) }

const CASES: [string, () => Promise<Response>, string][] = [
  ['GET the list', () => listPresets(new NextRequest('http://x/api/presets')), 'Failed to fetch presets'],
  ['POST a preset', () => createPreset(new NextRequest('http://x/api/presets', {
    method: 'POST', body: JSON.stringify({ name: 'Mine', settings: { naabuEnabled: true } }),
  })), 'Failed to create preset'],
  ['GET one preset', () => getPreset(new NextRequest('http://x/api/presets/up1'), one), 'Failed to fetch preset'],
  ['DELETE one preset', () => deletePreset(new NextRequest('http://x/api/presets/up1', { method: 'DELETE' }), one), 'Failed to delete preset'],
]

beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })
afterEach(() => { vi.restoreAllMocks() })

describe('a database that is down', () => {
  test.each(CASES)('%s: 500 with the fixed sentence and the Prisma code, never the message', async (_name, call, error) => {
    const res = await call()
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error, code: 'P2024' })
    expect(text).not.toContain('SECRET-TARGET')
    expect(text).not.toContain('prisma')
  })
})
