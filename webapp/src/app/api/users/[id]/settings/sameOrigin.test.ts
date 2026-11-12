/**
 * PUT /api/users/[id]/settings accepts only same-origin JSON (step 2.12, ID-26, T14). The row holds
 * the account's provider keys and, with the identity switch off, the instance's tunnel and capture
 * policy: a request whose Origin is another site is refused with 403 `cross_origin`, and a body
 * that is not JSON with 415, before the settings row is read or written. The access check answers
 * first; a request without an Origin (a script, a server-side caller) and one from this host pass.
 * Whatever the identity switch says.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  upsert: vi.fn(),
  access: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      upsert: (...a: unknown[]) => h.upsert(...a),
    },
    apiKeyRotationConfig: { findMany: async () => [] },
  },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => h.access(...a),
  isInternalRequest: () => false,
  isScannerRequest: () => false,
  getSession: async () => ({ userId: 'u1', role: 'standard' }),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { PUT } from './route'

const HOST = 'redamon.test'
const params = { params: Promise.resolve({ id: 'u1' }) }

function put(opts: { origin?: string; contentType?: string | null; body?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: HOST }
  if (opts.origin) headers.origin = opts.origin
  const contentType = opts.contentType === undefined ? 'application/json' : opts.contentType
  if (contentType) headers['content-type'] = contentType
  return new NextRequest(`http://${HOST}/api/users/u1/settings`, {
    method: 'PUT', headers, body: opts.body ?? JSON.stringify({ shodanApiKey: 'new-shodan-key-0001' }),
  })
}

beforeEach(() => {
  h.findUnique.mockReset().mockResolvedValue({ userId: 'u1', shodanApiKey: '' })
  h.upsert.mockReset().mockImplementation(async ({ update }: { update: Record<string, unknown> }) => ({ userId: 'u1', ...update }))
  h.access.mockReset().mockResolvedValue(null)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

for (const identity of [false, true]) {
  describe(`PUT /api/users/[id]/settings, same-origin JSON (switch ${identity ? 'on' : 'off'})`, () => {
    beforeEach(() => setFlagsForTests({ identity }))

    test('cross-origin refused before the row is read', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
      const res = await PUT(put({ origin: 'https://evil.example' }), params)
      expect(res.status).toBe(403)
      expect(await res.json()).toMatchObject({ code: 'cross_origin' })
      expect(h.findUnique).not.toHaveBeenCalled()
      expect(h.upsert).not.toHaveBeenCalled()
      expect(warn).toHaveBeenCalled()
    })

    test('a body that is not JSON 415, JSON that does not parse 400, nothing read', async () => {
      for (const [contentType, body] of [
        ['text/plain', JSON.stringify({ shodanApiKey: 'x' })],
        ['application/x-www-form-urlencoded', 'shodanApiKey=x'],
        [null, JSON.stringify({ shodanApiKey: 'x' })],
      ] as const) {
        expect((await PUT(put({ origin: `http://${HOST}`, contentType, body }), params)).status).toBe(415)
      }
      expect((await PUT(put({ origin: `http://${HOST}`, body: '{"shodanApiKey":' }), params)).status).toBe(400)
      expect(h.findUnique).not.toHaveBeenCalled()
      expect(h.upsert).not.toHaveBeenCalled()
    })

    test('the access check answers first', async () => {
      h.access.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
      const res = await PUT(put({ origin: 'https://evil.example' }), params)
      expect(res.status).toBe(401)
    })

    test('from this host and without an Origin the save goes through', async () => {
      for (const origin of [`http://${HOST}`, undefined]) {
        h.upsert.mockClear()
        const res = await PUT(put({ origin }), params)
        expect(res.status).toBe(200)
        expect(h.upsert).toHaveBeenCalledTimes(1)
      }
    })
  })
}
