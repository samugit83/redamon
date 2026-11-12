/**
 * GET /api/auth/password-policy (step 2.8, ID-20): what every password form shows next to its
 * fields and checks before sending, the policy the API applies. Any signed-in account reads it
 * (a member changing a forced password included); with the identity switch off it answers 404
 * and reads nothing, as before it existed (the forms keep Phase 1's floor).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  session: null as { userId: string; role: string } | null,
  getSession: vi.fn(),
  policy: vi.fn(),
}))
vi.mock('@/lib/session', () => ({ getSession: (...a: unknown[]) => h.getSession(...a) }))
vi.mock('@/lib/authz/passwordPolicyInForce', () => ({ passwordPolicyInForce: () => h.policy() }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { GET } from './route'

beforeEach(() => {
  vi.clearAllMocks()
  setFlagsForTests({ identity: true })
  h.getSession.mockImplementation(async () => h.session)
  h.session = { userId: 'member-1', role: 'standard' }
  h.policy.mockResolvedValue({ minLength: 16, rules: true, askChangeIfShort: true })
})
afterEach(() => setFlagsForTests(null))

describe('GET /api/auth/password-policy', () => {
  test('a signed-in account reads the policy in force and its text', async () => {
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      minLength: 16,
      maxBytes: 72,
      rules: true,
      description: 'At least 16 characters and at most 72 bytes; not a common password, not your email address or its name part, not one character repeated.',
    })
  })

  test('the sign-in prompt setting is not shown: it is the instance\'s, not the form\'s', async () => {
    expect(Object.keys(await (await GET()).json())).not.toContain('askChangeIfShort')
  })

  test('signed out: 401', async () => {
    h.session = null
    const res = await GET()
    expect(res.status).toBe(401)
    expect(h.policy).not.toHaveBeenCalled()
  })

  test('a failed read answers a coded 500, never a weaker policy', async () => {
    h.policy.mockRejectedValue(Object.assign(new Error('db down: secret-ish detail'), { code: 'P1001' }))
    const res = await GET()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.code).toBe('P1001')
    expect(JSON.stringify(body)).not.toContain('secret-ish')
  })

  test('switch off: 404 to everyone, nothing read', async () => {
    setFlagsForTests({ identity: false })
    const res = await GET()
    expect(res.status).toBe(404)
    expect(h.getSession).not.toHaveBeenCalled()
    expect(h.policy).not.toHaveBeenCalled()
  })
})
