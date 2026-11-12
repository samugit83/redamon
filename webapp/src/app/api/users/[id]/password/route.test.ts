/**
 * A password change must revoke every MCP personal access token.
 *
 * An admin can reset another user's password without knowing the current one,
 * so a reset that left live programmatic credentials behind would not actually
 * lock the account: a stolen token would keep working. The revoke shares the
 * password write's transaction, because a half-applied reset (new password, old
 * tokens still live) is worse than either outcome on its own.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  getSession: vi.fn(),
  hashPassword: vi.fn(),
  verifyPassword: vi.fn(),
  audit: vi.fn(),
  findUser: vi.fn(),
  updateUser: vi.fn(),
  updateManyTokens: vi.fn(),
  transaction: vi.fn(),
  invalidate: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: (...a: unknown[]) => h.findUser(...a),
      update: (...a: unknown[]) => h.updateUser(...a),
    },
    mcpAccessToken: { updateMany: (...a: unknown[]) => h.updateManyTokens(...a) },
    $transaction: (...a: unknown[]) => h.transaction(...a),
  },
}))
vi.mock('@/lib/session', () => ({ getSession: (...a: unknown[]) => h.getSession(...a) }))
vi.mock('@/lib/auth', () => ({
  hashPassword: (...a: unknown[]) => h.hashPassword(...a),
  verifyPassword: (...a: unknown[]) => h.verifyPassword(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/principal')>()),
  invalidatePrincipal: (...a: unknown[]) => h.invalidate(...a),
}))

import { __resetThrottle } from '@/lib/loginThrottle'
import { PUT } from './route'

const params = (id = 'owner') => ({ params: Promise.resolve({ id }) })
const req = (body: unknown) => ({ json: async () => body }) as never

beforeEach(() => {
  vi.clearAllMocks()
  h.getSession.mockResolvedValue({ userId: 'owner', role: 'standard' })
  h.hashPassword.mockResolvedValue('new-hash')
  h.verifyPassword.mockResolvedValue(true)
  h.findUser.mockResolvedValue({ password: 'old-hash' })
  h.updateUser.mockReturnValue('USER_UPDATE_OP')
  h.updateManyTokens.mockReturnValue('TOKEN_REVOKE_OP')
  // The route awaits prisma.$transaction([...]) and destructures the results.
  h.transaction.mockImplementation(async () => [{}, { count: 3 }])
  h.audit.mockResolvedValue(undefined)
  __resetThrottle()
})

describe('a self-service password change revokes the user tokens', () => {
  test('it revokes every live token in the same transaction', async () => {
    const res = await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))

    expect(res.status).toBe(200)
    expect(h.updateManyTokens).toHaveBeenCalledWith({
      where: { userId: 'owner', revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    })
    // Both operations go into ONE $transaction call.
    expect(h.transaction).toHaveBeenCalledWith(['USER_UPDATE_OP', 'TOKEN_REVOKE_OP'])
  })

  test('it reports how many tokens were revoked', async () => {
    const res = await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))
    expect(await res.json()).toMatchObject({ success: true, revokedMcpTokens: 3 })
  })

  test('already-revoked tokens are not re-stamped', async () => {
    await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))
    expect(h.updateManyTokens.mock.calls[0][0].where.revokedAt).toBeNull()
  })

  test('the revocation is audited', async () => {
    await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp-token.revoke-all',
      targetId: 'owner',
    }))
  })

  test('no audit noise when the user had no tokens', async () => {
    h.transaction.mockResolvedValue([{}, { count: 0 }])
    await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))
    // HD-14: the change itself is always audited; no revoke row when nothing was revoked.
    expect(h.audit.mock.calls.map(c => (c[0] as { action: string }).action)).toEqual(['user.password_changed'])
  })
})

describe("an admin reset also revokes the target user's tokens", () => {
  test('the reset does not leave live programmatic credentials behind', async () => {
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await PUT(req({ newPassword: 'reset-by-admin' }), params('victim'))

    expect(res.status).toBe(200)
    expect(h.updateManyTokens).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'victim', revokedAt: null } })
    )
  })

  test('the audit records that it was an admin action', async () => {
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    await PUT(req({ newPassword: 'reset-by-admin' }), params('victim'))
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      actorId: 'admin1',
      after: expect.objectContaining({ byAdmin: true }),
    }))
  })
})

describe('a refused password change revokes nothing', () => {
  test('a wrong current password leaves the tokens alone', async () => {
    h.verifyPassword.mockResolvedValue(false)
    const res = await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'wrong' }), params('owner'))

    expect(res.status).toBe(401)
    expect(h.transaction).not.toHaveBeenCalled()
    expect(h.updateManyTokens).not.toHaveBeenCalled()
  })

  test('a non-admin changing someone else changes nothing', async () => {
    h.getSession.mockResolvedValue({ userId: 'mallory', role: 'standard' })
    const res = await PUT(req({ newPassword: 'brand-new-passphrase' }), params('victim'))

    expect(res.status).toBe(403)
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('a too-short password changes nothing', async () => {
    const res = await PUT(req({ newPassword: 'ab', currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(400)
    expect(h.transaction).not.toHaveBeenCalled()
  })
})

describe('floor 12: every new password meets the one policy (HD-12)', () => {
  test('11 characters -> 400 password_too_short, nothing written', async () => {
    const res = await PUT(req({ newPassword: 'a'.repeat(11), currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'Password must be at least 12 characters', code: 'password_too_short',
    })
    expect(h.hashPassword).not.toHaveBeenCalled()
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('12 characters are accepted', async () => {
    const res = await PUT(req({ newPassword: 'a'.repeat(12), currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(200)
    expect(h.hashPassword).toHaveBeenCalledWith('a'.repeat(12))
  })

  test('73 bytes -> 400 password_too_long (bcrypt would ignore the rest)', async () => {
    const res = await PUT(req({ newPassword: 'a'.repeat(73), currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_too_long')
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('an admin reset meets the same floor', async () => {
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await PUT(req({ newPassword: 'short-reset' }), params('victim'))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_too_short')
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('a password that is not a string is refused, never hashed', async () => {
    const res = await PUT(req({ newPassword: 123456789012345, currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('password_too_short')
    expect(h.hashPassword).not.toHaveBeenCalled()
  })
})

describe('a password change the database refused', () => {
  test('answers the fixed sentence with its Prisma code', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.transaction.mockRejectedValue(Object.assign(new Error('Transaction already closed'), { code: 'P2028' }))
    const res = await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to change password', code: 'P2028' })
  })
})

// ---------------------------------------------------------------------------
// Step-up (HD-09, ID-25): another admin's reset needs the acting admin's own
// password; an admin's own change needs the current one, as a member's does.
// ---------------------------------------------------------------------------

describe('admin-on-admin resets and own changes prove the real password', () => {
  const ROWS: Record<string, { role: string; password: string }> = {
    admin1: { role: 'admin', password: 'admin1-hash' },
    admin2: { role: 'admin', password: 'admin2-hash' },
    member1: { role: 'standard', password: 'member1-hash' },
  }
  const SECRETS: Record<string, string> = { 'admin1-hash': 'admin1-pw', 'admin2-hash': 'admin2-pw', 'member1-hash': 'member1-pw' }

  beforeEach(() => {
    h.findUser.mockImplementation(async ({ where }: { where: { id: string } }) => ROWS[where.id] ?? null)
    h.verifyPassword.mockImplementation(async (pw: string, stored: string) => SECRETS[stored] === pw)
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
  })

  test('resetting an admin needs step-up', async () => {
    const missing = await PUT(req({ newPassword: 'reset-by-admin' }), params('admin2'))
    expect(missing.status).toBe(403)
    expect(await missing.json()).toEqual({ error: 'Enter your password to confirm this action.', code: 'step_up_required' })

    const wrong = await PUT(req({ newPassword: 'reset-by-admin', stepUpPassword: 'admin2-pw' }), params('admin2'))
    expect(wrong.status).toBe(403)
    expect((await wrong.json()).code).toBe('step_up_failed')
    expect(h.transaction).not.toHaveBeenCalled()

    const ok = await PUT(req({ newPassword: 'reset-by-admin', stepUpPassword: 'admin1-pw' }), params('admin2'))
    expect(ok.status).toBe(200)
    expect(h.updateManyTokens).toHaveBeenCalledWith(expect.objectContaining({ where: { userId: 'admin2', revokedAt: null } }))
  })

  test('the step-up checks the acting admin, never the target', async () => {
    await PUT(req({ newPassword: 'reset-by-admin', stepUpPassword: 'admin1-pw' }), params('admin2'))
    expect(h.verifyPassword).toHaveBeenCalledWith('admin1-pw', 'admin1-hash')
    expect(h.verifyPassword).not.toHaveBeenCalledWith(expect.anything(), 'admin2-hash')
  })

  test('an admin changing their own password needs the current one', async () => {
    const missing = await PUT(req({ newPassword: 'new-own-passphrase' }), params('admin1'))
    expect(missing.status).toBe(400)
    expect(await missing.json()).toEqual({ error: 'Current password is required', code: 'step_up_required' })

    const wrong = await PUT(req({ newPassword: 'new-own-passphrase', currentPassword: 'guess' }), params('admin1'))
    expect(wrong.status).toBe(401)
    expect(await wrong.json()).toEqual({ error: 'Current password is incorrect', code: 'step_up_failed' })
    expect(h.transaction).not.toHaveBeenCalled()

    const ok = await PUT(req({ newPassword: 'new-own-passphrase', currentPassword: 'admin1-pw' }), params('admin1'))
    expect(ok.status).toBe(200)
  })

  test('an admin cannot skip the current password with a step-up field', async () => {
    const res = await PUT(req({ newPassword: 'new-own-passphrase', stepUpPassword: 'admin1-pw' }), params('admin1'))
    expect(res.status).toBe(400)
    expect(h.transaction).not.toHaveBeenCalled()
  })

  test('a member target needs no step-up', async () => {
    const res = await PUT(req({ newPassword: 'reset-by-admin' }), params('member1'))
    expect(res.status).toBe(200)
    expect(h.verifyPassword).not.toHaveBeenCalled()
  })

  test('wrong current passwords lock the own change like every step-up (429 step_up_locked)', async () => {
    h.getSession.mockResolvedValue({ userId: 'member1', role: 'standard' })
    for (let i = 0; i < 5; i++) {
      expect((await PUT(req({ newPassword: 'new-own-passphrase', currentPassword: 'guess' }), params('member1'))).status).toBe(401)
    }
    h.verifyPassword.mockClear()
    const locked = await PUT(req({ newPassword: 'new-own-passphrase', currentPassword: 'member1-pw' }), params('member1'))
    expect(locked.status).toBe(429)
    expect((await locked.json()).code).toBe('step_up_locked')
    expect(h.verifyPassword).not.toHaveBeenCalled()
    expect(h.transaction).not.toHaveBeenCalled()
  })
})

describe('a password write drops the account from the principal cache (step 2.2)', () => {
  test('an own change and an admin reset, after the write', async () => {
    h.transaction.mockImplementation(async () => {
      expect(h.invalidate).not.toHaveBeenCalled()
      return [{}, { count: 0 }]
    })
    expect((await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'old' }), params('owner'))).status).toBe(200)
    expect(h.invalidate).toHaveBeenCalledWith('owner')
    h.invalidate.mockClear()
    h.getSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    h.findUser.mockResolvedValue({ role: 'standard' })
    expect((await PUT(req({ newPassword: 'reset-by-admin' }), params('victim'))).status).toBe(200)
    expect(h.invalidate).toHaveBeenCalledWith('victim')
  })

  test('a refused change drops nothing', async () => {
    h.verifyPassword.mockResolvedValue(false)
    expect((await PUT(req({ newPassword: 'brand-new-passphrase', currentPassword: 'wrong' }), params('owner'))).status).toBe(401)
    expect(h.invalidate).not.toHaveBeenCalled()
  })
})
