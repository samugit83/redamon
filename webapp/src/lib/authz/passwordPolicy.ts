/**
 * The one rule every NEW password meets: the admin create form, the set and
 * change modals, POST /api/users and PUT /api/users/[id]/password. Passwords set
 * before the rule existed stay valid; sign-in never applies it.
 *
 * Pure (no server imports), so the settings page uses it too and shows the
 * server's own message.
 *
 * The host scripts repeat MIN_PASSWORD_LENGTH (webapp/scripts/create-admin.mjs,
 * reset-password.mjs, redamon.sh MIN_ADMIN_PASSWORD_LEN, the single-host
 * deploy.sh): passwordPolicy.drift.test.ts fails when one of them drifts.
 */

export const MIN_PASSWORD_LENGTH = 12
/** bcrypt reads only the first 72 bytes: a longer password would match any string sharing them. */
export const MAX_PASSWORD_BYTES = 72

export type PasswordPolicyCode = 'password_too_short' | 'password_too_long'

export type PasswordCheck =
  | { ok: true }
  | { ok: false; code: PasswordPolicyCode; message: string }

export function passwordPolicyMessage(code: PasswordPolicyCode): string {
  return code === 'password_too_short'
    ? `Password must be at least ${MIN_PASSWORD_LENGTH} characters`
    : `Password must be at most ${MAX_PASSWORD_BYTES} bytes (a letter outside plain ASCII counts as 2 to 4)`
}

export function validateNewPassword(pw: string): PasswordCheck {
  // Characters are code points, so an emoji counts once toward the floor.
  if ([...pw].length < MIN_PASSWORD_LENGTH) {
    return { ok: false, code: 'password_too_short', message: passwordPolicyMessage('password_too_short') }
  }
  if (new TextEncoder().encode(pw).length > MAX_PASSWORD_BYTES) {
    return { ok: false, code: 'password_too_long', message: passwordPolicyMessage('password_too_long') }
  }
  return { ok: true }
}
