/**
 * The one policy every NEW password meets (HD-12, ID-20): the admin create form, the set and
 * change modals, the change page, POST /api/users and PUT /api/users/[id]/password. Passwords
 * set before a rule existed stay valid; sign-in never applies it (it may only ask for a change,
 * passwordPolicyInForce.ts).
 *
 * A policy is `{minLength, rules}`. With the identity switch off it is Phase 1's: the floor and
 * the 72-byte bound. On, the instance's minimum (never below the floor) and `rules`: a deny list
 * of common passwords, not the account's email or its local part, not one repeated character.
 *
 * Pure (no server imports), so the pages check with it too and show the server's own message.
 * The fixed part lives in scripts/lib/password-policy.json, which the host scripts read through
 * scripts/lib/passwordRules.mjs (they cannot import TypeScript); redamon.sh and the single-host
 * deploy.sh keep their own floor. passwordPolicy.drift.test.ts fails when any copy drifts.
 */
import policyFile from '../../../scripts/lib/password-policy.json'

export const MIN_PASSWORD_LENGTH: number = policyFile.floor
/** bcrypt reads only the first 72 bytes: a longer password would match any string sharing them. */
export const MAX_PASSWORD_BYTES: number = policyFile.maxBytes
/** Common passwords of floor length or more, lowercase; compared ignoring case. */
export const DENY_LIST: readonly string[] = Object.freeze([...policyFile.denyList])
const DENY = new Set(DENY_LIST)

export interface PasswordPolicy {
  /** Characters (code points), never below MIN_PASSWORD_LENGTH. */
  minLength: number
  /** The deny list and the email and repeated-character rules. */
  rules: boolean
}

/** Phase 1's policy: the floor and the byte bound only (the identity switch off). */
export const BASE_PASSWORD_POLICY: Readonly<PasswordPolicy> = Object.freeze({ minLength: MIN_PASSWORD_LENGTH, rules: false })

export type PasswordPolicyCode =
  | 'password_too_short' | 'password_too_long' | 'password_common' | 'password_is_email' | 'password_repeated'

export type PasswordCheck =
  | { ok: true }
  | { ok: false; code: PasswordPolicyCode; message: string }

/** A stored minimum as the policy applies it: a whole number, never below the floor nor above the byte bound. */
export function effectiveMinLength(stored: unknown): number {
  if (typeof stored !== 'number' || !Number.isInteger(stored)) return MIN_PASSWORD_LENGTH
  return Math.min(Math.max(stored, MIN_PASSWORD_LENGTH), MAX_PASSWORD_BYTES)
}

export function passwordPolicyMessage(code: PasswordPolicyCode, policy: PasswordPolicy = BASE_PASSWORD_POLICY): string {
  switch (code) {
    case 'password_too_short':
      return `Password must be at least ${effectiveMinLength(policy.minLength)} characters`
    case 'password_too_long':
      return `Password must be at most ${MAX_PASSWORD_BYTES} bytes (a letter outside plain ASCII counts as 2 to 4)`
    case 'password_common':
      return 'This password is too common: choose one that is not on the list of common passwords'
    case 'password_is_email':
      return 'The password must not be your email address or its name part'
    default:
      return 'The password must not be one character repeated'
  }
}

function refuse(code: PasswordPolicyCode, policy: PasswordPolicy): PasswordCheck {
  return { ok: false, code, message: passwordPolicyMessage(code, policy) }
}

/** `{ok: true}`, or the first rule the password breaks. `email`: the account the password is for. */
export function validateNewPassword(
  pw: string,
  policy: PasswordPolicy = BASE_PASSWORD_POLICY,
  { email }: { email?: string } = {},
): PasswordCheck {
  // Characters are code points, so an emoji counts once toward the minimum.
  const chars = [...pw]
  if (chars.length < effectiveMinLength(policy.minLength)) return refuse('password_too_short', policy)
  if (new TextEncoder().encode(pw).length > MAX_PASSWORD_BYTES) return refuse('password_too_long', policy)
  if (!policy.rules) return { ok: true }
  if (chars.every((c) => c === chars[0])) return refuse('password_repeated', policy)
  const lower = pw.toLowerCase()
  if (DENY.has(lower)) return refuse('password_common', policy)
  if (email) {
    const address = email.trim().toLowerCase()
    const local = address.split('@')[0]
    if (lower === address || (local !== '' && lower === local)) return refuse('password_is_email', policy)
  }
  return { ok: true }
}

/** The sentence shown next to every password field. */
export function describePasswordPolicy(policy: PasswordPolicy): string {
  const length = `At least ${effectiveMinLength(policy.minLength)} characters and at most ${MAX_PASSWORD_BYTES} bytes`
  return policy.rules
    ? `${length}; not a common password, not your email address or its name part, not one character repeated.`
    : `${length}.`
}
