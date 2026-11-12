/**
 * The password policy for the host scripts (create-admin.mjs, reset-password.mjs): the same
 * checks, codes and messages as src/lib/authz/passwordPolicy.ts, which a standalone script
 * cannot import. The fixed part (floor, byte bound, deny list) is read from
 * password-policy.json, the file the TypeScript policy imports; passwordPolicy.drift.test.ts
 * runs both implementations over the same cases and fails when they answer differently.
 *
 * A policy is `{minLength, rules}`: the minimum in characters (never below the floor) and
 * whether the deny list and the two rules (not the email or its local part, not one repeated
 * character) apply, which they do with the identity switch on.
 */
import { readFileSync } from 'node:fs'

export const PASSWORD_POLICY_FILE = JSON.parse(
  readFileSync(new URL('./password-policy.json', import.meta.url), 'utf8'),
)

const { floor: FLOOR, maxBytes: MAX_BYTES } = PASSWORD_POLICY_FILE
const DENY = new Set(PASSWORD_POLICY_FILE.denyList)

/** @typedef {{ minLength: number, rules: boolean }} PasswordPolicy */

/** Phase 1's policy: the floor and the byte bound only (the identity switch off). @type {Readonly<PasswordPolicy>} */
export const BASE_PASSWORD_POLICY = Object.freeze({ minLength: FLOOR, rules: false })

/** A stored minimum as the policy applies it: a whole number, never below the floor nor above the byte bound. */
export function effectiveMinLength(stored) {
  if (typeof stored !== 'number' || !Number.isInteger(stored)) return FLOOR
  return Math.min(Math.max(stored, FLOOR), MAX_BYTES)
}

/** @param {string} code @param {PasswordPolicy} [policy] */
export function passwordPolicyMessage(code, policy = BASE_PASSWORD_POLICY) {
  switch (code) {
    case 'password_too_short':
      return `Password must be at least ${effectiveMinLength(policy.minLength)} characters`
    case 'password_too_long':
      return `Password must be at most ${MAX_BYTES} bytes (a letter outside plain ASCII counts as 2 to 4)`
    case 'password_common':
      return 'This password is too common: choose one that is not on the list of common passwords'
    case 'password_is_email':
      return 'The password must not be your email address or its name part'
    default:
      return 'The password must not be one character repeated'
  }
}

function refuse(code, policy) {
  return { ok: false, code, message: passwordPolicyMessage(code, policy) }
}

/**
 * `{ok: true}`, or the first rule the password breaks: `{ok: false, code, message}`.
 * @param {string} password @param {PasswordPolicy} [policy] @param {{ email?: string }} [account]
 */
export function checkNewPassword(password, policy = BASE_PASSWORD_POLICY, { email } = {}) {
  // Characters are code points, so an emoji counts once toward the minimum.
  const chars = [...password]
  if (chars.length < effectiveMinLength(policy.minLength)) return refuse('password_too_short', policy)
  if (new TextEncoder().encode(password).length > MAX_BYTES) return refuse('password_too_long', policy)
  if (!policy.rules) return { ok: true }
  if (chars.every((c) => c === chars[0])) return refuse('password_repeated', policy)
  const lower = password.toLowerCase()
  if (DENY.has(lower)) return refuse('password_common', policy)
  if (email) {
    const address = email.trim().toLowerCase()
    const local = address.split('@')[0]
    if (lower === address || (local !== '' && lower === local)) return refuse('password_is_email', policy)
  }
  return { ok: true }
}

/**
 * The policy in force for a host command. With the identity switch off it is Phase 1's and
 * nothing is read; on, the instance settings row's minimum with the rules. A database without
 * the instance_settings table (7.7.x) or without the row reads as the floor.
 */
export async function passwordPolicyFromDatabase(prisma, { identity }) {
  if (!identity) return BASE_PASSWORD_POLICY
  const [{ present }] = await prisma.$queryRaw`SELECT to_regclass('instance_settings') IS NOT NULL AS present`
  if (!present) return { minLength: FLOOR, rules: true }
  const rows = await prisma.$queryRaw`
    SELECT password_min_length AS "minLength" FROM instance_settings WHERE id = 'instance'`
  return { minLength: effectiveMinLength(rows[0]?.minLength), rules: true }
}
