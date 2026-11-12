/**
 * Account emails, compared the way people type them. New accounts and email
 * edits are stored lowercase; accounts created before that may still hold
 * capitals, so lookups compare ignoring case and prefer an exact match.
 *
 * Not Prisma's `mode: 'insensitive'`: on Postgres it compiles `equals` to ILIKE,
 * where `_` and `%` are wildcards, so `a_min@x` would find `admin@x` and each
 * such spelling would count against its own lockout key. These lookups compare
 * lower() on both sides with the email as a bound parameter.
 */
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { now } from './clock'

export function normalizeEmail(email: string): string {
  return email.toLowerCase()
}

/**
 * What a sign-in needs, in one row: the account and its state. The session version goes
 * into the login token; status, the must-change flag and the last sign-in are read here
 * so the sign-in checks that use them add no second query (one read on every path).
 */
export interface SignInAccount {
  id: string
  name: string
  email: string
  password: string
  role: string
  status: string
  sessionVersion: number
  mustChangePassword: boolean
  lastLoginAt: Date | null
}

/**
 * The account a sign-in names: the exact email when an account holds it, else
 * the single account whose email equals it ignoring case. Two case variants and
 * no exact match name nobody: picking one would sign into an account chosen by
 * row order.
 *
 * One query on every path, so an unknown email costs the same reads as a known one.
 */
export async function findSignInAccount(email: string): Promise<SignInAccount | null> {
  const rows = await prisma.$queryRaw<SignInAccount[]>`
    SELECT id, name, email, password, role, status, session_version AS "sessionVersion", must_change_password AS "mustChangePassword", last_login_at AS "lastLoginAt" FROM users WHERE lower(email) = lower(${email})`
  return rows.find(r => r.email === email) ?? (rows.length === 1 ? rows[0] : null)
}

/**
 * Records a successful sign-in's time. Raw, so the account's `updated_at`, which the Users
 * page shows as its last change, does not move; the time is bound as UTC, how Prisma
 * stores every DateTime. Never fails the sign-in: a lost timestamp is logged, not raised.
 */
export async function recordSignIn(userId: string): Promise<void> {
  try {
    await prisma.$executeRaw`
      UPDATE users SET last_login_at = (${now().toISOString()}::timestamptz AT TIME ZONE 'UTC') WHERE id = ${userId}`
  } catch (err) {
    console.error(`[rbac] last-login write failed user=${userId} code=${safeErrorCode(err)}`)
  }
}

/** True when an account other than `exceptUserId` holds `email`, ignoring case. */
export async function emailTakenByAnother(email: string, exceptUserId?: string): Promise<boolean> {
  const rows = await prisma.$queryRaw<{ id: string }[]>`
    SELECT id FROM users WHERE lower(email) = lower(${email})`
  return rows.some(r => r.id !== exceptUserId)
}
