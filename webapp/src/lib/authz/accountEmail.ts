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

export function normalizeEmail(email: string): string {
  return email.toLowerCase()
}

export interface SignInAccount {
  id: string
  name: string
  email: string
  password: string
  role: string
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
    SELECT id, name, email, password, role FROM users WHERE lower(email) = lower(${email})`
  return rows.find(r => r.email === email) ?? (rows.length === 1 ? rows[0] : null)
}

/** True when an account other than `exceptUserId` holds `email`, ignoring case. */
export async function emailTakenByAnother(email: string, exceptUserId?: string): Promise<boolean> {
  const rows = await prisma.$queryRaw<{ id: string }[]>`
    SELECT id FROM users WHERE lower(email) = lower(${email})`
  return rows.some(r => r.id !== exceptUserId)
}
