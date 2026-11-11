/**
 * The signed-in account as the database holds it now. The login JWT lives 7 days
 * and carries a role, so trusting it kept a demoted or deleted admin's powers until
 * the cookie expired; the session helpers read role and existence here instead, on
 * every request, so a change takes effect on the account's next request.
 *
 * No cache yet: one indexed read by primary key per call.
 */
import prisma from '@/lib/prisma'

export interface Principal {
  id: string
  email: string
  role: string
  /** False for a passwordless (managed) account, which can never sign in itself. */
  hasPassword: boolean
  createdAt: Date
  /** The shared tools the account kept at the RBAC upgrade (authz/sharedTools.ts). */
  legacyGrants: string[]
}

/** The account `userId` names, or null when it no longer exists. A failed read throws. */
export async function loadPrincipal(userId: string): Promise<Principal | null> {
  if (!userId) return null
  // Prisma cannot select `password <> ''`, so the hash is read and reduced to a
  // boolean here; it never leaves this function.
  const row = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, role: true, password: true, createdAt: true, legacyGrants: true },
  })
  if (!row) return null
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    hasPassword: row.password !== '',
    createdAt: row.createdAt,
    legacyGrants: Array.isArray(row.legacyGrants) ? row.legacyGrants : [],
  }
}
