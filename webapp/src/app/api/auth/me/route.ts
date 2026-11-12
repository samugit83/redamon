import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '@/lib/session'
import { internalError, safeErrorCode } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { pendingLegacyGrantCount } from '@/lib/authz/updateReview'
import type { AdminNotices } from '@/providers/AuthProvider'

/**
 * What the header's admin banners show (step 1.18). Never fails the session, which the
 * whole app reads: a failed count is `null`, and the banner that needs it stays hidden.
 */
async function adminNotices(): Promise<AdminNotices> {
  let legacyGrantsPending: number | null = null
  try {
    legacyGrantsPending = await pendingLegacyGrantCount()
  } catch (err) {
    console.error(`[rbac] could not read the legacy grant review: ${safeErrorCode(err)}`)
  }
  const flags = rbacFlags()
  // `identity` only while the switch is on (the Users page then offers disable and sign-out),
  // so with it off the answer is exactly the one before the switch existed.
  return { compat: flags.sharedToolsCompat, legacyGrantsPending, ...(flags.identity ? { identity: true } : {}) }
}

export async function GET() {
  try {
    const session = await getSession()
    if (!session) {
      // With the identity switch on getSession cleared the refused cookie, and the code sends
      // the browser to sign-in (AuthProvider); off, the answer stays the one before the switch.
      const ended = rbacFlags().identity ? { code: 'session_ended' } : {}
      return NextResponse.json({ error: 'Unauthorized', ...ended }, { status: 401 })
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { id: true, name: true, email: true, role: true },
    })

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    // The real signed-in account's role, read from the database: only admins see the switch.
    if (session.role !== 'admin') return NextResponse.json(user)
    return NextResponse.json({ ...user, rbac: await adminNotices() })
  } catch (error) {
    return internalError(error, 'Internal server error', { log: 'Auth me error' })
  }
}
