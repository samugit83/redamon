import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '@/lib/session'
import { internalError, safeErrorCode } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { pendingLegacyGrantCount } from '@/lib/authz/updateReview'
import { accountTypeOf, loadInstanceRoot, type AccountType, type InstanceRoot } from '@/lib/authz/root'
import type { AdminNotices, RootNotice } from '@/providers/AuthProvider'

// The boot backfill's row (scripts/backfill-rbac-root.mjs): when an automatic Root was chosen.
const ROOT_ASSIGNED_ACTION = 'system.rbac_root_assigned'

interface RootView {
  accountType: AccountType
  /** Admins only. */
  root?: RootNotice | null
}

/**
 * The account type and, for an admin, the Root its banner shows (step 2.5); identity switch
 * on only. A member is never Root (Root is an admin), so its answer reads nothing. A failed
 * read leaves both out and is logged: the session, which the whole app reads, never fails.
 */
async function rootView(user: { id: string; role: string }): Promise<RootView | null> {
  if (!rbacFlags().identity) return null
  if (user.role !== 'admin') return { accountType: 'member' }
  try {
    const root = await loadInstanceRoot()
    return { accountType: accountTypeOf(user, root), root: root && await rootNotice(root) }
  } catch (err) {
    console.error(`[rbac] could not read the Root: ${safeErrorCode(err)}`)
    return null
  }
}

// Every admin page load asks while Root is unconfirmed. loadInstanceRoot hands back one frozen
// object for as long as it caches the row (RBAC_AUTHZ_CACHE_MS, invalidateInstanceRoot), so
// keyed on it the date lives and goes exactly as the Root does.
const chosenAtByRoot = new WeakMap<InstanceRoot, string | null>()

async function rootNotice(root: InstanceRoot): Promise<RootNotice> {
  if (root.confirmed) return { email: root.email, confirmed: true, chosenAt: null }
  let chosenAt = chosenAtByRoot.get(root)
  if (chosenAt === undefined) {
    // targetType lets it use the (target_type, target_id, created_at) index.
    const chosen = await prisma.auditLog.findFirst({
      where: { action: ROOT_ASSIGNED_ACTION, targetType: 'user', targetId: root.userId },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    })
    chosenAt = chosen?.createdAt.toISOString() ?? null
    chosenAtByRoot.set(root, chosenAt)
  }
  return { email: root.email, confirmed: false, chosenAt }
}

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

    const root = await rootView(user)
    const account = root ? { ...user, accountType: root.accountType } : user
    // The real signed-in account's role, read from the database: only admins see the switch.
    if (session.role !== 'admin') return NextResponse.json(account)
    const rbac = await adminNotices()
    return NextResponse.json({ ...account, rbac: root && 'root' in root ? { ...rbac, root: root.root } : rbac })
  } catch (error) {
    return internalError(error, 'Internal server error', { log: 'Auth me error' })
  }
}
