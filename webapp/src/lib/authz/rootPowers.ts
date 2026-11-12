/**
 * Root's powers (step 2.6, ID-03, ID-05, PE-08; feature document §4.4, §4.8): with the identity
 * switch on, managing admins (creating, promoting, demoting, editing, deleting, resetting,
 * disabling, enabling, signing out, acting as one), the instance security policy and the Root
 * transfer belong to a CONFIRMED Root, and each takes Root's own password (step-up, ID-25). An
 * admin acts on members only. An unconfirmed Root (the boot's automatic choice) has Root's
 * protections but none of these powers until the host confirms it, and an instance without a
 * Root has nobody holding them.
 *
 * The refusal is 403 `root_only`, answered before any password is checked, so a refused admin
 * spends nothing of its step-up budget. Root is read fresh. With the switch off nothing here is
 * called: each route keeps its Phase 1 rule (DV-30).
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import type { Session } from '@/lib/session'
import { rbacFlags } from './flags'
import { loadInstanceRoot } from './root'
import { requireStepUp } from './stepUp'

/** confirmed: holds the powers; unconfirmed: Root without them yet; none: not Root. */
export type RootStanding = 'confirmed' | 'unconfirmed' | 'none'

export async function rootStanding(userId: string): Promise<RootStanding> {
  if (!rbacFlags().identity) return 'none'
  const root = await loadInstanceRoot({ fresh: true })
  if (!root || root.userId !== userId) return 'none'
  return root.confirmed ? 'confirmed' : 'unconfirmed'
}

const UNCONFIRMED = ' Root chosen automatically gets these powers once the host confirms it '
  + '(./redamon.sh set-root <email>, or ./redamon.sh update).'

/** 403 `root_only`; `error` says what only Root can do, and an unconfirmed Root learns why it cannot yet. */
export function rootOnlyRefusal(standing: RootStanding, error: string): NextResponse {
  return NextResponse.json(
    { error: standing === 'unconfirmed' ? `${error}${UNCONFIRMED}` : error, code: 'root_only' },
    { status: 403 },
  )
}

/**
 * Null when the signed-in account is the confirmed Root and `password` is its own; otherwise the
 * answer: 403 `root_only` (before any password check), or the step-up refusal.
 */
export async function requireRootPower(
  request: NextRequest | { headers?: Headers },
  session: Session,
  password: unknown,
  error: string,
): Promise<NextResponse | null> {
  const standing = await rootStanding(session.userId)
  if (standing !== 'confirmed') return rootOnlyRefusal(standing, error)
  return requireStepUp(request, password)
}

/**
 * The gate of an action on another account (switch on): a member target, or the account itself,
 * needs nothing more (`adminTarget: false`); another admin needs Root's power. With the switch
 * off it answers `adminTarget: false` and reads nothing.
 */
export async function adminTargetGate(
  request: NextRequest,
  session: Session,
  targetId: string,
  password: unknown,
  error: string,
): Promise<NextResponse | { adminTarget: boolean }> {
  if (!rbacFlags().identity || targetId === session.userId) return { adminTarget: false }
  const target = await prisma.user.findUnique({ where: { id: targetId }, select: { role: true } })
  if (target?.role !== 'admin') return { adminTarget: false }
  const refusal = await requireRootPower(request, session, password, error)
  return refusal ?? { adminTarget: true }
}
