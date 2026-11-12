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
 *
 * With RBAC_PERMISSIONS_ENABLED on, `adminTargetGate` called with an action widens the Root-only
 * rule by hierarchy.ts `canManage` (step 3.11, D-02): an admin holding `admins:manage` also
 * disables, enables or signs out an admin whose profile sits strictly inside its own, with its own
 * password. Called without one (reset, invites) it stays Root's.
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import type { Session } from '@/lib/session'
import { rbacFlags } from './flags'
import { forbiddenResponse } from './guards'
import { canManage, type ManageAction, type ManageDecision } from './hierarchy'
import { managedOf, managerOf } from './permissionAdmin'
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
 * The answer to a refused `canManage` (hierarchy.ts): 400 `own_account`, 403 `root_protected`,
 * 403 `root_only` (with `error`, and the unconfirmed Root told why), 403 `forbidden` naming the
 * permission, or 403 `not_a_subset`.
 */
export async function manageRefusal(
  session: Session,
  decision: Exclude<ManageDecision, { allowed: true }>,
  error: string,
): Promise<NextResponse> {
  switch (decision.reason) {
    case 'own_account':
      return NextResponse.json({ error: 'This action does not apply to your own account.', code: 'own_account' }, { status: 400 })
    case 'root_protected':
      return NextResponse.json({ error: "This account is the instance's Root: no other account can change it.", code: 'root_protected' }, { status: 403 })
    case 'root_only':
      return rootOnlyRefusal(await rootStanding(session.userId), error)
    case 'forbidden':
      return forbiddenResponse(decision.permission)
    case 'not_a_subset':
      return NextResponse.json({
        error: "You manage only an admin whose profile is strictly inside your own admin permissions; this one's is not.",
        code: 'not_a_subset',
      }, { status: 403 })
  }
}

export interface AdminTargetPass {
  adminTarget: boolean
  /** The write is a Root power (re-checked under the Root lock); false on the `admins:manage` path. */
  needsRoot?: boolean
}

/**
 * The gate of an action on another account (switch on): a member target, or the account itself,
 * needs nothing more (`adminTarget: false`); another admin needs Root's power, or with the
 * permissions switch on and an `action`, `canManage`'s `admins:manage` rule and the person's own
 * password. With the identity switch off it answers `adminTarget: false` and reads nothing.
 */
export async function adminTargetGate(
  request: NextRequest,
  session: Session,
  targetId: string,
  password: unknown,
  error: string,
  action?: ManageAction,
): Promise<NextResponse | AdminTargetPass> {
  if (!rbacFlags().identity || targetId === session.userId) return { adminTarget: false }
  const target = await prisma.user.findUnique({ where: { id: targetId }, select: { role: true } })
  if (target?.role !== 'admin') return { adminTarget: false }
  if (action && rbacFlags().permissions && (await rootStanding(session.userId)) !== 'confirmed') {
    const managed = await managedOf(targetId)
    if (!managed) return { adminTarget: false }
    const decision = canManage((await managerOf(session)).manager, managed.managed, action)
    if (!decision.allowed) return manageRefusal(session, decision, error)
    const refusal = await requireStepUp(request, password)
    return refusal ?? { adminTarget: true, needsRoot: false }
  }
  const refusal = await requireRootPower(request, session, password, error)
  return refusal ?? { adminTarget: true, needsRoot: true }
}
