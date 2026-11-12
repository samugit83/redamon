/**
 * The member sets a new account starts with (step 3.13, ID-28: "permissions are chosen at
 * creation"): `POST /api/users/invite` and `POST /api/users` may name `sets`, written in the
 * account's own transaction with its audit row. Permissions switch on only; off, the key is ignored
 * as any unknown key was (DV-30). No set named, or `[]`: never assigned, so the account follows the
 * instance default set (capabilities.ts).
 *
 * The rules of assigning a set afterwards (userPermissionAdmin.ts) hold: the person needs
 * `users:assign_permissions`, gives only what they hold (PE-03, PE-10), and gives a cross-tenant
 * tool, an exploitation approval, sessions or Kali exec only with their own password (ID-25).
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import type { Session } from '@/lib/session'
import { rbacFlags } from './flags'
import { forbiddenResponse } from './guards'
import { stepUpPermissionsIn, unheld } from './hierarchy'
import { lockPermissions, managerOf, notHeldResponse, setOfKind, type Tx } from './permissionAdmin'
import type { PermissionId } from './permissions'
import { requireStepUp } from './stepUp'

// A picker sends one or a few; the bound keeps a hostile body from costing a read per id.
const MAX_SETS = 50

export interface InitialSets {
  sets: string[]
  /** Every permission the sets hold, in no particular order. */
  permissions: PermissionId[]
}

const bad = (code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status: 400 })

/**
 * The sets `body.sets` names, checked as an assignment would be, or the refusal; null when there
 * is nothing to write (switch off, no key, `[]`). `stepUpDone`: the route already took the
 * person's password for this request (Root creating an admin).
 */
export async function checkInitialSets(
  request: NextRequest,
  session: Session,
  body: Record<string, unknown>,
  { stepUpDone = false }: { stepUpDone?: boolean } = {},
): Promise<InitialSets | NextResponse | null> {
  if (!rbacFlags().permissions || !('sets' in body)) return null
  const sets = body.sets
  if (!Array.isArray(sets) || sets.length > MAX_SETS || sets.some((s) => typeof s !== 'string' || s === '' || s.length > 200)) {
    return bad('invalid_sets', `sets must be a list of at most ${MAX_SETS} permission set ids ([] = the instance default set).`)
  }
  if (new Set(sets).size !== sets.length) return bad('invalid_sets', 'A set is listed twice.')
  if (sets.length === 0) return null

  const { manager } = await managerOf(session)
  if (!manager.held.includes('users:assign_permissions')) return forbiddenResponse('users:assign_permissions')
  const permissions = new Set<PermissionId>()
  for (const id of sets as string[]) {
    const set = await setOfKind(prisma, id, 'member')
    if (!set) return bad('unknown_set', 'A set named is not a member permission set.', { setId: id.slice(0, 200) })
    for (const p of set.permissions) permissions.add(p)
  }
  const missing = unheld(manager, [...permissions])
  if (missing.length) return notHeldResponse(missing)
  if (!stepUpDone && stepUpPermissionsIn([...permissions]).length) {
    const stepUp = await requireStepUp(request, body.stepUpPassword)
    if (stepUp) return stepUp
  }
  return { sets: [...(sets as string[])], permissions: [...permissions] }
}

/** Thrown inside the account's transaction when a set was deleted after the check: nothing commits. */
export class InitialSetGone extends Error {
  constructor() {
    super('A permission set named was deleted while the account was being created')
    this.name = 'InitialSetGone'
  }
}

export function initialSetGoneResponse(): NextResponse {
  return NextResponse.json(
    { error: 'A permission set you chose was deleted meanwhile. Reload the sets and try again.', code: 'permissions_changed' },
    { status: 409 },
  )
}

/**
 * Writes the sets of the account just created, in its transaction, under the lock every
 * permission writer takes, so a set is never deleted while its assignment commits.
 */
export async function writeInitialSets(tx: Tx, userId: string, initial: InitialSets): Promise<void> {
  await lockPermissions(tx)
  for (const id of initial.sets) {
    if (!(await setOfKind(tx, id, 'member'))) throw new InitialSetGone()
  }
  await tx.userPermissionSet.createMany({ data: initial.sets.map((setId) => ({ userId, setId })) })
}
