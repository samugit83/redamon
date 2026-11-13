/**
 * One account's permissions (step 3.11; PE-03, PE-10, PE-15, PE-30, ID-21, ID-25): what it holds
 * and why (GET), and changing its member sets, its overrides and, for an admin, its profile (PUT).
 *
 * Who: the account itself reads its own; anyone else needs `canManage(..., 'assign_permissions')`
 * (hierarchy.ts): `users:assign_permissions` on a member; on an admin, Root, or an `admins:manage`
 * holder whose admin side strictly contains the target's profile. Nobody changes their own, and
 * nobody but Root itself acts on Root (rootProtection.ts, audited).
 *
 * A change gives only what the person holds: every set added, every grant added or lengthened,
 * every deny lifted, the new profile and every permission the account gains must be held by the
 * person (PE-03, PE-10); a profile only strictly inside the person's own (PE-09). It takes the
 * person's password (`stepUpPassword`) when the target is an admin or when it gives a cross-tenant
 * platform tool, an exploitation approval, sessions or Kali exec (ID-25). It commits with its
 * `user.permissions_changed` row (`writeAuditTx`: no row, no change), under the permissions lock,
 * on the rows it was decided on (else 409). A change that removes any permission the account held
 * raises its session version in that transaction and closes its sockets after it (ID-21); a change
 * that only adds drops this process's cached copy, and other copies see it within the bound.
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import type { Session } from '@/lib/session'
import { resolveCapabilities, type CapabilityPrincipal } from './capabilities'
import { now } from './clock'
import {
  canAssignProfile, canManage, overrideAllowed, stepUpPermissionsIn, unheld, type ManageDecision,
} from './hierarchy'
import {
  endSessionsOf, lockPermissions, managedOf, managerOf, notHeldResponse, personAuditEntry, profileContents, setOfKind,
  type Target,
} from './permissionAdmin'
import { PERMISSION_IDS, isPermissionId, type PermissionId } from './permissions'
import { invalidatePrincipal, type PermissionOverrideRow } from './principal'
import { manageRefusal } from './rootPowers'
import { rootProtectedRefusal } from './rootProtection'
import { requireStepUp } from './stepUp'

const ROOT_ONLY_ERROR = "Only Root can change another admin's permissions."
const MAX_REASON = 500

const bad = (code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status: 400 })
const USER_NOT_FOUND = () => NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
const CHANGED = () => NextResponse.json(
  { error: "The account's permissions changed while this request ran. Reload them and try again.", code: 'permissions_changed' },
  { status: 409 },
)

async function refusal(session: Session, decision: Exclude<ManageDecision, { allowed: true }>): Promise<NextResponse> {
  return manageRefusal(session, decision, ROOT_ONLY_ERROR)
}

interface OverrideOut {
  permission: string
  effect: string
  expiresAt: string | null
  reason: string | null
}

const iso = (d: Date | null) => (d ? d.toISOString() : null)

/** GET: the account's assignment as stored, and what it holds with every reason (PE-16, UI-12). */
export async function readUserPermissions(session: Session, targetId: string): Promise<NextResponse> {
  const target = await managedOf(targetId)
  if (!target) return USER_NOT_FOUND()
  if (targetId !== session.userId) {
    const { manager } = await managerOf(session)
    const decision = canManage(manager, target.managed, 'assign_permissions')
    if (!decision.allowed) return refusal(session, decision)
  }
  const capabilities = await resolveCapabilities(target.principal, { fresh: true })
  const rows = await prisma.userPermissionOverride.findMany({
    where: { userId: targetId },
    select: { permission: true, effect: true, expiresAt: true, reason: true, grantedById: true, createdAt: true },
  })
  const overrides = rows
    .map((r) => ({ ...r, expiresAt: iso(r.expiresAt), createdAt: iso(r.createdAt) }))
    .sort((a, b) => a.permission.localeCompare(b.permission))
  return NextResponse.json({
    userId: targetId,
    accountType: capabilities.accountType,
    enforced: capabilities.enforced,
    assignment: {
      sets: target.principal.permissionSets ?? [],
      overrides,
      ...(target.managed.accountType === 'admin' ? { adminProfileId: target.principal.adminProfileId } : {}),
    },
    sets: capabilities.sets,
    missingSets: capabilities.missingSets,
    held: capabilities.held,
    explain: capabilities.explainAll(),
  })
}

interface Assignment {
  sets: string[]
  overrides: PermissionOverrideRow[]
  adminProfileId: string | null
}

interface ParsedChange {
  sets?: string[]
  overrides?: PermissionOverrideRow[]
  /** Present (null = *Full admin*) only when the body names it. */
  adminProfileId?: string | null
}

/** The body's shape (no database read), or the 400. Each key present replaces that part whole. */
export function parseChange(body: Record<string, unknown>, accountType: Target['managed']['accountType']): ParsedChange | NextResponse {
  const out: ParsedChange = {}
  if ('sets' in body) {
    const sets = body.sets
    if (!Array.isArray(sets) || sets.some((s) => typeof s !== 'string' || s === '' || s.length > 200)) {
      return bad('invalid_sets', 'sets must be a list of permission set ids ([] = back to the default set).')
    }
    if (new Set(sets).size !== sets.length) return bad('invalid_sets', 'A set is listed twice.')
    out.sets = sets as string[]
  }
  if ('overrides' in body) {
    const list = body.overrides
    if (!Array.isArray(list) || list.length > PERMISSION_IDS.length) {
      return bad('invalid_overrides', 'overrides must be a list of {permission, effect, expiresAt?, reason?}.')
    }
    const at = now().getTime()
    const seen = new Set<string>()
    const rows: PermissionOverrideRow[] = []
    for (const item of list) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) return bad('invalid_overrides', 'Each override is an object.')
      const o = item as Record<string, unknown>
      if (!isPermissionId(o.permission)) {
        return bad('unknown_permission', 'An override names a permission that does not exist.', { permission: String(o.permission).slice(0, 80) })
      }
      const permission = o.permission
      if (seen.has(permission)) return bad('invalid_overrides', `${permission} has two overrides; keep one.`, { permission })
      seen.add(permission)
      if (o.effect !== 'grant' && o.effect !== 'deny') return bad('invalid_overrides', 'An override\'s effect is grant or deny.', { permission })
      if (!overrideAllowed(permission, accountType)) {
        return bad('admin_permission_override',
          `${permission} cannot be overridden on this account: an override names a member permission, or a platform tool on a member; an admin's administration rights come from its profile alone.`,
          { permission })
      }
      let expiresAt: Date | null = null
      if (o.expiresAt !== undefined && o.expiresAt !== null) {
        const t = typeof o.expiresAt === 'string' ? Date.parse(o.expiresAt) : NaN
        if (Number.isNaN(t)) return bad('invalid_expiry', 'expiresAt is an ISO date and time.', { permission })
        if (t <= at) return bad('invalid_expiry', 'expiresAt is already past.', { permission })
        expiresAt = new Date(t)
      }
      let reason: string | null = null
      if (o.reason !== undefined && o.reason !== null) {
        if (typeof o.reason !== 'string' || o.reason.length > MAX_REASON) {
          return bad('invalid_reason', `reason is text of at most ${MAX_REASON} characters.`, { permission })
        }
        reason = o.reason.trim() || null
      }
      rows.push({ permission, effect: o.effect, expiresAt, reason })
    }
    out.overrides = rows.sort((a, b) => a.permission.localeCompare(b.permission))
  }
  if ('adminProfileId' in body) {
    if (accountType !== 'admin') return bad('not_an_admin', 'Only an admin has an admin profile.')
    const id = body.adminProfileId
    if (id !== null && (typeof id !== 'string' || id === '' || id.length > 200)) {
      return bad('unknown_profile', 'adminProfileId is an admin profile id, or null for Full admin.')
    }
    out.adminProfileId = id as string | null
  }
  if (out.sets === undefined && out.overrides === undefined && !('adminProfileId' in out)) {
    return bad('nothing_to_change', 'Send sets, overrides or adminProfileId.')
  }
  return out
}

const active = (o: PermissionOverrideRow, at: number) => o.expiresAt === null || o.expiresAt.getTime() > at

function sameOverrides(a: readonly PermissionOverrideRow[], b: readonly PermissionOverrideRow[]): boolean {
  const key = (o: PermissionOverrideRow) => `${o.permission}|${o.effect}|${o.expiresAt?.getTime() ?? ''}|${o.reason ?? ''}`
  const ka = a.map(key).sort()
  const kb = b.map(key).sort()
  return ka.length === kb.length && ka.every((k, i) => k === kb[i])
}

function sameAssignment(a: Assignment, b: Assignment): boolean {
  const sa = [...a.sets].sort()
  const sb = [...b.sets].sort()
  return a.adminProfileId === b.adminProfileId && sa.length === sb.length && sa.every((s, i) => s === sb[i])
    && sameOverrides(a.overrides, b.overrides)
}

/** Grants that are new, back after expiring, or lengthened, and denies lifted: each gives a permission. */
function overridesGiving(before: readonly PermissionOverrideRow[], after: readonly PermissionOverrideRow[]): string[] {
  const at = now().getTime()
  const prev = new Map(before.map((o) => [o.permission, o]))
  const next = new Map(after.map((o) => [o.permission, o]))
  const out: string[] = []
  for (const o of after) {
    if (o.effect !== 'grant') continue
    const p = prev.get(o.permission)
    const held = p && p.effect === 'grant' && active(p, at)
    const longer = p && p.expiresAt !== null && (o.expiresAt === null || o.expiresAt > p.expiresAt)
    if (!held || longer) out.push(o.permission)
  }
  for (const p of before) {
    if (p.effect !== 'deny' || !active(p, at)) continue
    const n = next.get(p.permission)
    const stillDenied = n && n.effect === 'deny' && (n.expiresAt === null || (p.expiresAt !== null && n.expiresAt >= p.expiresAt))
    if (!stillDenied) out.push(p.permission)
  }
  return out
}

const setsOf = (ids: readonly string[]) => [...ids].sort()
const auditOverrides = (rows: readonly PermissionOverrideRow[]) =>
  rows.map((o) => ({ permission: o.permission, effect: o.effect, expiresAt: iso(o.expiresAt), reason: o.reason }))

/** PUT: change the account's sets, overrides and (admins) profile. The route checked the session, origin and JSON. */
export async function changeUserPermissions(
  request: NextRequest, session: Session, targetId: string, body: Record<string, unknown>,
): Promise<NextResponse> {
  if (targetId === session.userId) {
    return NextResponse.json({ error: 'You cannot change your own permissions.', code: 'own_account' }, { status: 400 })
  }
  const protectedRoot = await rootProtectedRefusal(request, session, targetId, 'change_permissions')
  if (protectedRoot) return protectedRoot
  const target = await managedOf(targetId)
  if (!target) return USER_NOT_FOUND()
  const acting = await managerOf(session)
  const decision = canManage(acting.manager, target.managed, 'assign_permissions')
  if (!decision.allowed) return refusal(session, decision)

  const parsed = parseChange(body, target.managed.accountType)
  if (parsed instanceof NextResponse) return parsed

  const { principal } = target
  const current: Assignment = {
    sets: [...(principal.permissionSets ?? [])],
    overrides: [...(principal.permissionOverrides ?? [])],
    adminProfileId: principal.adminProfileId,
  }
  const next: Assignment = {
    sets: parsed.sets ?? current.sets,
    overrides: parsed.overrides ?? current.overrides,
    adminProfileId: 'adminProfileId' in parsed ? parsed.adminProfileId! : current.adminProfileId,
  }

  const addedSets = next.sets.filter((s) => !current.sets.includes(s))
  const giving = new Set<string>()
  for (const id of addedSets) {
    const set = await setOfKind(prisma, id, 'member')
    if (!set) return bad('unknown_set', 'A set named is not a member permission set.', { setId: id.slice(0, 200) })
    for (const p of set.permissions) giving.add(p)
  }
  const profileChanged = next.adminProfileId !== current.adminProfileId
  if (profileChanged && next.adminProfileId !== null && !(await setOfKind(prisma, next.adminProfileId, 'admin'))) {
    return bad('unknown_profile', 'adminProfileId names no admin profile.')
  }
  if (sameAssignment(current, next)) return NextResponse.json({ id: targetId, changed: false })

  const as = (a: Assignment): CapabilityPrincipal => ({
    ...principal, status: 'active', permissionSets: a.sets, permissionOverrides: a.overrides, adminProfileId: a.adminProfileId,
  })
  // As if active: a disabled or invited account's rights apply the day it signs in.
  const before = await resolveCapabilities(as(current), { fresh: true })
  const after = await resolveCapabilities(as(next), { fresh: true })
  const added = after.held.filter((p) => !before.held.includes(p))
  const removed = before.held.filter((p) => !after.held.includes(p))
  for (const p of added) giving.add(p)
  for (const p of overridesGiving(current.overrides, next.overrides)) giving.add(p)

  if (profileChanged) {
    const profile = await profileContents(prisma, next.adminProfileId)
    const allowed = canAssignProfile(acting.manager, profile)
    if (!allowed.allowed) return refusal(session, allowed)
    for (const p of profile) giving.add(p)
  }
  const missing = unheld(acting.manager, [...giving])
  if (missing.length) return notHeldResponse(missing)

  if (target.managed.accountType === 'admin' || stepUpPermissionsIn([...giving]).length) {
    const stepUp = await requireStepUp(request, body.stepUpPassword)
    if (stepUp) return stepUp
  }

  const permission: PermissionId = target.managed.accountType === 'admin' ? 'admins:manage' : 'users:assign_permissions'
  const outcome = await auditedTransaction(prisma, async (tx) => {
    await lockPermissions(tx)
    const row = await tx.user.findUnique({
      where: { id: targetId },
      select: {
        role: true, adminProfileId: true,
        permissionSets: { select: { setId: true } },
        permissionOverrides: { select: { permission: true, effect: true, expiresAt: true, reason: true } },
      },
    })
    if (!row) return 'missing' as const
    const now_: Assignment = {
      sets: row.permissionSets.map((r) => r.setId),
      overrides: row.permissionOverrides.map((r) => ({ ...r, expiresAt: r.expiresAt ?? null, reason: r.reason ?? null })),
      adminProfileId: row.adminProfileId ?? null,
    }
    if (row.role !== principal.role || !sameAssignment(now_, current)) return 'changed' as const
    for (const id of addedSets) if (!(await setOfKind(tx, id, 'member'))) return 'changed' as const
    if (profileChanged && next.adminProfileId !== null && !(await setOfKind(tx, next.adminProfileId, 'admin'))) return 'changed' as const

    if (parsed.sets !== undefined) {
      await tx.userPermissionSet.deleteMany({ where: { userId: targetId } })
      if (next.sets.length) await tx.userPermissionSet.createMany({ data: next.sets.map((setId) => ({ userId: targetId, setId })) })
    }
    if (parsed.overrides !== undefined) {
      await tx.userPermissionOverride.deleteMany({ where: { userId: targetId } })
      if (next.overrides.length) {
        await tx.userPermissionOverride.createMany({
          data: next.overrides.map((o) => ({ userId: targetId, ...o, grantedById: session.userId })),
        })
      }
    }
    let sessionVersion: number | undefined
    if (profileChanged || removed.length) {
      const updated = await tx.user.update({
        where: { id: targetId },
        data: {
          ...(profileChanged ? { adminProfileId: next.adminProfileId } : {}),
          ...(removed.length ? { sessionVersion: { increment: 1 } } : {}),
        },
        select: { sessionVersion: true },
      })
      if (removed.length) sessionVersion = updated.sessionVersion
    }
    await writeAuditTx(tx, await personAuditEntry(request, session, {
      action: 'user.permissions_changed',
      targetType: 'user',
      targetId,
      permission,
      before: {
        sets: setsOf(current.sets), overrides: auditOverrides(current.overrides),
        ...(target.managed.accountType === 'admin' ? { adminProfileId: current.adminProfileId } : {}),
        held: before.held,
      },
      after: {
        sets: setsOf(next.sets), overrides: auditOverrides(next.overrides),
        ...(target.managed.accountType === 'admin' ? { adminProfileId: next.adminProfileId } : {}),
        held: after.held, added, removed,
        ...(sessionVersion !== undefined ? { sessionVersion } : {}),
      },
    }))
    return 'written' as const
  })
  if (outcome === 'missing') return USER_NOT_FOUND()
  if (outcome === 'changed') return CHANGED()

  if (!removed.length) {
    invalidatePrincipal(targetId)
    return NextResponse.json({ id: targetId, changed: true, added, removed, signedOut: false })
  }
  const agent = await endSessionsOf([targetId])
  return NextResponse.json({ id: targetId, changed: true, added, removed, signedOut: true, agent })
}
