/**
 * Deferred work of an account that is not active does not fire (step 2.3, DV-39). A schedule
 * and a queued job start their scan headless, on the keys and settings of the account that
 * created them and of the project's owner; once either account is disabled (or gone), the
 * scan must not start on its behalf. The schedule run and the queue dispatch ask here before
 * they start anything.
 *
 * With the identity switch off nothing is read and nothing is refused (Phase 1 behaviour).
 *
 * `actorScanRefusal` is the second question (step 5.5, DV-38, SH-12): does the actor still reach
 * the project at the level the scan needs? It runs whatever the switches: an owner always passes,
 * so with sharing off it changes nothing, and a collaborator whose share was revoked, expired or
 * narrowed (or whose permissions were taken away) is refused when the work fires, not when it was
 * queued.
 */
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { appendNotice, schedulePausedNotice } from './accountNotices'
import { can } from './can'
import { now } from './clock'
import { rbacFlags } from './flags'
import type { PermissionId } from './permissions'
import { loadPrincipal } from './principal'

export interface InactiveScanAccount {
  userId: string
  /** `actor`: the account that created the schedule or queued the job; `owner`: the project's owner. */
  as: 'actor' | 'owner'
  /** The account's status, or `deleted` when no such account exists. */
  status: string
}

export interface ScanAccounts {
  actorUserId: string
  /** The project's owner, when the caller already read the project. */
  ownerUserId?: string | null
  /** Read the owner from this project when `ownerUserId` is not given. */
  projectId?: string
}

/** The first of the scan's accounts that is not active, or null (always null with the switch off). */
export async function inactiveScanAccount(accounts: ScanAccounts): Promise<InactiveScanAccount | null> {
  if (!rbacFlags().identity) return null
  let owner = accounts.ownerUserId ?? null
  if (accounts.ownerUserId === undefined && accounts.projectId) {
    const project = await prisma.project.findUnique({ where: { id: accounts.projectId }, select: { userId: true } })
    // A project that is gone is the start path's own refusal; only its owner is judged here.
    owner = project?.userId ?? null
  }
  const ids = [...new Set([accounts.actorUserId, owner].filter((v): v is string => !!v))]
  const rows = await prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, status: true } })
  const status = new Map(rows.map((r) => [r.id, r.status]))
  const checks: Array<[string | null, InactiveScanAccount['as']]> = [[accounts.actorUserId, 'actor'], [owner, 'owner']]
  for (const [userId, as] of checks) {
    if (!userId) continue
    const s = status.get(userId) ?? 'deleted'
    if (s !== 'active') return { userId, as, status: s }
  }
  return null
}

/** The reason a skipped schedule or a cancelled job records, in words for the run history. */
export function inactiveScanReason(inactive: InactiveScanAccount, done: 'scheduled' | 'queued'): string {
  const whose = inactive.as === 'actor' ? `the account that ${done} it` : "the project owner's account"
  return `${whose} is ${inactive.status}`
}

export interface ActorScanRefusal {
  userId: string
  /** The first permission the actor no longer holds on the project. */
  permission: PermissionId
  /**
   * `project_not_visible`: no share, owner or oversight reaches the project any more (revoked,
   * expired, sharing off); `capability`: the person lacks the permission; `project_level`: their
   * access to the project is below the scan's level (a Read share, or Write without Run scans);
   * `deleted`: the account is gone.
   */
  reason: 'project_not_visible' | 'capability' | 'project_level' | 'deleted'
}

/**
 * Whether the actor of a deferred scan may still start it: each of `permissions` (the scan kind's,
 * `queuedJobPermissions`) on `projectId`, as can() decides it for that person now, read fresh
 * (a revocation must not wait out the cache). Null when every one holds, else the first refused.
 * A failed read throws: the caller's catch keeps the work from starting.
 */
export async function actorScanRefusal(
  actorUserId: string,
  projectId: string,
  permissions: readonly PermissionId[],
): Promise<ActorScanRefusal | null> {
  if (permissions.length === 0) return null
  const principal = await loadPrincipal(actorUserId, { fresh: true })
  if (!principal) return { userId: actorUserId, permission: permissions[0], reason: 'deleted' }
  for (const permission of permissions) {
    const decision = await can(principal, permission, { projectId, fresh: true })
    if (decision.allowed) continue
    if (decision.status === 400) throw new Error(`[rbac] actorScanRefusal needs a project (${permission})`)
    return { userId: actorUserId, permission, reason: decision.reason }
  }
  return null
}

/** The reason a cancelled job or a paused schedule records, in words for the run history. */
export function actorScanRefusalReason(refusal: ActorScanRefusal, done: 'scheduled' | 'queued'): string {
  const why = {
    project_not_visible: 'no longer has access to this project',
    capability: `no longer holds ${refusal.permission}`,
    project_level: `no longer has the access to this project that ${refusal.permission} needs`,
    deleted: 'no longer exists',
  }[refusal.reason]
  return `the account that ${done} it ${why}`
}

/**
 * Tells the project's owner that a schedule paused itself because the person it runs as lost access
 * (step 5.5, D-13), through the account's notices (shown at the next sign-in, kept in My account).
 * Best effort: the pause stands whatever happens here; a failure is logged with its code and
 * answers false.
 */
export async function noticeSchedulePaused(input: {
  projectId: string
  scheduleId: string
  label: string
  actorUserId: string
}): Promise<boolean> {
  try {
    const [project, actor] = await Promise.all([
      prisma.project.findUnique({ where: { id: input.projectId }, select: { userId: true, name: true } }),
      prisma.user.findUnique({ where: { id: input.actorUserId }, select: { name: true, email: true } }),
    ])
    if (!project) return false
    await appendNotice(project.userId, schedulePausedNotice({
      at: now(),
      by: { id: input.actorUserId, name: actor?.name ?? '', email: actor?.email ?? '' },
      project: { id: input.projectId, name: project.name },
      schedule: { id: input.scheduleId, label: input.label },
    }))
    return true
  } catch (err) {
    console.error(`[rbac] schedule pause notice failed schedule=${input.scheduleId} code=${safeErrorCode(err)}`)
    return false
  }
}
