/**
 * Impersonation under RBAC (step 3.14; feature document §4.7; IM-03 to IM-12, AU-03): who may act
 * as whom, for how long, and how an impersonation ends and is recorded.
 *
 * With RBAC_PERMISSIONS_ENABLED on:
 *   - acting as someone needs `users:impersonate`; an admin acts as members only, acting as an admin
 *     is Root's (hierarchy.ts `canManage`: Root's powers), and nobody acts as Root;
 *   - an impersonation has a reason (mandatory when Root says so) and a time limit (default 60
 *     minutes, at most the instance's `impersonationMaxMinutes`, never above 720, never longer than
 *     an admin session); the act-as token expires with it and carries the admin's session version;
 *   - the rule is judged again on every request (session.ts `actAsTarget`): the impersonation ends
 *     when its time is up, when the admin's version changes or the admin loses the permission, and
 *     when the account acted as is disabled, deleted or promoted. Each end writes one `ActAsAudit`
 *     end row naming how it ended (`endedBy`), the first time it is noticed; a cookie from before the
 *     switch (no version claim) stays valid until its own expiry, but a pair the rule forbids ends at
 *     once with an `act_as.refused` row (IM-12).
 * With it off, Phase 2's rule: only an admin acts as anyone and nobody acts as Root (identity on).
 *
 * Reads: the instance settings row (the three impersonation settings), the act-as log and, through
 * capabilities.ts, the Root and the admin's sets. A failed read throws; a failed end-row write is
 * logged and the impersonation still ends.
 */
import prisma from '@/lib/prisma'
import { createActAsToken, readActAsToken } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { safeErrorCode } from '@/lib/routeErrors'
import { rbacFlags } from './flags'
import { now } from './clock'
import { resolveCapabilities, type CapabilityPrincipal } from './capabilities'
import { canManage } from './hierarchy'
import { accountTypeOf, isRootAccount, loadInstanceRoot, INSTANCE_SETTINGS_ROW } from './root'

/** OQ-32: the instance limit stops at 720 minutes (the 12 h an act-as cookie lived before). */
export const IMPERSONATION_MAX_MINUTES = 720
/** OQ-32: the dialog's default duration. */
export const DEFAULT_IMPERSONATION_MINUTES = 60
export const IMPERSONATION_REASON_MAX_LENGTH = 500

/** How an impersonation ended, on its `ActAsAudit` end row (AU-03). */
export type ActAsEnd =
  | 'stopped' // the admin pressed Stop, chose themselves, or started acting as someone else
  | 'expired' // its time limit passed
  | 'logout' // the admin signed out
  | 'target_disabled'
  | 'target_deleted'
  | 'target_promoted' // the account acted as became an admin
  | 'invalidated' // the admin's session version changed, or the admin lost users:impersonate
  | 'refused' // a pair the rule forbids (an act-as cookie from before the switch, IM-12)

export interface ImpersonationPolicy {
  /** The longest impersonation, in minutes: the instance's value, at most 720. */
  maxMinutes: number
  reasonRequired: boolean
  notifyTarget: boolean
}

const POLICY_DEFAULTS: Readonly<ImpersonationPolicy> = Object.freeze({
  maxMinutes: IMPERSONATION_MAX_MINUTES,
  reasonRequired: false,
  notifyTarget: true,
})

/**
 * The instance's impersonation settings. A missing row reads as the schema defaults; a stored limit
 * that is not a whole number from 1 reads as 720, and one above 720 (written by hand: the policy
 * form refuses it, 3db56ff9) is held to 720.
 */
export async function impersonationPolicy(): Promise<ImpersonationPolicy> {
  const row = await prisma.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { impersonationMaxMinutes: true, impersonationReasonRequired: true, impersonationNotifyTarget: true },
  })
  if (!row) return { ...POLICY_DEFAULTS }
  const max = row.impersonationMaxMinutes
  return {
    maxMinutes: Number.isSafeInteger(max) && max >= 1 ? Math.min(max, IMPERSONATION_MAX_MINUTES) : IMPERSONATION_MAX_MINUTES,
    reasonRequired: row.impersonationReasonRequired === true,
    notifyTarget: row.impersonationNotifyTarget !== false,
  }
}

export interface ActAsRequest {
  reason: string | null
  /** The minutes asked for, held to the instance limit. */
  durationMinutes: number
}

export type ActAsRequestProblem = { status: 400; code: 'invalid_field' | 'reason_required'; field: 'reason' | 'durationMinutes'; error: string }

/** The reason and duration of an act-as request, checked against the policy. */
export function parseActAsRequest(body: Record<string, unknown>, policy: ImpersonationPolicy): ActAsRequest | ActAsRequestProblem {
  const raw = body.reason
  if (raw !== undefined && raw !== null && typeof raw !== 'string') {
    return { status: 400, code: 'invalid_field', field: 'reason', error: 'reason must be text' }
  }
  const reason = typeof raw === 'string' && raw.trim() ? raw.trim() : null
  if (reason && reason.length > IMPERSONATION_REASON_MAX_LENGTH) {
    return { status: 400, code: 'invalid_field', field: 'reason', error: `reason is longer than ${IMPERSONATION_REASON_MAX_LENGTH} characters` }
  }
  if (!reason && policy.reasonRequired) {
    return { status: 400, code: 'reason_required', field: 'reason', error: 'Say why you are acting as this account: a reason is required.' }
  }
  const asked = body.durationMinutes
  if (asked !== undefined && asked !== null && (typeof asked !== 'number' || !Number.isSafeInteger(asked) || asked < 1)) {
    return { status: 400, code: 'invalid_field', field: 'durationMinutes', error: 'durationMinutes must be a whole number of minutes from 1' }
  }
  const wanted = typeof asked === 'number' ? asked : DEFAULT_IMPERSONATION_MINUTES
  return { reason, durationMinutes: Math.min(wanted, policy.maxMinutes) }
}

/**
 * The act-as token of an impersonation that starts now: it expires with it, and it carries the
 * admin's session version, so signing the admin out everywhere ends it too.
 */
export async function mintImpersonationToken(
  admin: Pick<CapabilityPrincipal, 'id'> & { sessionVersion: number },
  targetUserId: string,
  seconds: number,
): Promise<string> {
  return createActAsToken(admin.id, targetUserId, seconds, { asv: admin.sessionVersion })
}

/** Only an admin acts as anyone: anyone else's act-as cookie is ignored (an account type). */
export function actsAsOthers(account: { role: string }): boolean {
  return account.role === 'admin'
}

/**
 * Why `actor` may not act as `target` now, or null when it may. Acting as oneself is no act-as
 * (null for an admin). Permissions switch on: `no_permission` (the actor lacks users:impersonate),
 * `admin_target` (an admin, and the actor is not Root), `root_target`, `target_disabled`. Off:
 * Phase 2's rule, `root_target` alone (identity on), reading the Root only for an admin target.
 */
export type ActAsRuleRefusal = 'not_an_admin' | 'no_permission' | 'admin_target' | 'root_target' | 'target_disabled'

/** The actor as the caller read it: Phase 2's rule needs its id and role; the permissions need the account read. */
export type ActAsActor = Pick<CapabilityPrincipal, 'id' | 'role'> & Partial<Omit<CapabilityPrincipal, 'id' | 'role'>>

function readWhole(actor: ActAsActor): actor is CapabilityPrincipal {
  return typeof actor.status === 'string' && Array.isArray(actor.legacyGrants) && actor.adminProfileId !== undefined
}

export async function actAsRuleRefusal(
  actor: ActAsActor,
  target: Pick<CapabilityPrincipal, 'id' | 'role'> & { status?: string },
  { fresh = false }: { fresh?: boolean } = {},
): Promise<ActAsRuleRefusal | null> {
  if (!actsAsOthers(actor)) return 'not_an_admin'
  if (target.id === actor.id) return null
  if (!rbacFlags().permissions) {
    // Root is an admin, so a member target costs no instance read.
    return target.role === 'admin' && (await isRootAccount(target.id, { fresh })) ? 'root_target' : null
  }
  // An actor known only by id and role holds nothing here: fail closed.
  if (!readWhole(actor)) return 'no_permission'
  const root = await loadInstanceRoot({ fresh })
  const own = await resolveCapabilities(actor, { fresh, root })
  const decision = canManage(
    { id: actor.id, accountType: own.accountType, held: own.held },
    // An impersonation of an admin is Root's whatever the profiles (ROOT_ONLY_ON_ADMINS).
    { id: target.id, accountType: accountTypeOf(target, root), profile: [] },
    'impersonate',
  )
  if (!decision.allowed) {
    if (decision.reason === 'root_protected') return 'root_target'
    if (decision.reason === 'forbidden') return 'no_permission'
    return 'admin_target'
  }
  return target.status === 'disabled' ? 'target_disabled' : null
}

/** The end an act-as cookie meets when the rule refuses it on a request (`asv`: the cookie is from this rule). */
export function endForRefusal(refusal: ActAsRuleRefusal, mintedUnderTheRule: boolean): ActAsEnd {
  switch (refusal) {
    case 'target_disabled':
      return 'target_disabled'
    case 'no_permission':
      return 'invalidated'
    case 'admin_target':
      // Started under this rule, the account was a member then: it has been promoted since.
      return mintedUnderTheRule ? 'target_promoted' : 'refused'
    default:
      return 'refused'
  }
}

/** Serialises the end rows of one admin's impersonations across requests and webapp copies. */
function lockKey(adminId: string): string {
  return `rbac-act-as:${adminId}`
}

export interface ActAsEndInput {
  adminId: string
  targetUserId: string
  endedBy: ActAsEnd
  /** The admin's email, for the `act_as.refused` row. */
  adminEmail?: string | null
}

/**
 * Writes the end row of the admin's impersonation of `targetUserId`, once: under a lock per admin,
 * and only when the pair's last row is not already an end (a Stop, an expiry seen by another
 * request or another copy). A forbidden pair also writes `act_as.refused`. True when it wrote.
 */
export async function recordActAsEnd({ adminId, targetUserId, endedBy, adminEmail }: ActAsEndInput): Promise<boolean> {
  const wrote = await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${lockKey(adminId)}))`
    const last = await tx.actAsAudit.findFirst({
      where: { adminId, targetUserId },
      orderBy: { createdAt: 'desc' },
      select: { event: true },
    })
    if (last?.event === 'end') return false
    await tx.actAsAudit.create({ data: { adminId, targetUserId, event: 'end', source: 'api', endedBy } })
    return true
  })
  if (!wrote) return false
  console.info(`[audit] act-as.end admin=${adminId} target=${targetUserId} ended-by=${endedBy}`)
  if (endedBy === 'refused') {
    await writeAudit({
      actorId: adminId,
      ...(adminEmail ? { actorEmail: adminEmail } : {}),
      action: 'act_as.refused',
      targetType: 'user',
      targetId: targetUserId,
      permission: 'users:impersonate',
      after: { reason: 'forbidden_pair' },
    })
  }
  return true
}

/**
 * recordActAsEnd for a request path that must go on whatever the log says: a failed write is
 * logged (`[rbac] act-as end not recorded`) and the impersonation ends anyway.
 */
export async function recordActAsEndQuietly(input: ActAsEndInput): Promise<void> {
  try {
    await recordActAsEnd(input)
  } catch (err) {
    console.error(`[rbac] act-as end not recorded admin=${input.adminId} target=${input.targetUserId} ended-by=${input.endedBy} code=${safeErrorCode(err)}`)
  }
}

// The newest rows read when settling: an admin's or an account's recent impersonations.
const SETTLE_WINDOW = 50

/**
 * Writes `expired` for every impersonation in the newest rows of an admin (or of an account acted
 * as) whose time limit has passed with no end row yet: the browser drops an act-as cookie when it
 * expires, so the expiry is otherwise never seen. Only impersonations started under this rule carry
 * a duration. Returns how many it ended.
 */
export async function settleExpiredActAs(where: { adminId: string } | { targetUserId: string }): Promise<number> {
  const rows = await prisma.actAsAudit.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: SETTLE_WINDOW,
    select: { adminId: true, targetUserId: true, event: true, createdAt: true, durationMinutes: true },
  })
  const seen = new Set<string>()
  let ended = 0
  for (const row of rows) {
    const pair = `${row.adminId}\u0000${row.targetUserId}`
    if (seen.has(pair)) continue
    seen.add(pair)
    if (row.event !== 'start' || !row.durationMinutes) continue
    if (row.createdAt.getTime() + row.durationMinutes * 60_000 > now().getTime()) continue
    if (await recordActAsEnd({ adminId: row.adminId, targetUserId: row.targetUserId, endedBy: 'expired' })) ended += 1
  }
  return ended
}

/** settleExpiredActAs for a path that must not fail on it (logged with its code). */
export async function settleExpiredActAsQuietly(where: { adminId: string } | { targetUserId: string }): Promise<void> {
  try {
    await settleExpiredActAs(where)
  } catch (err) {
    console.error(`[rbac] act-as expiry not recorded code=${safeErrorCode(err)}`)
  }
}

/**
 * The end of the impersonation an act-as token names, when it is this admin's (`expired` once the
 * token has, else `endedBy`), and `expired` for any of the admin's impersonations whose time ran out
 * with no cookie left to say so: a Stop, a new act-as, a sign-out. Written once each.
 */
export async function endPresentedActAs(adminId: string, token: string | null, endedBy: ActAsEnd): Promise<void> {
  const read = token ? await readActAsToken(token) : null
  if (read && read.claims.sub === adminId && read.claims.act !== adminId) {
    await recordActAsEnd({ adminId, targetUserId: read.claims.act, endedBy: read.expired ? 'expired' : endedBy })
  }
  await settleExpiredActAs({ adminId })
}

/** The reason and start of the admin's current impersonation of `targetUserId`, from its start row. */
export async function currentActAsStart(adminId: string, targetUserId: string): Promise<{ reason: string | null; startedAt: Date } | null> {
  const row = await prisma.actAsAudit.findFirst({
    where: { adminId, targetUserId, event: 'start' },
    orderBy: { createdAt: 'desc' },
    select: { reason: true, createdAt: true },
  })
  return row ? { reason: row.reason ?? null, startedAt: row.createdAt } : null
}
