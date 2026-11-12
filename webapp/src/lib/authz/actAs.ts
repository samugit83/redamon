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
 *     once with an `act_as.refused` row (IM-12);
 *   - the token names its start row (`jti`) and acts only while that row is the latest of its admin
 *     and account in the log (`ActAsBinding`): the end row a Stop, a sign-out or a new act-as writes
 *     ends every copy of the cookie, a saved one replayed included. A new act-as writes the previous
 *     one's end and its own start in one transaction, so the log and the cookies never disagree.
 * With it off, Phase 2's rule: only an admin acts as anyone and nobody acts as Root (identity on).
 *
 * Reads: the instance settings row (the three impersonation settings), the act-as log and, through
 * capabilities.ts, the Root and the admin's sets. A failed read throws; a failed end-row write is
 * logged and the impersonation still ends.
 *
 * Every row of a pair is written under the per-admin lock with a `createdAt` after the pair's last
 * row (`after`): Postgres gives every statement of a transaction the same `now()`, and "the pair's
 * latest row" must never be a tie.
 */
import { randomUUID } from 'node:crypto'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { createActAsToken, readActAsToken, type ActAsClaims } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { closeAgentSockets } from '@/lib/agentSockets'
import { safeErrorCode } from '@/lib/routeErrors'
import { WS_SOCKETS } from '@/lib/wsTicket'
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

/**
 * Which impersonation an act-as token names in the log, so that it acts only while that one is in
 * force (fail closed: a token whose impersonation the log does not show running acts as nobody):
 *   - `startId`: minted under the rule (`jti`), it names its start row, which must be its pair's
 *     latest row; an end, or a newer start of the same pair, ends it;
 *   - `legacy`: a token from before the switch (no `asv`, IM-12) keeps acting until its pair's log
 *     shows an end or a start under the rule (one with a duration); Phase 2 wrote its start row best
 *     effort, so a pair with no row at all does not refuse it;
 *   - `open`: a token minted under the rule before it carried `jti`; it names whatever start of the
 *     pair is open. The request path ends it at once; a Stop or a sign-out end the open one.
 */
export type ActAsBinding = { startId: string } | { legacy: true } | { open: true }

export function bindingOf(claims: ActAsClaims): ActAsBinding {
  if (claims.jti) return { startId: claims.jti }
  return claims.asv === undefined ? { legacy: true } : { open: true }
}

type Db = Pick<Prisma.TransactionClient, 'actAsAudit'>
type PairRow = { id: string; event: string; durationMinutes: number | null; createdAt: Date }

/** The pair's latest row: one read on the `(admin_id, created_at)` index. */
function latestOfPair(db: Db, adminId: string, targetUserId: string): Promise<PairRow | null> {
  return db.actAsAudit.findFirst({
    where: { adminId, targetUserId },
    orderBy: { createdAt: 'desc' },
    select: { id: true, event: true, durationMinutes: true, createdAt: true },
  })
}

function bindingInForce(latest: PairRow | null, binding: ActAsBinding): boolean {
  if ('startId' in binding) return latest?.event === 'start' && latest.id === binding.startId
  if ('legacy' in binding) return !latest || (latest.event === 'start' && latest.durationMinutes == null)
  return latest?.event === 'start'
}

/** A row's time: now, but always after the pair's last row. */
function after(latest: PairRow | null): Date {
  const at = now().getTime()
  return new Date(latest ? Math.max(at, latest.createdAt.getTime() + 1) : at)
}

/**
 * Whether the impersonation `binding` names is still the one the log shows running for the pair:
 * the per-request check of an act-as cookie (session.ts), one indexed read. A failed read throws.
 */
export async function actAsBindingInForce(adminId: string, targetUserId: string, binding: ActAsBinding): Promise<boolean> {
  return bindingInForce(await latestOfPair(prisma, adminId, targetUserId), binding)
}

/** Serialises the rows of one admin's impersonations across requests and webapp copies. */
function lockKey(adminId: string): string {
  return `rbac-act-as:${adminId}`
}

async function lockAdmin(tx: Prisma.TransactionClient, adminId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${lockKey(adminId)}))`
}

export interface ActAsEndInput {
  adminId: string
  targetUserId: string
  endedBy: ActAsEnd
  /** The admin's email, for the `act_as.refused` row. */
  adminEmail?: string | null
  /** The impersonation that ends; left out, whichever start of the pair is open. */
  binding?: ActAsBinding
  /** False when the caller closes the admin's sockets itself (a whole account's, accountStatus.ts). */
  closeSockets?: boolean
}

/**
 * The agent checks a WebSocket ticket only when its socket opens, so what the admin opened acting
 * as the account (a chat and its run, a terminal, a CypherFix socket) is closed when the
 * impersonation ends; the account's own sockets and runs stay. Never throws: a close the agent
 * did not confirm is logged (`[rbac] socket-close failed user=<account> actor=<admin>`) and the
 * end stands.
 */
async function closeActAsSockets({ adminId, targetUserId, closeSockets = true }: ActAsEndInput): Promise<void> {
  if (!closeSockets) return
  await closeAgentSockets({ userId: targetUserId, actorId: adminId, kinds: [...WS_SOCKETS], scope: 'act_as' })
}

/** The end row, inside the caller's locked transaction, when the impersonation is still the running one. */
async function endInTx(tx: Prisma.TransactionClient, { adminId, targetUserId, endedBy, binding = { open: true } }: ActAsEndInput): Promise<boolean> {
  const latest = await latestOfPair(tx, adminId, targetUserId)
  if (!bindingInForce(latest, binding)) return false
  await tx.actAsAudit.create({ data: { adminId, targetUserId, event: 'end', source: 'api', endedBy, createdAt: after(latest) } })
  return true
}

function loggedEnd({ adminId, targetUserId, endedBy }: ActAsEndInput): void {
  console.info(`[audit] act-as.end admin=${adminId} target=${targetUserId} ended-by=${endedBy}`)
}

/**
 * Writes the end row of the admin's impersonation of `targetUserId`, once: under a lock per admin,
 * and only while that impersonation is the one the log shows running (a Stop, an expiry seen by
 * another request or another copy, a newer act-as already ended it). A forbidden pair also writes
 * `act_as.refused`. True when it wrote.
 */
export async function recordActAsEnd(input: ActAsEndInput): Promise<boolean> {
  const { adminId, targetUserId, endedBy, adminEmail } = input
  const wrote = await prisma.$transaction(async (tx) => {
    await lockAdmin(tx, adminId)
    return endInTx(tx, input)
  })
  if (!wrote) return false
  loggedEnd(input)
  await closeActAsSockets(input)
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
    // It ends all the same, and so does what was opened under it.
    await closeActAsSockets(input)
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
    select: { id: true, adminId: true, targetUserId: true, event: true, createdAt: true, durationMinutes: true },
  })
  const seen = new Set<string>()
  let ended = 0
  for (const row of rows) {
    const pair = `${row.adminId}\u0000${row.targetUserId}`
    if (seen.has(pair)) continue
    seen.add(pair)
    if (row.event !== 'start' || !row.durationMinutes) continue
    if (row.createdAt.getTime() + row.durationMinutes * 60_000 > now().getTime()) continue
    const binding = { startId: row.id }
    if (await recordActAsEnd({ adminId: row.adminId, targetUserId: row.targetUserId, endedBy: 'expired', binding })) ended += 1
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

/** The admin's own act-as token as the browser sent it, read (an expired one included), or null. */
async function presentedBy(adminId: string, token: string | null) {
  const read = token ? await readActAsToken(token) : null
  return read && read.claims.sub === adminId && read.claims.act !== adminId ? read : null
}

/**
 * The end of the impersonation an act-as token names, when it is this admin's and still the running
 * one (`expired` once the token has, else `endedBy`), and `expired` for any of the admin's
 * impersonations whose time ran out with no cookie left to say so: a Stop, a sign-out. Written once
 * each; a stale copy of a cookie ends nothing.
 */
export async function endPresentedActAs(adminId: string, token: string | null, endedBy: ActAsEnd): Promise<void> {
  const read = await presentedBy(adminId, token)
  if (read) {
    const binding = bindingOf(read.claims)
    await recordActAsEnd({ adminId, targetUserId: read.claims.act, endedBy: read.expired ? 'expired' : endedBy, binding })
  }
  await settleExpiredActAs({ adminId })
}

export interface ImpersonationStart {
  admin: { id: string; sessionVersion: number }
  targetUserId: string
  /** The token's lifetime. */
  seconds: number
  reason: string | null
  durationMinutes: number
  /** The act-as token the browser sent: the impersonation it names ends here. */
  presentedToken: string | null
}

/**
 * Starts an impersonation and returns its act-as token: it expires with it, carries the admin's
 * session version (signing the admin out everywhere ends it) and names its start row. In one
 * transaction under the admin's lock: the impersonation the browser held ends (`stopped`, `expired`
 * when its token has), so does one of the same account still open in another browser (one at a time
 * per pair, so a token always names its pair's latest start), and the start row is written with its
 * reason and duration. A failed write throws and writes nothing: no start row, no impersonation
 * (IM-09), and the previous one runs on, as its unwritten end says.
 */
export async function startImpersonation(start: ImpersonationStart): Promise<string> {
  const { admin, targetUserId, seconds, reason, durationMinutes } = start
  await settleExpiredActAs({ adminId: admin.id })
  const startId = randomUUID()
  const token = await createActAsToken(admin.id, targetUserId, seconds, { asv: admin.sessionVersion, jti: startId })
  const previous = await presentedBy(admin.id, start.presentedToken)
  const ends: ActAsEndInput[] = []
  if (previous) {
    ends.push({
      adminId: admin.id, targetUserId: previous.claims.act,
      endedBy: previous.expired ? 'expired' : 'stopped', binding: bindingOf(previous.claims),
    })
  }
  ends.push({ adminId: admin.id, targetUserId, endedBy: 'stopped' })
  const ended = await prisma.$transaction(async (tx) => {
    await lockAdmin(tx, admin.id)
    const written: ActAsEndInput[] = []
    for (const end of ends) if (await endInTx(tx, end)) written.push(end)
    const latest = await latestOfPair(tx, admin.id, targetUserId)
    await tx.actAsAudit.create({
      data: {
        id: startId, adminId: admin.id, targetUserId, event: 'start', source: 'api',
        ...(reason ? { reason } : {}), durationMinutes, createdAt: after(latest),
      },
    })
    return written
  })
  for (const end of ended) loggedEnd(end)
  console.info(`[audit] act-as.start admin=${admin.id} target=${targetUserId}`)
  // Before the browser can open a socket under the new token, so only the ended ones close.
  for (const end of ended) await closeActAsSockets(end)
  return token
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
