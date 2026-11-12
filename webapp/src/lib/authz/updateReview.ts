/**
 * What an admin reviews after the RBAC hardening (step 1.18): the legacy grants existing
 * members kept (scripts/backfill-rbac-legacy-grants.mjs), and the one-time "What changed in
 * this update" card. Server side only.
 *
 * A grant is only ever kept or removed here; nothing adds one (HD-29). Every decision is one
 * AuditLog row per account and grant, written in the same transaction as the change and under
 * the backfill's advisory lock:
 * - `rbac.legacy_grant.remove` (`targetId` the account, `after.grant`): the backfill reads it,
 *   so a re-derivation after a downgrade never gives a removed grant back;
 * - `rbac.legacy_grant.keep`: the grant stays and is no longer "pending".
 *
 * Only non-admin accounts are reviewed: an admin reaches every shared tool by role, so its
 * grants matter only if it is demoted, and then they show up here again.
 */
import prisma from '@/lib/prisma'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import { isStdioServer } from '@/lib/mcp/schema'
import { legacyCutoff } from './sharedTools'
import { invalidatePrincipal } from './principal'

/** The backfill's LEGACY_GRANTS, LOCK_KEY and REMOVE_ACTION (a test keeps them equal). */
export const LEGACY_GRANTS = ['kali_terminal', 'shell_sessions', 'tunnels'] as const
export type LegacyGrant = (typeof LEGACY_GRANTS)[number]
export const LEGACY_GRANTS_LOCK_KEY = 'system.rbac_legacy_grants'
export const REMOVE_ACTION = 'rbac.legacy_grant.remove'
export const KEEP_ACTION = 'rbac.legacy_grant.keep'

export const WHATS_NEW_DISMISSED_ACTION = 'rbac.whats_new_dismissed'
/** The card's edition: a later update with a card of its own uses a new one. */
export const WHATS_NEW_EDITION = 'rbac-hardening'

export function isLegacyGrant(value: unknown): value is LegacyGrant {
  return typeof value === 'string' && (LEGACY_GRANTS as readonly string[]).includes(value)
}

export interface LegacyGrantState {
  grant: LegacyGrant
  state: 'pending' | 'kept'
}

export interface LegacyHolder {
  id: string
  name: string
  email: string
  grants: LegacyGrantState[]
}

/** Who made a decision: the real signed-in admin, and the account it was acting as, if any. */
export interface DecisionActor {
  actorId: string
  actingAsUserId: string | null
  /** The admin's email when the session read returned it (lib/auditActor.ts). */
  actorEmail?: string | null
}

/** The actor columns of a decision row, as lib/auditActor.ts names them; an empty one is left out. */
function decisionActorColumns(actor: DecisionActor) {
  return actorFields(auditActorOf({ id: actor.actorId, email: actor.actorEmail }, actor.actingAsUserId))
}

type Db = Pick<typeof prisma, 'user' | 'auditLog'>
type Tx = Parameters<Parameters<typeof prisma.$transaction>[0]>[0]

const grantKey = (accountId: string, grant: string) => `${accountId}\u0000${grant}`

function grantOf(after: unknown): string | null {
  if (!after || typeof after !== 'object' || Array.isArray(after)) return null
  const grant = (after as { grant?: unknown }).grant
  return typeof grant === 'string' ? grant : null
}

const REVIEWED = { role: { not: 'admin' }, legacyGrants: { hasSome: [...LEGACY_GRANTS] } }

async function readHolders(db: Db): Promise<LegacyHolder[]> {
  const users = await db.user.findMany({
    where: REVIEWED,
    select: { id: true, name: true, email: true, legacyGrants: true },
    orderBy: { email: 'asc' },
  })
  if (users.length === 0) return []
  const kept = new Set((await db.auditLog.findMany({
    where: { action: KEEP_ACTION, targetType: 'user', targetId: { in: users.map(u => u.id) } },
    select: { targetId: true, after: true },
  })).map(r => grantKey(r.targetId ?? '', grantOf(r.after) ?? '')))
  return users.map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    grants: LEGACY_GRANTS.filter(g => u.legacyGrants.includes(g)).map(g => ({
      grant: g,
      state: kept.has(grantKey(u.id, g)) ? 'kept' as const : 'pending' as const,
    })),
  }))
}

export function listLegacyHolders(): Promise<LegacyHolder[]> {
  return readHolders(prisma)
}

/** How many grants of non-admin accounts no admin has decided on yet. */
export async function pendingLegacyGrantCount(): Promise<number> {
  const holders = await readHolders(prisma)
  return holders.reduce((n, h) => n + h.grants.filter(g => g.state === 'pending').length, 0)
}

async function lock(tx: Tx): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LEGACY_GRANTS_LOCK_KEY}))`
}

interface AuditLine {
  action: string
  actorId: string
  targetId: string
}

// The rows go through the transaction, not writeAudit (best effort): a removal whose row were
// lost could be given back by the backfill. This prints the line writeAudit would.
function logAudit(rows: AuditLine[]): void {
  for (const r of rows) console.info(`[audit] ${r.action} actor=${r.actorId} target=user:${r.targetId} source=api`)
}

async function writeDecision(
  tx: Tx, actor: DecisionActor, action: string, targetId: string, grant: LegacyGrant, bulk: boolean,
): Promise<AuditLine> {
  await tx.auditLog.create({
    data: {
      ...decisionActorColumns(actor),
      action,
      targetType: 'user',
      targetId,
      after: {
        grant,
        ...(bulk ? { bulk: true } : {}),
        ...(actor.actingAsUserId ? { actingAsUserId: actor.actingAsUserId } : {}),
      },
      source: 'api',
    },
  })
  return { action, actorId: actor.actorId, targetId }
}

export type DecisionResult =
  | { ok: true; changed: boolean }
  | { ok: false; status: 404 | 409; code: 'not_found' | 'not_held'; error: string }

/**
 * Keep or remove one grant of one account. Removing a grant the account no longer holds
 * changes nothing (`changed: false`); keeping one it does not hold is refused, so a keep can
 * never put a grant back.
 */
export async function decideLegacyGrant(
  actor: DecisionActor, userId: string, grant: LegacyGrant, action: 'keep' | 'remove',
): Promise<DecisionResult> {
  const { result, rows } = await prisma.$transaction(async (tx) => {
    await lock(tx)
    const user = await tx.user.findUnique({
      where: { id: userId },
      select: { id: true, legacyGrants: true, updatedAt: true },
    })
    if (!user) {
      return { result: { ok: false, status: 404, code: 'not_found', error: 'Account not found' } as const, rows: [] }
    }
    const held = user.legacyGrants.includes(grant)
    if (action === 'remove') {
      if (!held) return { result: { ok: true, changed: false } as const, rows: [] }
      // The row's own updatedAt, as the backfill writes it: a grant is not an edit of the account.
      await tx.user.update({
        where: { id: userId },
        data: { legacyGrants: user.legacyGrants.filter(g => g !== grant), updatedAt: user.updatedAt },
      })
      const row = await writeDecision(tx, actor, REMOVE_ACTION, userId, grant, false)
      return { result: { ok: true, changed: true } as const, rows: [row] }
    }
    if (!held) {
      return {
        result: { ok: false, status: 409, code: 'not_held', error: 'This account no longer holds that grant.' } as const,
        rows: [],
      }
    }
    const decided = await tx.auditLog.findFirst({
      where: { action: KEEP_ACTION, targetType: 'user', targetId: userId, after: { path: ['grant'], equals: grant } },
      select: { id: true },
    })
    if (decided) return { result: { ok: true, changed: false } as const, rows: [] }
    const row = await writeDecision(tx, actor, KEEP_ACTION, userId, grant, false)
    return { result: { ok: true, changed: true } as const, rows: [row] }
  })
  if (action === 'remove' && result.ok && result.changed) invalidatePrincipal(userId)
  logAudit(rows)
  return result
}

export interface BulkDecisionResult {
  /** Grants removed or newly kept. */
  changed: number
  /** Accounts that lost the Kali terminal grant: their open terminals are to be closed. */
  terminalLost: string[]
}

/**
 * `remove_all`: every legacy grant of every reviewed account, kept ones included (what the
 * card's "Remove all" says); values the backfill does not know are left alone, as it does.
 * `keep_all`: every grant still pending.
 */
export async function decideAllLegacyGrants(
  actor: DecisionActor, action: 'keep_all' | 'remove_all',
): Promise<BulkDecisionResult> {
  const { result, rows, updated } = await prisma.$transaction(async (tx) => {
    await lock(tx)
    const rows: AuditLine[] = []
    if (action === 'keep_all') {
      for (const holder of await readHolders(tx)) {
        for (const g of holder.grants) {
          if (g.state === 'pending') rows.push(await writeDecision(tx, actor, KEEP_ACTION, holder.id, g.grant, true))
        }
      }
      return { result: { changed: rows.length, terminalLost: [] }, rows, updated: [] as string[] }
    }
    const users = await tx.user.findMany({
      where: REVIEWED,
      select: { id: true, legacyGrants: true, updatedAt: true },
      orderBy: { id: 'asc' },
    })
    const terminalLost: string[] = []
    for (const user of users) {
      const removed = LEGACY_GRANTS.filter(g => user.legacyGrants.includes(g))
      await tx.user.update({
        where: { id: user.id },
        data: { legacyGrants: user.legacyGrants.filter(g => !isLegacyGrant(g)), updatedAt: user.updatedAt },
      })
      for (const g of removed) rows.push(await writeDecision(tx, actor, REMOVE_ACTION, user.id, g, true))
      if (removed.includes('kali_terminal')) terminalLost.push(user.id)
    }
    return { result: { changed: rows.length, terminalLost }, rows, updated: users.map(u => u.id) }
  })
  for (const id of updated) invalidatePrincipal(id)
  logAudit(rows)
  return result
}

export interface StdioMember {
  id: string
  name: string
  email: string
  servers: number
}

export interface WhatsNewState {
  dismissed: boolean
  /** False on a single-operator install: nothing changed that an admin needs to hear about. */
  applies: boolean
  /** Non-admin accounts whose saved stdio MCP servers no longer load (OQ-48). */
  stdioMembers: StdioMember[]
}

/**
 * The facts of the "What changed in this update" card for one admin. It applies when more
 * than one account that can sign in existed at the upgrade (the cutoff; every account when
 * the backfill has not written it yet), or when a non-admin account holds stdio servers.
 */
export async function whatsNewState(adminId: string): Promise<WhatsNewState> {
  const dismissal = await prisma.auditLog.findFirst({
    where: { action: WHATS_NEW_DISMISSED_ACTION, actorId: adminId, targetId: WHATS_NEW_EDITION },
    select: { id: true },
  })
  if (dismissal) return { dismissed: true, applies: false, stdioMembers: [] }

  const cutoff = await legacyCutoff()
  const signIn = await prisma.user.count({
    where: { password: { not: '' }, ...(cutoff ? { createdAt: { lte: cutoff } } : {}) },
  })
  const members = await prisma.user.findMany({
    where: { role: { not: 'admin' } },
    select: { id: true, name: true, email: true },
    orderBy: { email: 'asc' },
  })
  // One settings row per account; the members are picked in the loop below.
  const settings = members.length === 0 ? [] : await prisma.userSettings.findMany({
    select: { userId: true, mcpServers: true },
  })
  const stdioCount = new Map(settings.map(s => [
    s.userId,
    Array.isArray(s.mcpServers) ? s.mcpServers.filter(isStdioServer).length : 0,
  ]))
  const stdioMembers = members
    .filter(m => (stdioCount.get(m.id) ?? 0) > 0)
    .map(m => ({ ...m, servers: stdioCount.get(m.id) ?? 0 }))
  return { dismissed: false, applies: signIn > 1 || stdioMembers.length > 0, stdioMembers }
}

/** Records that this admin read the card. A second dismissal writes nothing. */
export async function dismissWhatsNew(actor: DecisionActor): Promise<{ changed: boolean }> {
  const existing = await prisma.auditLog.findFirst({
    where: { action: WHATS_NEW_DISMISSED_ACTION, actorId: actor.actorId, targetId: WHATS_NEW_EDITION },
    select: { id: true },
  })
  if (existing) return { changed: false }
  await prisma.auditLog.create({
    data: {
      ...decisionActorColumns(actor),
      action: WHATS_NEW_DISMISSED_ACTION,
      targetType: 'notice',
      targetId: WHATS_NEW_EDITION,
      after: actor.actingAsUserId ? { actingAsUserId: actor.actingAsUserId } : undefined,
      source: 'api',
    },
  })
  console.info(`[audit] ${WHATS_NEW_DISMISSED_ACTION} actor=${actor.actorId} target=notice:${WHATS_NEW_EDITION} source=api`)
  return { changed: true }
}
