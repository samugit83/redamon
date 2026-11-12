// R1: thin server-side audit helper. Emits a structured console line (the repo's
// `[tag]` bracket convention) AND an append-only DB row. Populate the actor going
// forward only. `writeAudit` is best-effort: an audit failure must NEVER break the
// underlying request, so its insert is wrapped and swallowed with a log line.
// `writeAuditTx` is the opposite, for privileged changes (AU-05): the row is written
// in the change's own transaction and a failure throws, so no row means no change.
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'

export interface AuditEntry {
  /** The person signed in, never the account an admin acts as (lib/auditActor.ts). */
  actorId?: string | null
  /** The account an admin acted as, when acting. */
  onBehalfOfUserId?: string | null
  /** The actor's email when the row is written. */
  actorEmail?: string | null
  projectId?: string | null
  /** The permission the action used, when one applies. */
  permission?: string | null
  action: string
  targetType: string
  targetId?: string | null
  before?: unknown
  after?: unknown
  source?: string // "api" | "ui" | "admin" | "system"
}

/** Only the audit table of a transaction client is used; the plugin tests' fake has it too. */
export interface AuditTx {
  auditLog: { create(args: { data: Prisma.AuditLogUncheckedCreateInput }): Promise<unknown> }
}

const OPTIONAL_COLUMNS = ['onBehalfOfUserId', 'actorEmail', 'projectId', 'permission'] as const

function auditRow(entry: AuditEntry): Prisma.AuditLogUncheckedCreateInput {
  const row: Prisma.AuditLogUncheckedCreateInput = {
    actorId: entry.actorId ?? null,
    action: entry.action,
    targetType: entry.targetType,
    targetId: entry.targetId ?? null,
    before: (entry.before ?? undefined) as never,
    after: (entry.after ?? undefined) as never,
    source: entry.source ?? 'api',
  }
  // An empty column is left out, not written as null: the database default is null
  // anyway, and a row without them keeps exactly the shape it had before they existed.
  for (const column of OPTIONAL_COLUMNS) {
    const value = entry[column]
    if (value) row[column] = value
  }
  return row
}

function logLine(entry: AuditEntry): string {
  const onBehalf = entry.onBehalfOfUserId ? ` on-behalf-of=${entry.onBehalfOfUserId}` : ''
  return `[audit] ${entry.action} actor=${entry.actorId ?? '-'}${onBehalf} ` +
    `target=${entry.targetType}:${entry.targetId ?? '-'} source=${entry.source ?? 'api'}`
}

export async function writeAudit(entry: AuditEntry): Promise<void> {
  console.info(logLine(entry))
  try {
    await prisma.auditLog.create({ data: auditRow(entry) })
  } catch (e) {
    // Never let audit persistence failures break the request path.
    console.error(`[audit] failed to persist ${entry.action}:`, e)
  }
}

/**
 * Writes the row through `tx`, the transaction of the change it records, and throws
 * when it cannot: the caller's transaction then rolls the change back.
 */
export async function writeAuditTx(tx: AuditTx, entry: AuditEntry): Promise<void> {
  console.info(logLine(entry))
  try {
    await tx.auditLog.create({ data: auditRow(entry) })
  } catch (e) {
    console.error(`[audit] failed to persist ${entry.action} (the change is rolled back):`, e)
    throw e
  }
}

export interface ActAsAuditEntry {
  adminId: string
  targetUserId: string
  event: 'start' | 'end'
  source?: string // "api" | "self-clear"
  /** Step 3.14 (permissions switch on): the start row's reason and duration, the end row's cause. */
  reason?: string | null
  durationMinutes?: number | null
  endedBy?: string | null
}

const ACT_AS_OPTIONAL = ['reason', 'durationMinutes', 'endedBy'] as const

/**
 * Best effort, like writeAudit; `strict` throws instead, for a row the action must not go on
 * without (an impersonation's start with the permissions switch on: no row, no impersonation).
 */
export async function writeActAsAudit(entry: ActAsAuditEntry, { strict = false }: { strict?: boolean } = {}): Promise<void> {
  console.info(`[audit] act-as.${entry.event} admin=${entry.adminId} target=${entry.targetUserId}`)
  const data: Prisma.ActAsAuditUncheckedCreateInput = {
    adminId: entry.adminId,
    targetUserId: entry.targetUserId,
    event: entry.event,
    source: entry.source ?? 'api',
  }
  // Left out when empty, so a row written without them keeps the shape it always had.
  for (const column of ACT_AS_OPTIONAL) {
    const value = entry[column]
    if (value !== undefined && value !== null && value !== '') (data as Record<string, unknown>)[column] = value
  }
  try {
    await prisma.actAsAudit.create({ data })
  } catch (e) {
    console.error(`[audit] failed to persist act-as.${entry.event}:`, e)
    if (strict) throw e
  }
}
