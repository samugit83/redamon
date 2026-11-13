/**
 * Oversight (step 4.14; SH-47, DV-24, OQ-03; feature document §4.5): an admin holding
 * `projects:oversee` reads any project at the Read level, without Raw data & files and without
 * anyone's private conversations (projectAccess answers `via: 'oversight'`), and every such read is
 * audited and shown in the owner's activity feed.
 *
 * - The audit: one `project.oversee` row per admin, project and UTC day (DV-24), written by the
 *   callers that used an oversight access: the route guard (guards.ts, every requirePermission and
 *   withPermission allowed through oversight), the activity feed and the share list. projectAccess
 *   stays a pure read: its MCP and plugin callers never take oversight. The row is written in one
 *   transaction that holds `pg_advisory_xact_lock(hashtext('oversee:<admin>:<project>:<day>'))` and
 *   first looks for that day's row, so two webapp copies cannot both write it (AuditLog has no
 *   unique index and no day column). Each process then remembers the day's rows it wrote or found,
 *   so a second read costs nothing. A failed write throws: the caller refuses the read (no row, no
 *   read).
 * - Never while acting as someone: under act-as the account acted as decides (can() refuses an
 *   oversight access to an acting session, D-22), and no row is written for one.
 * - The "All projects (oversight)" list (`oversightProjects`) names every project with its owner
 *   and the holder's own access to each, as the user directory's project list does for an admin
 *   (step 6.2): listing writes no row; opening a project is the read the row records.
 */
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import type { Capabilities } from './capabilities'
import { now } from './clock'
import { myAccessView, SHARE_ACCESS, type MyAccess, type ProjectAccess, type ProjectAccessLevel, type ProjectAccessVia } from './projectAccess'

export const OVERSEE_ACTION = 'project.oversee'
export const OVERSEE_PERMISSION = 'projects:oversee'
const DAY_MS = 86_400_000

/** The UTC day of an instant (`YYYY-MM-DD`): DV-24's unit, one row per admin, project and day. */
export function oversightDay(at: Date): string {
  return at.toISOString().slice(0, 10)
}

export function oversightLockKey(actorId: string, projectId: string, day: string): string {
  return `oversee:${actorId}:${projectId}:${day}`
}

let memoDay = ''
const recorded = new Set<string>()

export function clearOversightMemoForTests(): void {
  memoDay = ''
  recorded.clear()
}

export interface OversightReader {
  id: string
  email?: string | null
}

/**
 * Writes the day's `project.oversee` row for this admin and project unless it exists. `read` is the
 * permission the request used (the route's, or the feed's), kept in the row's `after`. Throws when
 * the row can be neither found nor written.
 */
export async function recordOversightRead(reader: OversightReader, projectId: string, read: string, source = 'api'): Promise<void> {
  const day = oversightDay(now())
  if (day !== memoDay) {
    recorded.clear()
    memoDay = day
  }
  const key = oversightLockKey(reader.id, projectId, day)
  if (recorded.has(key)) return
  const start = new Date(`${day}T00:00:00.000Z`)
  const end = new Date(start.getTime() + DAY_MS)
  await auditedTransaction(prisma, async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key}))`
    const existing = await tx.auditLog.findFirst({
      where: { action: OVERSEE_ACTION, actorId: reader.id, projectId, createdAt: { gte: start, lt: end } },
      select: { id: true },
    })
    if (existing) return
    await writeAuditTx(tx, {
      actorId: reader.id,
      ...(reader.email ? { actorEmail: reader.email } : {}),
      projectId,
      permission: OVERSEE_PERMISSION,
      action: OVERSEE_ACTION,
      targetType: 'project',
      targetId: projectId,
      after: { day, read },
      source,
    })
  })
  recorded.add(key)
}

/** Who asked, as the guards and the identity read them. */
export interface OversightIdentity {
  principal: { id: string; email?: string | null }
  actingAs?: unknown
}

/**
 * The audit of a read that `access` allowed: the day's row when the access came from oversight and
 * the person acts as nobody; nothing for any other access (the owner, a share, Root's break-glass,
 * whose opening is audited instead).
 */
export async function auditOversightRead(identity: OversightIdentity, access: ProjectAccess | null | undefined, read: string): Promise<void> {
  if (access?.via !== 'oversight' || identity.actingAs) return
  await recordOversightRead({ id: identity.principal.id, email: identity.principal.email }, access.project.id, read)
}

/** The fields of a list row, as GET /api/projects selects them (the cards read them). */
const PROJECT_LIST_SELECT = {
  id: true,
  userId: true,
  name: true,
  description: true,
  targetDomain: true,
  subdomainList: true,
  ipMode: true,
  targetIps: true,
  domainBatchMode: true,
  domainBatchHosts: true,
  captureProxyEnabled: true,
  createdAt: true,
  updatedAt: true,
  user: { select: { id: true, name: true, email: true } },
} as const

interface ListRow {
  id: string
  userId: string
  user: { id: string; name: string | null; email: string | null } | null
  [field: string]: unknown
}

function rowAccess(row: ListRow, level: ProjectAccessLevel, rawData: boolean, via: ProjectAccessVia): MyAccess {
  const access = { project: { id: row.id, userId: row.userId }, level, toggles: { rawData }, via } as ProjectAccess
  return myAccessView(access, row.user)
}

/**
 * Every project of the instance, newest first, each with the holder's own access as projectAccess
 * would answer it with sharing in force (the owner; a live share; Root's unexpired break-glass, which
 * also needs `projects:administer` now; oversight otherwise). For a holder of `projects:oversee`; the
 * route checks it and that sharing is in force.
 */
export async function oversightProjects(userId: string, capabilities: Pick<Capabilities, 'has'>): Promise<Array<ListRow & { myAccess: MyAccess }>> {
  const at = now()
  const [rows, shares, glass] = await Promise.all([
    prisma.project.findMany({ orderBy: { createdAt: 'desc' }, select: PROJECT_LIST_SELECT }) as Promise<ListRow[]>,
    prisma.projectCollaborator.findMany({
      where: { userId, OR: [{ expiresAt: null }, { expiresAt: { gt: at } }] },
      select: { projectId: true, access: true, rawData: true },
    }),
    capabilities.has('projects:administer')
      ? prisma.projectBreakGlass.findMany({ where: { userId, expiresAt: { gt: at } }, select: { projectId: true } })
      : Promise.resolve([] as Array<{ projectId: string }>),
  ])
  const shared = new Map(shares.filter((s) => SHARE_ACCESS.has(s.access)).map((s) => [s.projectId, s.rawData === true]))
  const glassOn = new Set(glass.map((g) => g.projectId))
  return rows.map((row) => {
    let myAccess: MyAccess
    if (row.userId === userId) myAccess = rowAccess(row, 'owner', true, 'owner')
    else if (shared.get(row.id) === true) myAccess = rowAccess(row, 'read', true, 'share')
    else if (glassOn.has(row.id)) myAccess = rowAccess(row, 'read', true, 'break_glass')
    else if (shared.has(row.id)) myAccess = rowAccess(row, 'read', false, 'share')
    else myAccess = rowAccess(row, 'read', false, 'oversight')
    return { ...row, myAccess }
  })
}
