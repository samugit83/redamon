/**
 * The project activity feed (step 4.13; UI-08, AU-07, AU-09, IM-07; feature document §4.1.9, §7.3):
 * who did what on a project, for GET /api/projects/[id]/activity.
 *
 * - The rows are the audit rows of the project (`projectId`), and the rows written about it before
 *   step 2.1 added that column (`targetType: 'project'`, `targetId`), newest first, a page at a time
 *   (a cursor of the last row's instant and id, so rows of the same instant are neither repeated nor
 *   skipped). Each index serves one side: `(projectId, createdAt)` and `(targetType, targetId,
 *   createdAt)`.
 * - Each row says only: the action, its label and group (auditLabels.ts), when, through which door
 *   (`source`), and the people by name, email and account type: who did it (the person signed in),
 *   the account an admin acted as (`onBehalfOf`), and the account a share row changed. Never `before`
 *   or `after` (a lookup's email hash, a token prefix, a share's note), never an account id
 *   (master plan §9.8).
 * - Readers: the owner (and Phase 5's co-owners) through `project:share` at Manage; an admin reading
 *   the project by oversight, or Root by break-glass. With Root's policy hiding shares from admins
 *   (`adminsSeeAllShares: false`) an overseer reads the feed without the share rows, as the share list
 *   refuses them (projectShares.requireShareListAccess).
 */
import { NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { getAuthzIdentity } from '@/lib/session'
import { auditActionLabel, auditGroupTerms, isAuditGroup, type AuditGroup } from './auditLabels'
import { projectAccess } from './projectAccess'
import { accountTypeOf, loadInstanceRoot, type AccountType } from './root'
import type { SharingPolicy } from './sharingPolicy'

export const ACTIVITY_PAGE_SIZE = 50
const SHARE_ACTION_PREFIX = 'project.share.'
const CURSOR_ID = /^[A-Za-z0-9_-]{1,64}$/

/** A person as a feed row names them (IdentityLabel's fields). */
export interface ActivityPerson {
  /** Empty for a deleted account. */
  name: string
  /** The account's email; for a deleted actor the one the row recorded; null when nothing names it. */
  email: string | null
  accountType: AccountType | null
  deleted: boolean
}

export interface ActivityEvent {
  id: string
  at: string
  action: string
  label: string
  /** Null for an action no label knows (a newer or older version wrote it). */
  group: AuditGroup | null
  /** Null for the system, the host scripts, or a row that names no one. */
  actor: ActivityPerson | null
  onBehalfOf: ActivityPerson | null
  /** The account a row is about (a share's collaborator); null for any other target. */
  target: ActivityPerson | null
  source: string
}

export interface ActivityPage {
  project: { name: string } | null
  events: ActivityEvent[]
  nextCursor: string | null
  /** The share rows were left out: an overseer under Root's `adminsSeeAllShares: false`. */
  sharesHidden: boolean
}

export interface ActivityQuery {
  cursor: { at: Date; id: string } | null
  group: AuditGroup | null
}

export function encodeActivityCursor(at: Date, id: string): string {
  return Buffer.from(JSON.stringify({ t: at.toISOString(), i: id }), 'utf8').toString('base64url')
}

function decodeActivityCursor(value: string): ActivityQuery['cursor'] {
  try {
    const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as { t?: unknown; i?: unknown }
    if (typeof parsed?.t !== 'string' || typeof parsed.i !== 'string' || !CURSOR_ID.test(parsed.i)) return null
    const at = new Date(parsed.t)
    return Number.isNaN(at.getTime()) || at.toISOString() !== parsed.t ? null : { at, id: parsed.i }
  } catch {
    return null
  }
}

function invalidField(field: string, error: string): NextResponse {
  return NextResponse.json({ error, code: 'invalid_field', field }, { status: 400 })
}

/** `?cursor` (from the previous page) and `?group` (an AUDIT_GROUPS id); 400 naming the field. */
export function parseActivityQuery(params: URLSearchParams): ActivityQuery | NextResponse {
  const rawCursor = params.get('cursor')
  const cursor = rawCursor ? decodeActivityCursor(rawCursor) : null
  if (rawCursor && !cursor) return invalidField('cursor', 'cursor must be the nextCursor of a previous page')
  const rawGroup = params.get('group')
  if (rawGroup && !isAuditGroup(rawGroup)) return invalidField('group', 'group must be one of the activity groups')
  return { cursor, group: rawGroup ? (rawGroup as AuditGroup) : null }
}

/**
 * The second way in, after `project:share` refused with 403: an admin reading the project by
 * oversight, or Root by break-glass, never while acting as someone (the account acted as decides,
 * D-22). Null when neither applies (the route then answers its 403).
 */
export async function oversightActivityAccess(
  projectId: string,
  policy: Readonly<SharingPolicy>,
): Promise<{ hideShares: boolean } | null> {
  const identity = await getAuthzIdentity()
  if (!identity || identity.actingAs) return null
  const access = await projectAccess({ userId: identity.principal.id }, projectId, { principal: identity.principal })
  if (access?.via === 'break_glass') return { hideShares: false }
  if (access?.via === 'oversight') return { hideShares: !policy.adminsSeeAllShares }
  return null
}

function groupWhere(group: AuditGroup): Prisma.AuditLogWhereInput {
  const { actions, prefixes } = auditGroupTerms(group)
  const terms: Prisma.AuditLogWhereInput[] = [
    ...(actions.length ? [{ action: { in: actions } }] : []),
    ...prefixes.map(prefix => ({ action: { startsWith: prefix } })),
  ]
  // Acting as: also every row an admin wrote while acting as someone, whatever its action.
  if (group === 'acting') terms.push({ onBehalfOfUserId: { not: null } })
  return { OR: terms }
}

export function activityWhere(projectId: string, query: ActivityQuery, hideShares: boolean): Prisma.AuditLogWhereInput {
  const and: Prisma.AuditLogWhereInput[] = [{ OR: [{ projectId }, { targetType: 'project', targetId: projectId }] }]
  if (hideShares) and.push({ NOT: { action: { startsWith: SHARE_ACTION_PREFIX } } })
  if (query.group) and.push(groupWhere(query.group))
  if (query.cursor) {
    and.push({ OR: [{ createdAt: { lt: query.cursor.at } }, { createdAt: query.cursor.at, id: { lt: query.cursor.id } }] })
  }
  return { AND: and }
}

interface FeedRow {
  id: string
  action: string
  createdAt: Date
  actorId: string | null
  actorEmail: string | null
  onBehalfOfUserId: string | null
  targetType: string
  targetId: string | null
  source: string
}

/** One page of the feed, newest first. */
export async function readProjectActivity(
  projectId: string,
  query: ActivityQuery,
  { hideShares }: { hideShares: boolean },
): Promise<ActivityPage> {
  const [project, rows] = await Promise.all([
    prisma.project.findUnique({ where: { id: projectId }, select: { name: true } }),
    prisma.auditLog.findMany({
      where: activityWhere(projectId, query, hideShares),
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: ACTIVITY_PAGE_SIZE + 1,
      select: {
        id: true, action: true, createdAt: true, actorId: true, actorEmail: true, onBehalfOfUserId: true,
        targetType: true, targetId: true, source: true,
      },
    }) as Promise<FeedRow[]>,
  ])
  const page = rows.slice(0, ACTIVITY_PAGE_SIZE)
  const last = page[page.length - 1]
  const nextCursor = rows.length > ACTIVITY_PAGE_SIZE && last ? encodeActivityCursor(last.createdAt, last.id) : null

  const ids = new Set<string>()
  for (const r of page) {
    if (r.actorId) ids.add(r.actorId)
    if (r.onBehalfOfUserId) ids.add(r.onBehalfOfUserId)
    if (r.targetType === 'user' && r.targetId) ids.add(r.targetId)
  }
  const [people, root] = await Promise.all([
    ids.size
      ? prisma.user.findMany({ where: { id: { in: [...ids] } }, select: { id: true, name: true, email: true, role: true } })
      : Promise.resolve([]),
    ids.size ? loadInstanceRoot() : Promise.resolve(null),
  ])
  const byId = new Map(people.map(p => [p.id, p]))
  const person = (id: string | null, recordedEmail: string | null = null): ActivityPerson | null => {
    if (!id) return recordedEmail ? { name: '', email: recordedEmail, accountType: null, deleted: false } : null
    const account = byId.get(id)
    if (!account) return { name: '', email: recordedEmail, accountType: null, deleted: true }
    return { name: account.name ?? '', email: account.email, accountType: accountTypeOf(account, root), deleted: false }
  }

  return {
    project: project ? { name: project.name } : null,
    events: page.map((r): ActivityEvent => {
      const { label, group } = auditActionLabel(r.action)
      return {
        id: r.id,
        at: r.createdAt.toISOString(),
        action: r.action,
        label,
        group,
        actor: person(r.actorId, r.actorEmail),
        onBehalfOf: r.onBehalfOfUserId ? person(r.onBehalfOfUserId) : null,
        target: r.targetType === 'user' && r.targetId && byId.has(r.targetId) ? person(r.targetId) : null,
        source: r.source,
      }
    }),
    nextCursor,
    sharesHidden: hideShares,
  }
}
