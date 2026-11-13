/**
 * Conversation privacy, sharing and retention (step 5.8; SH-22, DV-23, T24, OQ-07; feature document §6.6).
 *
 * A conversation is its author's (`Conversation.userId`): only the author writes, continues and deletes
 * it (lib/access.ts `requireConversationAccess`, at `agent:chat`). While write sharing is in force
 * (RBAC_SHARING_WRITE_ENABLED, sharing, and Root's `maxLevel: 'write'`) other people may READ one:
 *   - `shared`: its author shared it with the project (`ConversationShare`, `agent:conversations_share`);
 *   - `managers`: the owner turned on "managers see all conversations"
 *     (`ProjectAccessPolicy.managersSeeAllConversations`): the owner and the co-owners (`M`) read every
 *     conversation of the project;
 *   - `break_glass`: Root's break-glass reads every conversation of the project (its opening is audited and
 *     the owner told, step 4.14).
 * A conversation holds the agent's thoughts, commands and tool output word for word, which is raw data
 * (SH-30, stepContent.ts), so reading another person's also needs Raw data & files (`R*`): a Read share
 * without it and an overseer read none (oversight.ts: never anyone's private conversations). That read asks
 * `graph:read` at `R*` through the route guard, which audits a read made while acting as someone; under
 * act-as the account's share is Read at most (D-22), so the managers view never opens there.
 *
 * Retention (T24, DV-23): deleting an account reassigns its conversations in other people's projects to
 * each project's owner, keeping the former author's id and name or email as they were, while the write
 * switch is on (the user DELETE calls it before the account row goes: Conversation.user cascades). Such a
 * conversation opens read-only, since its checkpoint thread is the former author's
 * (agentic/orchestrator_helpers/config.py), and its write routes refuse a change (409).
 *
 * With the write switch off nothing here reads anything: no Phase 5 table or column, not the policy, and
 * every route answers as after Phase 4 (sharingWrite.flags.off.test.ts).
 */
import { NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { requireConversationAccess, requireConversationAccessBySession, requireEffectiveUser } from '@/lib/access'
import type { EffectiveUser } from '@/lib/session'
import { rbacFlags } from './flags'
import { requireLevel, requirePermission, type PermissionContext } from './guards'
import { meetsLevel, projectAccess, type ProjectAccess } from './projectAccess'
import { ownsRow } from './rowOwner'
import { maxShareLevel, sharingPolicyInForce } from './sharingPolicy'

/** Why a person reads a conversation: their own, or another person's under one of the rules above. */
export type ConversationReader = 'author' | 'shared' | 'managers' | 'break_glass'

/** What a screen is told of a conversation it lists or opens (with the write switch on only). */
export interface ConversationView {
  /** The viewer is its author (after a reassignment, the project's owner is). */
  mine: boolean
  /** Opened without the composer: another person's, or one reassigned from a deleted account. */
  readOnly: boolean
  /** Its author shared it with the project (false while write sharing is not in force). */
  shared: boolean
  /** Who wrote it, when that is not the viewer: their name or email, or the deleted account's snapshot. */
  by: string | null
  /** Reassigned from a deleted account: shown "by <name> (account deleted)". */
  authorDeleted: boolean
}

/** Write sharing in force: the switch, sharing and Root's policy at Read + Write. Switch off: nothing read. */
export async function conversationSharingInForce({ fresh = false }: { fresh?: boolean } = {}): Promise<boolean> {
  if (!rbacFlags().sharingWrite) return false
  const policy = await sharingPolicyInForce({ fresh })
  return policy?.enabled === true && maxShareLevel(policy) === 'write'
}

/**
 * The reassignment and its read-only rule follow the write switch alone, not Root's policy: a deletion while
 * Root holds sharing at Read must not lose a collaborator's conversations either.
 */
export function conversationRetentionOn(): boolean {
  return rbacFlags().sharingWrite
}

type Db = Pick<Prisma.TransactionClient, 'conversation' | 'conversationShare' | 'projectAccessPolicy'>

/** The owner's "managers see all conversations"; no policy row is off. Read on every call. */
export async function managersSeeAllConversations(projectId: string, db: Pick<Db, 'projectAccessPolicy'> = prisma): Promise<boolean> {
  const row = await db.projectAccessPolicy.findUnique({ where: { projectId }, select: { managersSeeAllConversations: true } })
  return row?.managersSeeAllConversations === true
}

/** Sets the owner's policy through `tx` (the transaction of its audit row); answers whether it changed. */
export async function writeManagersSeeAll(tx: Pick<Db, 'projectAccessPolicy'>, projectId: string, value: boolean): Promise<boolean> {
  const before = await managersSeeAllConversations(projectId, tx)
  if (before === value) return false
  await tx.projectAccessPolicy.upsert({
    where: { projectId },
    create: { projectId, managersSeeAllConversations: value },
    update: { managersSeeAllConversations: value },
  })
  return true
}

/** Shares the conversation (`byUserId`, its author) or stops sharing it (null) through `tx`; answers whether it changed. */
export async function writeConversationShare(tx: Pick<Db, 'conversationShare'>, conversationId: string, byUserId: string | null): Promise<boolean> {
  const existing = await tx.conversationShare.findUnique({ where: { conversationId }, select: { id: true } })
  if ((existing !== null) === (byUserId !== null)) return false
  if (byUserId) await tx.conversationShare.create({ data: { conversationId, sharedById: byUserId } })
  else await tx.conversationShare.deleteMany({ where: { conversationId } })
  return true
}

/**
 * Whether the conversation's author shared it with the project, as the plugin platform asks before it hands
 * another person's session to a plugin (step 5.10: "author, or an explicit conversation share"; never the
 * managers' view or break-glass). With write sharing not in force nothing is read and the answer is false.
 */
export async function conversationSharedWithProject(conversationId: string, db: Pick<Db, 'conversationShare'> = prisma): Promise<boolean> {
  if (!conversationId || !(await conversationSharingInForce())) return false
  return (await db.conversationShare.findUnique({ where: { conversationId }, select: { id: true } })) !== null
}

/**
 * How `access` reads a conversation it did not write, or null: below Raw data & files nothing; Root's
 * break-glass every one; a shared one anyone else on the project; with the owner's policy on, the owner and
 * co-owners every one. A pure decision over facts the caller read.
 */
export function othersReader(
  access: Pick<ProjectAccess, 'level' | 'toggles' | 'via'>,
  facts: { shared: boolean; managersSeeAll: boolean },
): Exclude<ConversationReader, 'author'> | null {
  if (!meetsLevel(access as ProjectAccess, 'R*')) return null
  if (access.via === 'break_glass') return 'break_glass'
  if (facts.shared) return 'shared'
  if (facts.managersSeeAll && meetsLevel(access as ProjectAccess, 'M')) return 'managers'
  return null
}

/** The other people's conversations of `projectId` that `access` reads (write sharing in force), or null for none. */
async function othersWhere(access: ProjectAccess, projectId: string): Promise<Prisma.ConversationWhereInput | null> {
  if (!meetsLevel(access, 'R*')) return null
  if (access.via === 'break_glass') return { projectId }
  if (meetsLevel(access, 'M') && (await managersSeeAllConversations(projectId))) return { projectId }
  return { projectId, share: { isNot: null } }
}

/**
 * Every conversation of `projectId` that `viewerId` reads at `access`: their own, and with write sharing in
 * force the others' the rules above open (a co-owner's export, step 5.2, reads this).
 */
export async function readableConversationsWhere(access: ProjectAccess, projectId: string, viewerId: string): Promise<Prisma.ConversationWhereInput> {
  const own: Prisma.ConversationWhereInput = { projectId, userId: viewerId }
  if (!(await conversationSharingInForce())) return own
  const others = await othersWhere(access, projectId)
  return others ? { OR: [own, others] } : own
}

const RETENTION_SELECT = { userId: true, formerAuthorId: true, formerAuthorLabel: true } as const
const VIEW_SELECT = { ...RETENTION_SELECT, user: { select: { name: true, email: true } }, share: { select: { id: true } } } as const

type ViewRow = {
  userId: string
  formerAuthorId: string | null
  formerAuthorLabel: string | null
  user?: { name: string | null; email: string } | null
  share?: { id: string } | null
}

function viewOf(row: ViewRow, viewerId: string): ConversationView {
  const mine = ownsRow({ userId: viewerId }, row.userId)
  const authorDeleted = row.formerAuthorId !== null
  const author = row.user ? (row.user.name?.trim() || row.user.email) : null
  return {
    mine,
    readOnly: !mine || authorDeleted,
    shared: row.share != null,
    by: authorDeleted ? row.formerAuthorLabel : mine ? null : author,
    authorDeleted,
  }
}

/** The view of one conversation for `viewerId`; the share is read only with write sharing in force. */
async function conversationView(conversationId: string, viewerId: string, inForce: boolean): Promise<ConversationView | null> {
  const row = await prisma.conversation.findUnique({
    where: { id: conversationId },
    select: inForce ? VIEW_SELECT : { ...RETENTION_SELECT, user: VIEW_SELECT.user },
  })
  return row ? viewOf(row as ViewRow, viewerId) : null
}

type ConversationRow = { id: string; userId: string; projectId: string }
export type ConversationWhere = { id: string } | { sessionId: string }

export interface ConversationRead {
  conversation: ConversationRow
  reader: ConversationReader
  /** For the screens; null with the write switch off (the answer then carries nothing new). */
  view: ConversationView | null
}

/** Any refusal of another person's read is the author guard's own 404, unless the session or a read failed. */
const asOwn = (refusal: NextResponse, own: NextResponse): NextResponse =>
  refusal.status === 401 || refusal.status >= 500 ? refusal : own

/**
 * The read routes of one conversation (GET by id, by session, its Fireteam waves). The author reads it as
 * before: the author guard, then `agent:chat` on its project. Anyone else gets that guard's 404 unless
 * write sharing is in force and a rule above lets them read it; then `graph:read` at `R*` on the project.
 * No guard runs for a person below Raw data & files, so an overseer's attempt writes no oversight row.
 */
export async function requireConversationRead(request: Request, eff: EffectiveUser, where: ConversationWhere): Promise<ConversationRead | NextResponse> {
  const own = 'id' in where
    ? await requireConversationAccess(eff, where.id)
    : await requireConversationAccessBySession(eff, where.sessionId)
  if (!(own instanceof NextResponse)) {
    const auth = await requirePermission(request, 'agent:chat', { projectId: own.conversation.projectId })
    if (auth instanceof NextResponse) return auth
    const view = conversationRetentionOn()
      ? await conversationView(own.conversation.id, eff.userId, await conversationSharingInForce())
      : null
    return { conversation: own.conversation, reader: 'author', view }
  }
  if (own.status !== 404 || !(await conversationSharingInForce())) return own

  const row = await prisma.conversation.findUnique({
    where,
    select: { id: true, userId: true, projectId: true, share: { select: { id: true } } },
  })
  if (!row) return own
  const before = await projectAccess(eff, row.projectId)
  if (!before || !meetsLevel(before, 'R*')) return own
  const auth = await requirePermission(request, 'graph:read', { projectId: row.projectId })
  if (auth instanceof NextResponse) return asOwn(auth, own)
  if (!auth.access || requireLevel(auth, 'R*')) return own
  const shared = row.share !== null
  const managersSeeAll = !shared && auth.access.via !== 'break_glass' && meetsLevel(auth.access, 'M')
    ? await managersSeeAllConversations(row.projectId)
    : false
  const reader = othersReader(auth.access, { shared, managersSeeAll })
  if (!reader) return own
  const conversation = { id: row.id, userId: row.userId, projectId: row.projectId }
  return { conversation, reader, view: await conversationView(row.id, eff.userId, true) }
}

export interface ConversationListScope {
  where: Prisma.ConversationWhereInput
  /** Fields to select beside the list's own, for the view; empty with the write switch off. */
  select: Prisma.ConversationSelect
  /** The rows as the list answers them: as selected with the switch off, else each with its `access` view. */
  present: (rows: Array<Record<string, unknown>>) => unknown[]
}

function presenter(viewerId: string | null): ConversationListScope['present'] {
  if (viewerId === null) return (rows) => rows
  return (rows) => rows.map((row) => {
    const { userId: _u, formerAuthorId: _f, formerAuthorLabel: _l, user: _a, share: _s, ...listed } = row
    return { ...listed, access: viewOf(row as unknown as ViewRow, viewerId) }
  })
}

/**
 * GET /api/conversations: what the list holds. `auth` is the route's `agent:chat` answer on the project.
 * Allowed: the person's own conversations, exactly as before with the write switch off; with write sharing
 * in force also the others' they may read. Refused (403) with write sharing in force: a person below the
 * agent's level who reaches `graph:read` at `R*` (a Read share with Raw data, Root's break-glass) lists the
 * others' they may read, and has no own; otherwise the route's refusal stands.
 */
export async function conversationListScope(
  request: Request,
  projectId: string,
  auth: PermissionContext | NextResponse,
): Promise<ConversationListScope | NextResponse> {
  if (!(auth instanceof NextResponse)) {
    const me = auth.effective.userId
    const own: Prisma.ConversationWhereInput = { projectId, userId: me }
    if (!conversationRetentionOn()) return { where: own, select: {}, present: presenter(null) }
    if (!(await conversationSharingInForce())) {
      return { where: own, select: { ...RETENTION_SELECT, user: VIEW_SELECT.user }, present: presenter(me) }
    }
    const where = auth.access ? await readableConversationsWhere(auth.access, projectId, me) : own
    return { where, select: VIEW_SELECT, present: presenter(me) }
  }
  if (auth.status !== 403 || !(await conversationSharingInForce())) return auth
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const before = await projectAccess(eff, projectId)
  if (!before || !meetsLevel(before, 'R*')) return auth
  const read = await requirePermission(request, 'graph:read', { projectId })
  if (read instanceof NextResponse) return asOwn(read, auth)
  if (!read.access || requireLevel(read, 'R*')) return auth
  const others = await othersWhere(read.access, projectId)
  if (!others) return auth
  return { where: others, select: VIEW_SELECT, present: presenter(eff.userId) }
}

/**
 * The write routes' check (PATCH, appending messages): a conversation reassigned from a deleted account is
 * read and deleted, never continued (409 `conversation_read_only`). Null with the write switch off, nothing read.
 */
export async function readOnlyConversationRefusal(conversationId: string): Promise<NextResponse | null> {
  if (!conversationRetentionOn()) return null
  const row = await prisma.conversation.findUnique({ where: { id: conversationId }, select: { formerAuthorId: true } })
  if (!row?.formerAuthorId) return null
  return NextResponse.json(
    {
      error: 'This session belonged to an account that was deleted: it can be read and deleted, not continued.',
      code: 'conversation_read_only',
    },
    { status: 409 },
  )
}

/**
 * The user DELETE's reassignment (T24, DV-23), inside the transaction that deletes the account: each of the
 * account's conversations in a project it does not own goes to that project's owner, keeping the former
 * author's id and `label` (their name or email, as they are now). Answers how many moved, or null with the
 * write switch off (nothing read: the conversations go with the account, as before).
 */
export async function reassignConversationsOfDeletedAuthor(
  tx: Pick<Db, 'conversation'>,
  userId: string,
  label: string,
): Promise<number | null> {
  if (!conversationRetentionOn()) return null
  const rows = await tx.conversation.findMany({
    where: { userId, project: { userId: { not: userId } } },
    select: { id: true, project: { select: { userId: true } } },
  })
  const byOwner = new Map<string, string[]>()
  for (const row of rows) byOwner.set(row.project.userId, [...(byOwner.get(row.project.userId) ?? []), row.id])
  for (const [ownerId, ids] of byOwner) {
    await tx.conversation.updateMany({
      where: { id: { in: ids }, userId },
      data: { userId: ownerId, formerAuthorId: userId, formerAuthorLabel: label },
    })
  }
  return rows.length
}
