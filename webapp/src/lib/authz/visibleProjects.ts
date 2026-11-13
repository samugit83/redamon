/**
 * Which projects a person sees, for the lists that show "my projects": the project list, the
 * reports, the running scans and their counts. The list form of projectAccess.ts: the projects the
 * person owns and, with sharing in force (step 4.3), those shared with them by a live share (not
 * expired on the clock, their account active), the same shares projectAccess() answers for, so a
 * list never names a project its detail route answers 404 for. Oversight and break-glass open a
 * project by its id and fill no list (step 4.14 gives overseers their own filter).
 *
 * The person is the effective user (under act-as, the account acted as, whose shares then list).
 * MCP's list_projects uses it too, narrowed to a token's opt-in and allowlist (step 4.10).
 *
 * Step 4.5 adds what the lists show with shares: each project row's own access (`myShareSelect` +
 * `withMyAccess`, the project GET's `myAccess` read from the same query) and the scan activity
 * view's split of the job queue (`jobQueueScope`). Step 5.2 lists a Read + Write share as `write`
 * with its toggles when projectAccess() would answer `write` (write sharing in force, not acting).
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'
import { maxShareLevel, sharingPolicyInForce } from './sharingPolicy'
import { ConsentStoreMissing, holdsSpendToggle, readOwnerConsents } from './ownerConsent'
import {
  SHARE_ACCESS, effectiveToggles, myAccessView, type MyAccess, type ProjectAccess, type ProjectAccessSubject, type WriteToggles,
} from './projectAccess'

// A subject without an id matches no project: Prisma drops an undefined filter, so
// `{userId: undefined}` would list every account's projects.
function subjectId(subject: ProjectAccessSubject): string | null {
  const userId: unknown = subject.userId
  return typeof userId === 'string' && userId !== '' ? userId : null
}

/**
 * The projects `subject` owns, whatever is shared: for a view of what the person's own keys pay for
 * (a shared project's runs spend its owner's, T9). A subject without an id owns nothing.
 */
export function ownedProjectsWhere(subject: ProjectAccessSubject): Prisma.ProjectWhereInput {
  const userId = subjectId(subject)
  return userId === null ? { id: { in: [] } } : { userId }
}

/** The projects a person sees, and whether shares widened them beyond the owned ones. */
export interface VisibleProjects {
  where: Prisma.ProjectWhereInput
  /** Sharing in force: `where` also admits the projects shared with the person by a live share. */
  withShares: boolean
  /**
   * Write sharing in force too (RBAC_SHARING_WRITE_ENABLED and Root's `maxLevel: 'write'`,
   * `maxShareLevel`): a share stored at `write` lists as `write`, unless the caller acts as the
   * person (`withMyAccess`'s `actingAs`, D-22). Absent otherwise, so Phase 4's answer is unchanged.
   */
  writeShares?: true
}

/**
 * visibleProjectsWhere's filter with whether it admits shares, for a list that shows more than the
 * rows with sharing in force (each row's access, the jobs of a shared project). Reads as
 * visibleProjectsWhere does.
 */
export async function visibleProjects(subject: ProjectAccessSubject): Promise<VisibleProjects> {
  const userId = subjectId(subject)
  if (userId === null) return { where: { id: { in: [] } }, withShares: false }
  if (!rbacFlags().sharing) return { where: { userId }, withShares: false }
  const policy = await sharingPolicyInForce()
  if (policy?.enabled !== true) return { where: { userId }, withShares: false }
  return {
    where: {
      OR: [
        { userId },
        {
          collaborators: {
            some: { userId, access: { in: [...SHARE_ACCESS] }, user: { status: 'active' }, OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] },
          },
        },
      ],
    },
    withShares: true,
    ...(maxShareLevel(policy) === 'write' ? { writeShares: true as const } : {}),
  }
}

/**
 * The Prisma filter of the projects `subject` sees, for a `project` query or a relation filter
 * (`{project: await visibleProjectsWhere(eff)}`). With sharing not in force it is the owned filter
 * and reads nothing; in force it reads the policy (cached). A failed read throws.
 */
export async function visibleProjectsWhere(subject: ProjectAccessSubject): Promise<Prisma.ProjectWhereInput> {
  return (await visibleProjects(subject)).where
}

/** Phase 4's share columns; the level and the write toggles only when a share can list as `write`. */
const READ_SHARE_SELECT = { rawData: true } as const
const WRITE_SHARE_SELECT = { rawData: true, access: true, runScans: true, useAgent: true, exploit: true, manage: true } as const

/**
 * The `select` keys a project list adds so each row carries the person's own share of it (its Raw
 * data toggle, and with write sharing in force its level and toggles), only when shares are listed.
 * A project has at most one share per person, and the list's filter already admitted only a live one.
 */
export function myShareSelect(subject: ProjectAccessSubject, visible: VisibleProjects): {
  collaborators?: { where: { userId: string }; select: typeof READ_SHARE_SELECT | typeof WRITE_SHARE_SELECT }
} {
  const userId = subjectId(subject)
  if (!visible.withShares || userId === null) return {}
  return { collaborators: { where: { userId }, select: visible.writeShares === true ? WRITE_SHARE_SELECT : READ_SHARE_SELECT } }
}

/** The person's share as a list reads it: the level and toggles only with write sharing in force. */
export type ListedShare = { rawData: boolean; access?: string } & Partial<Record<keyof WriteToggles, boolean>>

/** A project row as a list reads it, with its owner and (myShareSelect) the person's share. */
export interface ListedProjectRow {
  id: string
  userId: string
  user?: { name?: string | null; email?: string | null } | null
  collaborators?: ReadonlyArray<ListedShare>
}

export interface WithMyAccessOptions {
  /** The person is the account an admin acts as: a share lists as read, never more (D-22). */
  actingAs?: boolean
}

/** The person's share of a row when it lists as `write`: its level read (write sharing in force), not under act-as. */
function listedWriteShare(userId: string | null, row: ListedProjectRow, opts: WithMyAccessOptions): ListedShare | null {
  if (userId === null || row.userId === userId || opts.actingAs === true) return null
  const share = row.collaborators?.[0]
  return share?.access === 'write' ? share : null
}

/**
 * The listed projects whose owner consents to collaborators spending its credentials, read once for
 * the list and only for a write share holding a run toggle, as projectAccess() reads it for one. A
 * table this database lacks yet lists the toggles off (the list is a view; every gate asks again).
 */
async function listedConsents(userId: string | null, rows: ReadonlyArray<ListedProjectRow>, opts: WithMyAccessOptions): Promise<ReadonlySet<string>> {
  const ids = rows.filter(row => {
    const share = listedWriteShare(userId, row, opts)
    return share !== null && holdsSpendToggle(share)
  }).map(row => row.id)
  if (ids.length === 0) return new Set()
  try {
    return await readOwnerConsents(ids)
  } catch (err) {
    if (err instanceof ConsentStoreMissing) return new Set()
    throw err
  }
}

/**
 * Each listed row with the person's own access (`myAccess`, the project GET's view: the owner, or a
 * share at `read` with its Raw data; a share at `write` lists as `write` with its toggles, through
 * `effectiveToggles` with the owner's consent as projectAccess() answers them, only when myShareSelect
 * read its level, i.e. with write sharing in force, and not under act-as), the share itself removed.
 * The consent is one read for the whole list (`readOwnerConsents`). With RBAC_SHARING_ENABLED off the
 * rows come back as they are, without the key, as the project GET does (DV-30). A row neither owned
 * nor shared with the person is left out. The list shows the share: a break-glass row that would raise
 * it (projectAccess) opens the project by its id, as oversight does, and the detail's `myAccess` says so.
 */
export async function withMyAccess<T extends ListedProjectRow>(
  subject: ProjectAccessSubject,
  rows: T[],
  opts: WithMyAccessOptions = {},
): Promise<Array<Omit<T, 'collaborators'> & { myAccess?: MyAccess }>> {
  if (!rbacFlags().sharing) return rows
  const userId = subjectId(subject)
  const consented = await listedConsents(userId, rows, opts)
  const out: Array<Omit<T, 'collaborators'> & { myAccess: MyAccess }> = []
  for (const listed of rows) {
    const { collaborators, ...row } = listed
    const project = { id: row.id, userId: row.userId }
    const writeShare = listedWriteShare(userId, listed, opts)
    let access: ProjectAccess | null = null
    if (userId !== null && row.userId === userId) {
      access = { project, level: 'owner', toggles: { rawData: true }, via: 'owner' }
    } else if (writeShare) {
      access = { project, level: 'write', toggles: { rawData: true, ...effectiveToggles(writeShare, consented.has(row.id)) }, via: 'share' }
    } else if (userId !== null && collaborators && collaborators.length > 0) {
      access = { project, level: 'read', toggles: { rawData: collaborators[0].rawData === true }, via: 'share' }
    }
    if (access) out.push({ ...row, myAccess: myAccessView(access, row.user) })
  }
  return out
}

/** The job-queue rows a person sees in full, and the rest, which the activity view only counts. */
export interface JobQueueScope {
  mine: Prisma.JobQueueWhereInput
  others: Prisma.JobQueueWhereInput
}

/**
 * The scan activity view's split of the job queue: the jobs the person queued (JobQueue.userId is
 * who queued a job) and, with shares listed, every job of a project they see, so a shared project's
 * queue shows beside its running scans and the owner sees every job of their projects; the others
 * are the exact complement, so no job is shown and counted. Without shares: the person's own rows
 * and everyone else's, as before.
 */
export function jobQueueScope(subject: ProjectAccessSubject, visible: VisibleProjects): JobQueueScope {
  const userId = subjectId(subject)
  if (userId === null) return { mine: { id: { in: [] } }, others: {} }
  if (!visible.withShares) return { mine: { userId }, others: { userId: { not: userId } } }
  return {
    mine: { OR: [{ userId }, { project: visible.where }] },
    others: { userId: { not: userId }, project: { NOT: visible.where } },
  }
}

/**
 * Of the project rows a read with `visible` listed (their `userId` selected), the ids `subject` does
 * not own: the projects shared with them, which the scan activity view counts apart from their own
 * (step 4.11). Empty without shares listed; a row without its owner is never called shared.
 */
export function sharedProjectIds(
  subject: ProjectAccessSubject,
  visible: VisibleProjects,
  rows: ReadonlyArray<{ id: string; userId?: string | null }>,
): string[] {
  const userId = subjectId(subject)
  if (!visible.withShares || userId === null) return []
  return rows.filter((row) => typeof row.userId === 'string' && row.userId !== userId).map((row) => row.id)
}

/** The ids of the projects `subject` sees, oldest first. One read (and the policy); a failed read throws. */
export async function visibleProjectIds(subject: ProjectAccessSubject): Promise<string[]> {
  const rows = await prisma.project.findMany({
    where: await visibleProjectsWhere(subject),
    select: { id: true },
    orderBy: { createdAt: 'asc' },
  })
  return rows.map((r) => r.id)
}
