/**
 * Which projects a person sees, for the lists that show "my projects": the project list, the
 * reports, the running scans and their counts. The list form of projectAccess.ts: the projects the
 * person owns and, with sharing in force (step 4.3), those shared with them by a live share (not
 * expired on the clock, their account active), the same shares projectAccess() answers `read` for,
 * so a list never names a project its detail route answers 404 for. Oversight and break-glass open
 * a project by its id and fill no list (step 4.14 gives overseers their own filter).
 *
 * The person is the effective user (under act-as, the account acted as, whose shares then list).
 *
 * The MCP tools list projects at the owner level on purpose (`assertMcpProjectAccess` requires the
 * owner): their list stays on the owner, not on this filter.
 *
 * Step 4.5 adds what the lists show with shares: each project row's own access (`myShareSelect` +
 * `withMyAccess`, the project GET's `myAccess` read from the same query) and the scan activity
 * view's split of the job queue (`jobQueueScope`).
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'
import { sharingPolicyInForce } from './sharingPolicy'
import { SHARE_ACCESS, myAccessView, type MyAccess, type ProjectAccess, type ProjectAccessSubject } from './projectAccess'

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

/**
 * The `select` keys a project list adds so each row carries the person's own share of it (its Raw
 * data toggle), only when shares are listed. A project has at most one share per person, and the
 * list's filter already admitted only a live one.
 */
export function myShareSelect(subject: ProjectAccessSubject, visible: VisibleProjects): {
  collaborators?: { where: { userId: string }; select: { rawData: true } }
} {
  const userId = subjectId(subject)
  if (!visible.withShares || userId === null) return {}
  return { collaborators: { where: { userId }, select: { rawData: true } } }
}

/** A project row as a list reads it, with its owner and (myShareSelect) the person's share. */
export interface ListedProjectRow {
  id: string
  userId: string
  user?: { name?: string | null; email?: string | null } | null
  collaborators?: ReadonlyArray<{ rawData: boolean }>
}

/**
 * Each listed row with the person's own access (`myAccess`, the project GET's view: the owner, or a
 * share at `read` with its Raw data; a share at `write` reads as `read` until Phase 5), the share
 * itself removed. With RBAC_SHARING_ENABLED off the rows come back as they are, without the key,
 * as the project GET does (DV-30). A row neither owned nor shared with the person is left out.
 * The list shows the share: a break-glass row that would raise it (projectAccess) opens the
 * project by its id, as oversight does, and the detail's `myAccess` says so.
 */
export function withMyAccess<T extends ListedProjectRow>(
  subject: ProjectAccessSubject,
  rows: T[],
): Array<Omit<T, 'collaborators'> & { myAccess?: MyAccess }> {
  if (!rbacFlags().sharing) return rows
  const userId = subjectId(subject)
  const out: Array<Omit<T, 'collaborators'> & { myAccess: MyAccess }> = []
  for (const { collaborators, ...row } of rows) {
    const project = { id: row.id, userId: row.userId }
    let access: ProjectAccess | null = null
    if (userId !== null && row.userId === userId) {
      access = { project, level: 'owner', toggles: { rawData: true }, via: 'owner' }
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

/** The ids of the projects `subject` sees, oldest first. One read (and the policy); a failed read throws. */
export async function visibleProjectIds(subject: ProjectAccessSubject): Promise<string[]> {
  const rows = await prisma.project.findMany({
    where: await visibleProjectsWhere(subject),
    select: { id: true },
    orderBy: { createdAt: 'asc' },
  })
  return rows.map((r) => r.id)
}
