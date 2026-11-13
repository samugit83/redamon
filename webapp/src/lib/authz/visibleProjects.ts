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
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'
import { sharingPolicyInForce } from './sharingPolicy'
import { SHARE_ACCESS, type ProjectAccessSubject } from './projectAccess'

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

/**
 * The Prisma filter of the projects `subject` sees, for a `project` query or a relation filter
 * (`{project: await visibleProjectsWhere(eff)}`). With sharing not in force it is the owned filter
 * and reads nothing; in force it reads the policy (cached). A failed read throws.
 */
export async function visibleProjectsWhere(subject: ProjectAccessSubject): Promise<Prisma.ProjectWhereInput> {
  const userId = subjectId(subject)
  if (userId === null) return { id: { in: [] } }
  if (!rbacFlags().sharing) return { userId }
  const policy = await sharingPolicyInForce()
  if (policy?.enabled !== true) return { userId }
  return {
    OR: [
      { userId },
      {
        collaborators: {
          some: { userId, access: { in: [...SHARE_ACCESS] }, user: { status: 'active' }, OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] },
        },
      },
    ],
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
