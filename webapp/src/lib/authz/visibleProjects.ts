/**
 * Which projects a person sees, for the lists that show "my projects": the project list, the
 * reports, the running scans and their counts. The list form of projectAccess.ts: a project is in
 * these lists exactly when `projectAccess()` would answer for it, so a list never names a project
 * its detail route answers 404 for, and the two change together.
 *
 * Owner-only, as projectAccess() is: the projects the person owns. The person is the effective
 * user (under act-as, the account acted as).
 *
 * The MCP tools list projects at the owner level on purpose (`assertMcpProjectAccess` requires the
 * owner): their list stays on the owner, not on this filter.
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import type { ProjectAccessSubject } from './projectAccess'

/**
 * The Prisma filter of the projects `subject` sees, for a `project` query or a relation filter
 * (`{project: visibleProjectsWhere(eff)}`). A subject without an id sees nothing: Prisma drops an
 * undefined filter, so `{userId: undefined}` would list every account's projects.
 */
export function visibleProjectsWhere(subject: ProjectAccessSubject): Prisma.ProjectWhereInput {
  const userId: unknown = subject.userId
  if (typeof userId !== 'string' || userId === '') return { id: { in: [] } }
  return { userId }
}

/** The ids of the projects `subject` sees, oldest first. One read; a failed read throws. */
export async function visibleProjectIds(subject: ProjectAccessSubject): Promise<string[]> {
  const rows = await prisma.project.findMany({
    where: visibleProjectsWhere(subject),
    select: { id: true },
    orderBy: { createdAt: 'asc' },
  })
  return rows.map((r) => r.id)
}
