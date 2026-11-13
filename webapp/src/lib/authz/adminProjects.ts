/**
 * The admin console's projects overview (step 6.4; GV-04, SH-18): every project on the instance with
 * its owner, its live shares and its last activity, searched and paged, for a holder of
 * projects:oversee; and Root's forced delete of a project somebody else owns (projects:administer).
 *
 * Listing reads no project content and writes no audit row: opening a project read-only is the
 * oversight read itself (projectAccess's oversight branch, audited once a day by step 4.14), and
 * Root's break-glass is step 4.14's route; both exist only while sharing is in force and never while
 * acting as someone (D-22), so the page offers them only then. Share counts read collaborator rows
 * only with sharing in force.
 *
 * The forced delete runs the owner's own teardown (lib/projectTeardown.ts) with the owner as the
 * tenant, never Root. The teardown is not one transaction, so its audit row is written once the
 * outcome is known, as the account delete writes `user.delete` (users/[id]/route.ts): `project.delete`
 * with `after.forced`, or `project.delete_failed` naming the step that stopped it.
 */
import type { Prisma } from '@prisma/client'
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { teardownProject } from '@/lib/projectTeardown'
import { projectTargetLabel } from '@/lib/projectSummary'
import type { Session } from '@/lib/session'
import { actingAsUserId } from '@/lib/userAudit'
import { now } from './clock'
import { personAuditEntry } from './permissionAdmin'
import { rootStanding } from './rootPowers'
import { sharingPolicyInForce } from './sharingPolicy'
import {
  DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, decodeCursor, encodeCursor, type DirectoryCursor, type FilterProblem,
} from './userDirectory'

export const ADMINISTER_PERMISSION = 'projects:administer'
const MAX_QUERY_LENGTH = 200
const MAX_ID_LENGTH = 200

export interface ProjectFilters {
  /** Matches the project's name and its owner's name or email. */
  q: string | null
  /** Only this account's projects. */
  owner: string | null
  cursor: DirectoryCursor | null
  limit: number
}

export interface AdminProjectRow {
  id: string
  name: string
  targetLabel: string
  owner: { id: string; name: string; email: string; status: string }
  /** Live shares; null while sharing is not in force (no collaborator row is read). */
  collaborators: number | null
  createdAt: string
  /** The later of the last settings change and the project's latest audit row (its activity feed). */
  lastActivityAt: string
}

/** What the signed-in person may do from the list, decided once for the page. */
export interface AdminProjectActions {
  /** Open the project read-only by oversight: sharing in force and not acting as someone. */
  openReadOnly: boolean
  /**
   * The confirmed Root's break-glass (step 4.14's POST /api/projects/[id]/breakglass): sharing in
   * force and not acting as someone; never on Root's own project (the route refuses it).
   */
  breakGlass: boolean
  /** The confirmed Root's forced delete. */
  delete: boolean
  /** The confirmed Root's force-revoke, offered where the shares can be listed. */
  revokeShares: boolean
}

export interface ProjectsOverview {
  projects: AdminProjectRow[]
  nextCursor: string | null
  /** Projects the filters select, the cursor ignored. */
  total: number
  sharing: { inForce: boolean; allShares: boolean }
  actions: AdminProjectActions
}

const problem = (field: string, error: string): FilterProblem => ({ error, code: 'invalid_filter', field })

/** The list's query string, or the first field that is not one it takes. */
export function parseProjectsQuery(params: URLSearchParams): ProjectFilters | FilterProblem {
  const text = (name: string) => {
    const v = params.get(name)?.trim()
    return v ? v : null
  }
  const q = text('q')
  if (q && q.length > MAX_QUERY_LENGTH) return problem('q', `q is longer than ${MAX_QUERY_LENGTH} characters`)
  const owner = text('owner')
  if (owner && owner.length > MAX_ID_LENGTH) return problem('owner', 'owner is not an account id')
  const rawCursor = text('cursor')
  const cursor = rawCursor ? decodeCursor(rawCursor) : null
  if (rawCursor && !cursor) return problem('cursor', 'cursor is not one this list gave')
  const rawLimit = text('limit')
  const limit = rawLimit === null ? DEFAULT_PAGE_SIZE : Number(rawLimit)
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
    return problem('limit', `limit is a whole number from 1 to ${MAX_PAGE_SIZE}`)
  }
  return { q, owner, cursor, limit }
}

/** The projects the filters select (the cursor is applied apart, so the total ignores it). */
export function projectsWhere(f: ProjectFilters): Prisma.ProjectWhereInput {
  const and: Prisma.ProjectWhereInput[] = []
  if (f.q) {
    and.push({
      OR: [
        { name: { contains: f.q, mode: 'insensitive' } },
        { user: { name: { contains: f.q, mode: 'insensitive' } } },
        { user: { email: { contains: f.q, mode: 'insensitive' } } },
      ],
    })
  }
  if (f.owner) and.push({ userId: f.owner })
  return and.length > 0 ? { AND: and } : {}
}

function afterCursor(c: DirectoryCursor): Prisma.ProjectWhereInput {
  return { OR: [{ createdAt: { lt: c.createdAt } }, { createdAt: c.createdAt, id: { lt: c.id } }] }
}

const liveShare = (): Prisma.ProjectCollaboratorWhereInput => ({ OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] })

const SCOPE_FIELDS = {
  targetDomain: true, ipMode: true, targetIps: true, subdomainList: true, domainBatchMode: true, domainBatchHosts: true,
} as const

function rowSelect(sharing: boolean) {
  return {
    id: true, name: true, createdAt: true, updatedAt: true, ...SCOPE_FIELDS,
    user: { select: { id: true, name: true, email: true, status: true } },
    ...(sharing ? { _count: { select: { collaborators: { where: liveShare() } } } } : {}),
  } satisfies Prisma.ProjectSelect
}

type ProjectRow = Record<string, unknown> & {
  id: string
  name: string
  createdAt: Date
  updatedAt: Date
  user: { id: string; name: string; email: string; status: string | null }
  _count?: { collaborators?: number }
}

/** The latest audit row of each project, by id (the `(projectId, createdAt)` index answers it). */
async function latestActivity(ids: readonly string[]): Promise<Map<string, Date>> {
  if (ids.length === 0) return new Map()
  const rows = await prisma.auditLog.groupBy({
    by: ['projectId'],
    where: { projectId: { in: [...ids] } },
    _max: { createdAt: true },
  })
  const out = new Map<string, Date>()
  for (const r of rows) if (r.projectId && r._max.createdAt) out.set(r.projectId, r._max.createdAt)
  return out
}

function toRow(p: ProjectRow, sharing: boolean, activity: Map<string, Date>): AdminProjectRow {
  const audited = activity.get(p.id)
  const last = audited && audited > p.updatedAt ? audited : p.updatedAt
  return {
    id: p.id,
    name: p.name,
    targetLabel: projectTargetLabel(p as Parameters<typeof projectTargetLabel>[0]),
    owner: { id: p.user.id, name: p.user.name, email: p.user.email, status: p.user.status || 'active' },
    collaborators: sharing ? p._count?.collaborators ?? 0 : null,
    createdAt: p.createdAt.toISOString(),
    lastActivityAt: last.toISOString(),
  }
}

/** One page of the projects overview for the signed-in person (who holds projects:oversee: the route asked). */
export async function readProjectsPage(request: NextRequest, session: Session, f: ProjectFilters): Promise<ProjectsOverview> {
  const [policy, actingAs, standing] = await Promise.all([
    sharingPolicyInForce(), actingAsUserId(request, session), rootStanding(session.userId),
  ])
  const inForce = policy?.enabled === true
  const allShares = inForce && policy?.adminsSeeAllShares === true
  const where = projectsWhere(f)
  const [found, total] = await Promise.all([
    prisma.project.findMany({
      where: f.cursor ? { AND: [where, afterCursor(f.cursor)] } : where,
      select: rowSelect(inForce),
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: f.limit + 1,
    }) as unknown as Promise<ProjectRow[]>,
    prisma.project.count({ where }),
  ])
  const page = found.slice(0, f.limit)
  const activity = await latestActivity(page.map((p) => p.id))
  const last = page[page.length - 1]
  const root = standing === 'confirmed'
  return {
    projects: page.map((p) => toRow(p, inForce, activity)),
    nextCursor: found.length > f.limit && last ? encodeCursor({ createdAt: last.createdAt, id: last.id }) : null,
    total,
    sharing: { inForce, allShares },
    actions: {
      openReadOnly: inForce && !actingAs,
      breakGlass: root && inForce && !actingAs,
      delete: root,
      revokeShares: root && allShares,
    },
  }
}

/**
 * Root's forced delete (the route asked for the confirmed Root and its password): the teardown the
 * owner's own delete runs, with the owner as the tenant. 404 `project_not_found` for a project that
 * is not there (or went meanwhile); a teardown stopped before the row went answers as the project
 * DELETE does, after a `project.delete_failed` row.
 */
export async function forceDeleteProject(request: NextRequest, session: Session, projectId: string): Promise<NextResponse> {
  const project = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true, userId: true, name: true } })
  if (!project) return NextResponse.json({ error: 'Project not found', code: 'project_not_found' }, { status: 404 })
  const result = await teardownProject(
    { id: project.id, userId: project.userId },
    { actorUserId: session.userId, archiveReason: 'project_deleted_by_root' },
  )
  const entry = {
    projectId: project.id,
    permission: ADMINISTER_PERMISSION,
    targetType: 'project',
    targetId: project.id,
    before: { name: project.name, ownerId: project.userId },
  }
  if (!result.ok) {
    if (result.code === 'project_not_found') {
      return NextResponse.json({ error: 'Project not found', code: 'project_not_found' }, { status: 404 })
    }
    console.error(`[rbac] forced project delete failed project=${project.id} step=${result.failedStep} code=${result.code}`)
    await writeAudit(await personAuditEntry(request, session, {
      ...entry, action: 'project.delete_failed', after: { forced: true, failedStep: result.failedStep, code: result.code },
    }))
    if (result.failedStep === 'archive_authorizations') {
      return NextResponse.json({
        error: "Could not archive this project's engagement authorization records, so it was not deleted. "
          + 'The record of what authorized an engagement must outlive the engagement. Retry.',
        code: result.code,
      }, { status: 500 })
    }
    throw result.error
  }
  await writeAudit(await personAuditEntry(request, session, { ...entry, action: 'project.delete', after: { forced: true } }))
  return NextResponse.json({ deleted: { projectId: project.id, ownerId: project.userId } })
}
