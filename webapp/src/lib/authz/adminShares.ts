/**
 * The admin console's shares overview (step 6.4; GV-05, GV-20, SH-18): every share between accounts,
 * with the project, its owner, the collaborator, the level, the toggles and the expiry, for a holder
 * of users:read while sharing is in force and Root's policy lets administrators see every share
 * (`adminsSeeAllShares`, §6.5; the route answers 404 / 403 otherwise, having read no share). Expired
 * shares not yet swept are listed and marked: they give nothing (expiry is lazy, step 4.15).
 *
 * Root's force-revoke (projects:administer, §6.3) removes one share whatever its level, a co-owner's
 * included (OQ-34 binds the project's people, not Root). The row and its audit row go in one
 * transaction (`project.share.revoke` with `after.forced`, in the project's activity feed); then the
 * collaborator's live work on the project stops as after an owner's revoke (`onAccessReduced`, step
 * 5.9), best effort: the revoke stands when the agent is down (`[rbac] socket-close failed`).
 */
import type { Prisma } from '@prisma/client'
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import type { Session } from '@/lib/session'
import { ADMINISTER_PERMISSION } from './adminProjects'
import { now } from './clock'
import { personAuditEntry } from './permissionAdmin'
import { onAccessReduced } from './revocation'
import { rootStanding } from './rootPowers'
import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, type FilterProblem } from './userDirectory'

const MAX_QUERY_LENGTH = 200
const MAX_ID_LENGTH = 200

/** Where the previous page ended (rows run newest first; a share's key is project and person). */
export interface ShareCursor {
  createdAt: Date
  projectId: string
  userId: string
}

export interface ShareFilters {
  /** Matches the project's name, the collaborator's and the owner's name or email. */
  q: string | null
  project: string | null
  /** Shares this account holds or gave (as the project's owner). */
  user: string | null
  cursor: ShareCursor | null
  limit: number
}

export interface ShareToggles {
  rawData: boolean
  runScans: boolean
  useAgent: boolean
  exploit: boolean
  manage: boolean
}

export interface AdminShareRow {
  project: { id: string; name: string }
  owner: { id: string; name: string; email: string }
  collaborator: { id: string; name: string; email: string; status: string }
  access: string
  toggles: ShareToggles
  expiresAt: string | null
  /** Past its expiry: it gives nothing until the sweep removes it. */
  expired: boolean
  createdAt: string
}

export interface SharesOverview {
  shares: AdminShareRow[]
  nextCursor: string | null
  total: number
  /** The confirmed Root's force-revoke. */
  actions: { revoke: boolean }
}

const problem = (field: string, error: string): FilterProblem => ({ error, code: 'invalid_filter', field })

export function encodeShareCursor(c: ShareCursor): string {
  return Buffer.from(`${c.createdAt.toISOString()}|${c.projectId}|${c.userId}`, 'utf8').toString('base64url')
}

export function decodeShareCursor(raw: string): ShareCursor | null {
  const parts = Buffer.from(raw, 'base64url').toString('utf8').split('|')
  if (parts.length !== 3 || parts.some((p) => p === '')) return null
  const createdAt = new Date(parts[0])
  if (Number.isNaN(createdAt.getTime())) return null
  return { createdAt, projectId: parts[1], userId: parts[2] }
}

/** The list's query string, or the first field that is not one it takes. */
export function parseSharesQuery(params: URLSearchParams): ShareFilters | FilterProblem {
  const text = (name: string) => {
    const v = params.get(name)?.trim()
    return v ? v : null
  }
  const q = text('q')
  if (q && q.length > MAX_QUERY_LENGTH) return problem('q', `q is longer than ${MAX_QUERY_LENGTH} characters`)
  const project = text('project')
  if (project && project.length > MAX_ID_LENGTH) return problem('project', 'project is not a project id')
  const user = text('user')
  if (user && user.length > MAX_ID_LENGTH) return problem('user', 'user is not an account id')
  const rawCursor = text('cursor')
  const cursor = rawCursor ? decodeShareCursor(rawCursor) : null
  if (rawCursor && !cursor) return problem('cursor', 'cursor is not one this list gave')
  const rawLimit = text('limit')
  const limit = rawLimit === null ? DEFAULT_PAGE_SIZE : Number(rawLimit)
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
    return problem('limit', `limit is a whole number from 1 to ${MAX_PAGE_SIZE}`)
  }
  return { q, project, user, cursor, limit }
}

/** The shares the filters select (the cursor is applied apart, so the total ignores it). */
export function sharesWhere(f: ShareFilters): Prisma.ProjectCollaboratorWhereInput {
  const and: Prisma.ProjectCollaboratorWhereInput[] = []
  if (f.q) {
    const like = { contains: f.q, mode: 'insensitive' as const }
    and.push({
      OR: [
        { project: { name: like } },
        { user: { name: like } },
        { user: { email: like } },
        { project: { user: { name: like } } },
        { project: { user: { email: like } } },
      ],
    })
  }
  if (f.project) and.push({ projectId: f.project })
  if (f.user) and.push({ OR: [{ userId: f.user }, { project: { userId: f.user } }] })
  return and.length > 0 ? { AND: and } : {}
}

function afterCursor(c: ShareCursor): Prisma.ProjectCollaboratorWhereInput {
  return {
    OR: [
      { createdAt: { lt: c.createdAt } },
      { createdAt: c.createdAt, projectId: { lt: c.projectId } },
      { createdAt: c.createdAt, projectId: c.projectId, userId: { lt: c.userId } },
    ],
  }
}

const ROW_SELECT = {
  projectId: true, userId: true, access: true, rawData: true, runScans: true, useAgent: true, exploit: true,
  manage: true, expiresAt: true, createdAt: true,
  user: { select: { id: true, name: true, email: true, status: true } },
  project: { select: { id: true, name: true, user: { select: { id: true, name: true, email: true } } } },
} satisfies Prisma.ProjectCollaboratorSelect

interface ShareRecord {
  projectId: string
  userId: string
  access: string
  rawData: boolean
  runScans: boolean
  useAgent: boolean
  exploit: boolean
  manage: boolean
  expiresAt: Date | null
  createdAt: Date
  user: { id: string; name: string; email: string; status: string | null }
  project: { id: string; name: string; user: { id: string; name: string; email: string } }
}

function toRow(r: ShareRecord, at: number): AdminShareRow {
  return {
    project: { id: r.project.id, name: r.project.name },
    owner: { id: r.project.user.id, name: r.project.user.name, email: r.project.user.email },
    collaborator: { id: r.user.id, name: r.user.name, email: r.user.email, status: r.user.status || 'active' },
    access: r.access,
    toggles: { rawData: r.rawData, runScans: r.runScans, useAgent: r.useAgent, exploit: r.exploit, manage: r.manage },
    expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
    expired: r.expiresAt !== null && r.expiresAt.getTime() <= at,
    createdAt: r.createdAt.toISOString(),
  }
}

/** One page of the shares overview (the route checked users:read, sharing in force and the policy). */
export async function readSharesPage(session: Session, f: ShareFilters): Promise<SharesOverview> {
  const where = sharesWhere(f)
  const [found, total, standing] = await Promise.all([
    prisma.projectCollaborator.findMany({
      where: f.cursor ? { AND: [where, afterCursor(f.cursor)] } : where,
      select: ROW_SELECT,
      orderBy: [{ createdAt: 'desc' }, { projectId: 'desc' }, { userId: 'desc' }],
      take: f.limit + 1,
    }) as unknown as Promise<ShareRecord[]>,
    prisma.projectCollaborator.count({ where }),
    rootStanding(session.userId),
  ])
  const page = found.slice(0, f.limit)
  const last = page[page.length - 1]
  const at = now().getTime()
  return {
    shares: page.map((r) => toRow(r, at)),
    nextCursor: found.length > f.limit && last
      ? encodeShareCursor({ createdAt: last.createdAt, projectId: last.projectId, userId: last.userId })
      : null,
    total,
    actions: { revoke: standing === 'confirmed' },
  }
}

/** The share as the audit rows record it, as the owner's revoke does (the note stays out). */
function auditView(row: { access: string; rawData: boolean; runScans: boolean; useAgent: boolean; exploit: boolean; manage: boolean; expiresAt: Date | null; grantedById: string }) {
  return {
    access: row.access, rawData: row.rawData, runScans: row.runScans, useAgent: row.useAgent, exploit: row.exploit,
    manage: row.manage, expiresAt: row.expiresAt ? row.expiresAt.toISOString() : null, grantedById: row.grantedById,
  }
}

/**
 * Root's force-revoke (the route asked for the confirmed Root and its password, with sharing in
 * force): 404 `no_such_share` when there is none (or another revoke took it first: of two at once
 * only one removes it and writes the row).
 */
export async function forceRevokeShare(request: NextRequest, session: Session, projectId: string, userId: string): Promise<NextResponse> {
  const entry = await personAuditEntry(request, session, {
    projectId, permission: ADMINISTER_PERMISSION, action: 'project.share.revoke', targetType: 'user', targetId: userId,
  })
  const removed = await auditedTransaction(prisma, async (tx) => {
    const row = await tx.projectCollaborator.findUnique({
      where: { projectId_userId: { projectId, userId } },
      select: {
        access: true, rawData: true, runScans: true, useAgent: true, exploit: true, manage: true, expiresAt: true, grantedById: true,
      },
    })
    if (!row) return false
    const { count } = await tx.projectCollaborator.deleteMany({ where: { projectId, userId } })
    if (count !== 1) return false
    await writeAuditTx(tx, { ...entry, before: auditView(row), after: { forced: true } })
    return true
  })
  if (!removed) return NextResponse.json({ error: 'This person holds no share of the project.', code: 'no_such_share' }, { status: 404 })
  const stopped = await onAccessReduced(projectId, userId, 'share_force_revoked')
  return NextResponse.json({ revoked: { projectId, userId }, forced: true, socketsClosed: !('error' in stopped.sockets) })
}
