/**
 * Deleting an account that owns shared projects (step 5.13; SH-16, SH-17; feature document §6.3). With
 * write sharing switched on (RBAC_SHARING_WRITE_ENABLED):
 * - the deletion plan (GET /api/users/[id]/deletion-plan) shows what the deletion does: the account's
 *   projects split into shared (a share that has not expired) and unshared, with what runs on each; the
 *   shares it holds in other people's projects, which end with it (cascade); its conversations there,
 *   reassigned to each project's owner (step 5.8); its agent runs, queued scans and schedules, which the
 *   revocation path stops, cancels and pauses; its MCP tokens and device sessions, gone with it; its own
 *   Nuclei templates, which go to the admin deleting it (DV-33);
 * - each shared project is resolved before the deletion: given to a collaborator (an offer they accept,
 *   or a transfer forced by projects:administer, through ownershipTransfer.ts), or named in the DELETE's
 *   `deleteAnyway`, which tears it down with the unshared ones. A DELETE that leaves one unresolved
 *   answers 409 `deletion_plan_unresolved` before anything is torn down, so a direct call cannot skip
 *   the plan.
 * With the switch off the plan route answers 404 and the user DELETE keeps its Phase 1 teardown (DV-30).
 *
 * Whatever that switch says, once the account row is gone the revocation path (step 5.9,
 * `account_deleted`) stops what the person still ran on other people's projects, with sharing in force
 * only: without it nobody reaches another person's project, and the teardown stopped the work on the
 * account's own.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { safeErrorCode } from '@/lib/routeErrors'
import type { Session } from '@/lib/session'
import { sessionHolds } from './adminPermission'
import { now } from './clock'
import { rbacFlags } from './flags'
import { openOffersOf, writeSharingInForce, type TransferView } from './ownershipTransfer'
import { agentRunCount } from './quotas'
import { onAccessReduced, type LiveWorkStopped } from './revocation'
import { rootStanding } from './rootPowers'

/** The deletion plan and the DELETE's check of it exist only with the write switch on. */
export function deletionWizardOff(): boolean {
  return !rbacFlags().sharingWrite
}

const liveShare = () => ({ OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] })
const NOT_STARTED = ['queued', 'needs_review']

export interface DeletionPerson {
  id: string
  name: string | null
  email: string | null
}

export interface PlannedProject {
  id: string
  name: string
  /** What runs on it now, in words, or null: the teardown stops it. */
  running: string | null
}

export interface PlannedCollaborator extends DeletionPerson {
  access: string
  /** Only an active account can receive the project. */
  active: boolean
  expiresAt: string | null
}

export interface SharedProjectPlan extends PlannedProject {
  collaborators: PlannedCollaborator[]
  /** The project's open ownership offer, whoever made it; the deletion waits for its answer. */
  offer: TransferView | null
}

export interface PlannedMembership {
  project: { id: string; name: string }
  owner: DeletionPerson
  access: string
  expiresAt: string | null
}

export interface DeletionPlan {
  account: DeletionPerson & { role: string; status: string }
  transfers: {
    /** Root's sharing policy lets a project change owner (write sharing in force). */
    available: boolean
    /** The viewer may force a transfer: projects:administer, held by the confirmed Root. */
    mayForce: boolean
  }
  sharedProjects: SharedProjectPlan[]
  unsharedProjects: PlannedProject[]
  memberships: PlannedMembership[]
  /** Its conversations in other people's projects, reassigned to each project's owner (step 5.8). */
  conversationsReassigned: number
  liveWork: {
    /** The agent's count of the account's runs in progress; null when the agent could not say. */
    agentRuns: number | null
    queuedScans: number
    schedules: number
  }
  endsWithAccount: { mcpTokens: number; deviceSessions: number; nucleiTemplates: number }
}

/** The account's own projects that hold a share that has not expired, oldest first. */
export async function sharedProjectsOf(userId: string): Promise<Array<{ id: string; name: string }>> {
  return prisma.project.findMany({
    where: { userId, collaborators: { some: liveShare() } },
    select: { id: true, name: true },
    orderBy: { createdAt: 'asc' },
  })
}

/** The project ids a DELETE body names in `deleteAnyway`; anything but a list of strings names none. */
export function deleteAnywayOf(body: unknown): string[] {
  const value = body && typeof body === 'object' ? (body as { deleteAnyway?: unknown }).deleteAnyway : undefined
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

/**
 * The DELETE's check (write switch on): every shared project of the account either named in
 * `deleteAnyway` or none left. `deletedAnyway` lists the shared projects the deletion will tear down.
 */
export async function resolveSharedProjects(
  userId: string,
  body: unknown,
): Promise<{ deletedAnyway: string[] } | { unresolved: Array<{ id: string; name: string }> }> {
  const named = new Set(deleteAnywayOf(body))
  const shared = await sharedProjectsOf(userId)
  const unresolved = shared.filter((p) => !named.has(p.id))
  if (unresolved.length > 0) return { unresolved }
  return { deletedAnyway: shared.map((p) => p.id) }
}

/** 409 naming each unresolved shared project and the plan that resolves them. */
export function unresolvedResponse(userId: string, unresolved: Array<{ id: string; name: string }>): NextResponse {
  return NextResponse.json({
    error: 'This user owns projects shared with other people. Resolve each one in the deletion plan first: '
      + 'transfer it to a collaborator, or name it to be deleted anyway.',
    code: 'deletion_plan_unresolved',
    projects: unresolved.map(({ id, name }) => ({ id, name })),
    plan: `/api/users/${encodeURIComponent(userId)}/deletion-plan`,
  }, { status: 409 })
}

/**
 * After the account row is deleted: what the person still ran on other people's projects stops
 * (agent runs, sockets, queued scans, schedules, a triage run). Never throws; each failed step is logged
 * by the revocation path. Null with sharing off (nothing to reach, nothing asked).
 */
export async function endDeletedAccountWork(userId: string): Promise<LiveWorkStopped | null> {
  if (!rbacFlags().sharing) return null
  return onAccessReduced(null, userId, 'account_deleted')
}

/** Whether `projectId` is one of the account's own projects: the plan acts on no other. */
export async function isProjectOf(userId: string, projectId: string): Promise<boolean> {
  return (await prisma.project.count({ where: { id: projectId, userId } })) === 1
}

/** The deletion plan's own account is never the signed-in one: nobody deletes their own account. */
export function isOwnAccount(session: Pick<Session, 'userId'>, userId: string): boolean {
  return session.userId === userId
}

/** A forced transfer is projects:administer's, a power of the confirmed Root (rootOnly). */
export async function mayForceTransfers(session: Session): Promise<boolean> {
  if ((await rootStanding(session.userId)) !== 'confirmed') return false
  return sessionHolds(session, 'projects:administer', { fresh: true })
}

async function running(projectId: string): Promise<string | null> {
  try {
    return await describeLiveGraphWriters(projectId)
  } catch (err) {
    console.error(`[rbac] deletion-plan running_check_failed project=${projectId} code=${safeErrorCode(err)}`)
    return 'what runs could not be verified'
  }
}

async function agentRuns(userId: string): Promise<number | null> {
  try {
    return await agentRunCount(userId)
  } catch {
    return null
  }
}

const iso = (d: unknown) => (d instanceof Date ? d.toISOString() : null)

/** The deletion plan of `userId`, or null when there is no such account. */
export async function deletionPlan(userId: string, viewer: Session): Promise<DeletionPlan | null> {
  const account = await prisma.user.findUnique({
    where: { id: userId }, select: { id: true, name: true, email: true, role: true, status: true },
  })
  if (!account) return null
  const owned = await prisma.project.findMany({
    where: { userId }, select: { id: true, name: true }, orderBy: { createdAt: 'asc' },
  })
  const ownedIds = owned.map((p) => p.id)
  const shares = ownedIds.length
    ? await prisma.projectCollaborator.findMany({
      where: { projectId: { in: ownedIds }, ...liveShare() },
      select: { projectId: true, userId: true, access: true, expiresAt: true, user: { select: { name: true, email: true, status: true } } },
      orderBy: { createdAt: 'asc' },
    })
    : []
  const sharedIds = [...new Set(shares.map((s) => s.projectId))]
  const [offers, runningByProject, memberships, conversationsReassigned, queuedScans, schedules, mcpTokens, deviceSessions,
    nucleiTemplates, runs, available, mayForce] = await Promise.all([
    openOffersOf(sharedIds),
    Promise.all(owned.map(async (p) => [p.id, await running(p.id)] as const)).then((pairs) => new Map(pairs)),
    prisma.projectCollaborator.findMany({
      where: { userId, ...liveShare() },
      select: { projectId: true, access: true, expiresAt: true, project: { select: { name: true, userId: true, user: { select: { name: true, email: true } } } } },
      orderBy: { createdAt: 'asc' },
    }),
    prisma.conversation.count({ where: { userId, project: { userId: { not: userId } } } }),
    prisma.jobQueue.count({ where: { userId, status: { in: NOT_STARTED } } }),
    prisma.scanSchedule.count({ where: { userId, enabled: true } }),
    prisma.mcpAccessToken.count({ where: { userId, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] } }),
    prisma.userSession.count({ where: { userId, revokedAt: null, expiresAt: { gt: now() } } }),
    prisma.nucleiTemplate.count({ where: { ownerUserId: userId } }),
    agentRuns(userId),
    writeSharingInForce({ fresh: true }),
    mayForceTransfers(viewer),
  ])

  const collaboratorsOf = (projectId: string): PlannedCollaborator[] => shares
    .filter((s) => s.projectId === projectId)
    .map((s) => ({
      id: s.userId, name: s.user?.name ?? null, email: s.user?.email ?? null, access: s.access,
      active: s.user?.status === 'active', expiresAt: iso(s.expiresAt),
    }))
  const shared = new Set(sharedIds)
  return {
    account: { id: account.id, name: account.name ?? null, email: account.email ?? null, role: account.role, status: account.status },
    transfers: { available, mayForce },
    sharedProjects: owned.filter((p) => shared.has(p.id)).map((p) => ({
      id: p.id, name: p.name, running: runningByProject.get(p.id) ?? null,
      collaborators: collaboratorsOf(p.id), offer: offers.get(p.id) ?? null,
    })),
    unsharedProjects: owned.filter((p) => !shared.has(p.id)).map((p) => ({ id: p.id, name: p.name, running: runningByProject.get(p.id) ?? null })),
    memberships: memberships.map((m) => ({
      project: { id: m.projectId, name: m.project?.name ?? '' },
      owner: { id: m.project?.userId ?? '', name: m.project?.user?.name ?? null, email: m.project?.user?.email ?? null },
      access: m.access,
      expiresAt: iso(m.expiresAt),
    })),
    conversationsReassigned,
    liveWork: { agentRuns: runs, queuedScans, schedules },
    endsWithAccount: { mcpTokens, deviceSessions, nucleiTemplates },
  }
}
