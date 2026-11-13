/**
 * Collaborators spend the owner's credentials only with consent, and every spend names who spent
 * (C1; step 5.6; SH-32, GV-12, OQ-06). A run, a scan or a webapp-side LLM feature on a project
 * spends its owner's providers and keys, whoever starts it: the model is the owner's feature model
 * and the agent is sent the owner's id, so a `custom/<providerId>` model resolves against the
 * owner's providers. The key itself never leaves the agent's settings fetch.
 *
 * - A collaborator reaches a spend only through Run scans, Use AI agent or Exploitation & shells,
 *   which count only while the owner consents (`effectiveToggles`, `ownerConsent.ts`). The LLM
 *   features whose permission sits below Use AI agent (report narratives at W, RoE parse at M,
 *   multi-mute suggest at W) ask `W+A` of a non-owner as well (`ownerSpend.ts`).
 * - Each collaborator spend writes `credits.used {feature, actor}` with the project, before the
 *   spend and fail closed (`ownerSpend.ts`): no row, no spend. The owner's own use writes nothing,
 *   so with write sharing off nothing here writes or reads (DV-30).
 * - Withdrawing the consent ends what collaborators still spend on the project
 *   (`endCollaboratorSpending`): their agent runs and sockets there, their queued scans, a live
 *   triage run one of them started. Best effort, each step logged when it fails.
 * - The owner's API usage report lists the last 30 days of those rows by collaborator
 *   (`collaboratorSpends`).
 */
import prisma from '@/lib/prisma'
import { closeAgentSockets } from '@/lib/agentSockets'
import { findLiveTriageRun } from '@/lib/triageRun'
import { stopRun } from '@/lib/triage/actions'
import { safeErrorCode } from '@/lib/routeErrors'
import { WS_SOCKETS } from '@/lib/wsTicket'
import { stopAgentRunsOnProjects } from './accountStatus'
import { rbacFlags } from './flags'
import { listShares } from './projectShares'
import { SPEND_FEATURES, type SpendFeature } from './ownerSpend'
import { ownedProjectsWhere } from './visibleProjects'

export interface SpendingEnded {
  collaborators: number
  runsStopped: number
  socketsClosed: number
  scansCancelled: number
  triageStopped: boolean
  /** The steps that failed (each logged `[rbac] consent-withdrawal step failed`). */
  failed: string[]
}

const NOT_STARTED = ['queued', 'needs_review']

/**
 * After the owner withdrew the consent: stops every collaborator's agent runs on the project, closes
 * their sockets there (the agent also stops each closed socket's run), cancels their queued scans and
 * stops a live triage run one of them started. Scans already running finish (OQ-13). The owner's work
 * is untouched. Never throws: the withdrawal stands whatever the agent answers.
 */
export async function endCollaboratorSpending(projectId: string, ownerId: string): Promise<SpendingEnded> {
  const out: SpendingEnded = { collaborators: 0, runsStopped: 0, socketsClosed: 0, scansCancelled: 0, triageStopped: false, failed: [] }
  const fail = (step: string, reason: string, userId?: string) => {
    console.error(`[rbac] consent-withdrawal step failed step=${step} project=${projectId}${userId ? ` user=${userId}` : ''}: ${reason}`)
    if (!out.failed.includes(step)) out.failed.push(step)
  }
  let people: string[]
  try {
    people = [...new Set((await listShares(projectId)).map(s => s.user.id))].filter(id => id && id !== ownerId)
  } catch (err) {
    fail('list_collaborators', safeErrorCode(err))
    return out
  }
  out.collaborators = people.length
  for (const userId of people) {
    const runs = await stopAgentRunsOnProjects(userId, [projectId])
    if ('error' in runs) fail('stop_runs', runs.error, userId)
    else out.runsStopped += runs.stopped
    const close = await closeAgentSockets({ userId, projectId, kinds: [...WS_SOCKETS], scope: 'access' })
    if (close.ok) out.socketsClosed += close.closed
    else fail('close_sockets', close.reason, userId)
  }
  if (people.length === 0) return out
  try {
    const cancelled = await prisma.jobQueue.updateMany({
      where: { projectId, userId: { in: people }, status: { in: NOT_STARTED } },
      data: {
        status: 'canceled',
        blockedCode: 'owner_consent_withdrawn',
        blockedReason: "The project's owner withdrew the consent to spend their credentials.",
        finishedAt: new Date(),
      },
    })
    out.scansCancelled = cancelled.count
  } catch (err) {
    fail('cancel_queued_scans', safeErrorCode(err))
  }
  try {
    const live = await findLiveTriageRun(projectId)
    if (live && people.includes(live.actorUserId)) {
      out.triageStopped = (await stopRun({ userId: ownerId, projectId }, 'app')).stopped
    }
  } catch (err) {
    fail('stop_triage_run', safeErrorCode(err))
  }
  return out
}

export interface CollaboratorSpend {
  userId: string
  name: string | null
  email: string | null
  total: number
  byFeature: Partial<Record<SpendFeature, number>>
  projects: Array<{ id: string; name: string; count: number }>
  lastAt: string
}

export interface CollaboratorSpends {
  sinceDays: number
  /** Rows beyond the cap were not counted. */
  truncated: boolean
  people: CollaboratorSpend[]
}

export const SPENDS_WINDOW_DAYS = 30
const SPENDS_ROW_CAP = 10_000

/**
 * Who spent `ownerId`'s credentials on the projects they own in the last 30 days, by collaborator,
 * newest first: for the owner's API usage report. Null with write sharing off (nothing is read; no
 * collaborator can spend then). A failed read throws.
 */
export async function collaboratorSpends(ownerId: string): Promise<CollaboratorSpends | null> {
  if (!rbacFlags().sharingWrite || !ownerId) return null
  const projects = await prisma.project.findMany({ where: ownedProjectsWhere({ userId: ownerId }), select: { id: true, name: true } })
  if (projects.length === 0) return { sinceDays: SPENDS_WINDOW_DAYS, truncated: false, people: [] }
  const since = new Date(Date.now() - SPENDS_WINDOW_DAYS * 86_400_000)
  const rows = await prisma.auditLog.findMany({
    where: { action: 'credits.used', projectId: { in: projects.map(p => p.id) }, createdAt: { gte: since } },
    select: { actorId: true, projectId: true, after: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
    take: SPENDS_ROW_CAP + 1,
  })
  const truncated = rows.length > SPENDS_ROW_CAP
  const names = new Map(projects.map(p => [p.id, p.name]))
  const byPerson = new Map<string, CollaboratorSpend>()
  for (const row of rows.slice(0, SPENDS_ROW_CAP)) {
    const after = (row.after ?? {}) as { actor?: unknown; feature?: unknown }
    const userId = typeof after.actor === 'string' && after.actor ? after.actor : row.actorId
    if (!userId || userId === ownerId || !row.projectId) continue
    const person = byPerson.get(userId) ?? {
      userId, name: null, email: null, total: 0, byFeature: {}, projects: [], lastAt: row.createdAt.toISOString(),
    }
    person.total += 1
    if (typeof after.feature === 'string' && (SPEND_FEATURES as readonly string[]).includes(after.feature)) {
      const feature = after.feature as SpendFeature
      person.byFeature[feature] = (person.byFeature[feature] ?? 0) + 1
    }
    const project = person.projects.find(p => p.id === row.projectId)
    if (project) project.count += 1
    else person.projects.push({ id: row.projectId, name: names.get(row.projectId) ?? row.projectId, count: 1 })
    byPerson.set(userId, person)
  }
  if (byPerson.size > 0) {
    const accounts = await prisma.user.findMany({
      where: { id: { in: [...byPerson.keys()] } }, select: { id: true, name: true, email: true },
    })
    for (const a of accounts) {
      const person = byPerson.get(a.id)
      if (person) Object.assign(person, { name: a.name ?? null, email: a.email ?? null })
    }
  }
  return { sinceDays: SPENDS_WINDOW_DAYS, truncated, people: [...byPerson.values()] }
}
