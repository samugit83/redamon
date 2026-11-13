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
 *   (`endCollaboratorSpending`, through `onAccessReduced`, step 5.9): their agent runs and sockets
 *   there, their queued scans and schedules, a live triage run one of them started. Best effort,
 *   each step logged when it fails.
 * - The owner's API usage report lists the last 30 days of those rows by collaborator
 *   (`collaboratorSpends`).
 */
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { rbacFlags } from './flags'
import { listShares } from './projectShares'
import { onAccessReduced, type RevocationStep } from './revocation'
import { SPEND_FEATURES, type SpendFeature } from './ownerSpend'
import { ownedProjectsWhere } from './visibleProjects'

export interface SpendingEnded {
  collaborators: number
  runsStopped: number
  socketsClosed: number
  scansCancelled: number
  schedulesPaused: number
  triageStopped: boolean
  /** The steps that failed (each logged `[rbac] revocation step failed`, or `consent-withdrawal` for the list). */
  failed: Array<RevocationStep | 'list_collaborators'>
}

const count = <K extends string>(c: { [P in K]: number } | { error: string } | undefined, key: K): number =>
  (c && !('error' in c) ? (c as { [P in K]: number })[key] : 0)

/**
 * After the owner withdrew the consent: every collaborator's live work on the project stops
 * (`onAccessReduced`, `consent_withdrawn`): their agent runs and sockets there, their queued scans
 * and schedules, a live triage run one of them started. Scans already running finish (OQ-13). The
 * owner's work is untouched. Never throws: the withdrawal stands whatever the agent answers.
 */
export async function endCollaboratorSpending(projectId: string, ownerId: string): Promise<SpendingEnded> {
  const out: SpendingEnded = {
    collaborators: 0, runsStopped: 0, socketsClosed: 0, scansCancelled: 0, schedulesPaused: 0, triageStopped: false, failed: [],
  }
  let people: string[]
  try {
    people = [...new Set((await listShares(projectId)).map(s => s.user.id))].filter(id => id && id !== ownerId)
  } catch (err) {
    console.error(`[rbac] consent-withdrawal step failed step=list_collaborators project=${projectId}: ${safeErrorCode(err)}`)
    out.failed.push('list_collaborators')
    return out
  }
  out.collaborators = people.length
  for (const userId of people) {
    const stopped = await onAccessReduced(projectId, userId, 'consent_withdrawn', { ownerId })
    out.runsStopped += count(stopped.runs, 'stopped')
    out.socketsClosed += count(stopped.sockets, 'closed')
    out.scansCancelled += count(stopped.scans, 'cancelled')
    out.schedulesPaused += count(stopped.schedules, 'paused')
    if (count(stopped.triage, 'stopped') > 0) out.triageStopped = true
    for (const step of stopped.failed) if (!out.failed.includes(step)) out.failed.push(step)
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
