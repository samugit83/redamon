/**
 * A project's Tradecraft Resources accordion (§3.4, T4.4): the owner's resources with their
 * per-project switch, and the counts of what the next message will use.
 *
 * Who sees what (R-066, D-07, §6.6):
 *   - the owner sees every resource with its read-only details;
 *   - an administrator acting as the owner sees the same, but no text of a resource with a login
 *     (its summary was built from the private pages);
 *   - anyone else who reads the project (a collaborator, oversight, break-glass) sees names and
 *     on/off only, and a resource with a login as "Owner only", locked.
 * The caller passes whose resources these are and whether the viewer owns the project as the
 * access check answered them, never from the request.
 */
import prisma from '@/lib/prisma'
import { activeCounts, type ActiveCounts } from './activeCounts'
import { isOwnerRun } from './catalog'
import { lastRefreshedOf } from './client'
import { hasStoredLogin } from './masking'
import { choiceChangeable, type ChoiceViewer } from './projectChoices'
import { tradecraftV2Enabled } from './switch'
import { listResourcesV2, type ResourceView } from './v2/list'
import type { IngestionReport } from './agentContract'

export interface ProjectResourceDetails {
  url: string
  /** 1: the 1.x map; 2: converted from 1.x; 3: ingested by 2.0. */
  mapVersion: number
  stale: boolean
  /** The resource's focus as saved (§6.14); empty means Everything. */
  focus: Record<string, unknown>
  /** Null when the viewer may not read it (an administrator acting as the owner, on a resource with a login). */
  summary: string | null
  summarySource: string
  report: IngestionReport | null
  /** The effective settings the live version was ingested with; empty before a 2.0 ingestion. */
  ingestedWith: Record<string, unknown>
  hasLogin: boolean
  lastError: string
}

export interface ProjectResourceRow {
  id: string
  name: string
  /** Null for a viewer who sees names and on/off only. */
  type: string | null
  storageMode: string | null
  pages: number | null
  lastRefreshedAt: string | null
  enabledGlobally: boolean
  offInProject: boolean
  /** A resource with a login, never used in this viewer's chats. */
  ownerOnly: boolean
  /** The viewer cannot change this resource's switch in the project. */
  locked: boolean
  details?: ProjectResourceDetails
}

export interface ProjectTradecraftView {
  /** The project owner's Tradecraft 2.0 switch: false leaves the tab and the drawer as they were. */
  v2: boolean
  viewerIsOwner: boolean
  resources: ProjectResourceRow[]
  counts: ActiveCounts | null
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const DETAIL_SELECT = { id: true, name: true, enabled: true, hasLogin: true, credentials: true, settingsSnapshot: true, focus: true } as const

export async function projectTradecraftView(opts: {
  projectId: string
  ownerId: string
  viewer: ChoiceViewer
  viewerIsOwner: boolean
}): Promise<ProjectTradecraftView> {
  const { projectId, ownerId, viewer, viewerIsOwner } = opts
  if (!(await tradecraftV2Enabled(ownerId))) return { v2: false, viewerIsOwner, resources: [], counts: null }

  const [rows, choices, project, views] = await Promise.all([
    prisma.userTradecraftResource.findMany({ where: { userId: ownerId }, orderBy: { createdAt: 'asc' }, select: DETAIL_SELECT }),
    prisma.tradecraftProjectChoice.findMany({ where: { projectId }, select: { resourceId: true } }),
    prisma.project.findUnique({ where: { id: projectId }, select: { attackSkillConfig: true } }),
    viewerIsOwner ? listResourcesV2(ownerId) : Promise.resolve([] as ResourceView[]),
  ])
  const off = new Set(choices.map(c => c.resourceId))
  const byId = new Map(views.map(v => [v.id, v]))
  const ownerRun = isOwnerRun({ ownerId, personId: viewer.personId, actorId: viewer.actorId })

  const resources = rows.map((r): ProjectResourceRow => {
    const login = hasStoredLogin(r)
    const row: ProjectResourceRow = {
      id: r.id,
      name: r.name,
      type: null,
      storageMode: null,
      pages: null,
      lastRefreshedAt: null,
      enabledGlobally: r.enabled,
      offInProject: r.enabled && off.has(r.id),
      ownerOnly: login && !ownerRun,
      locked: !choiceChangeable(r, ownerId, viewer),
    }
    const v = byId.get(r.id)
    if (!viewerIsOwner || !v) return row
    const snapshot = isPlainObject(r.settingsSnapshot) && isPlainObject(r.settingsSnapshot.values) ? r.settingsSnapshot.values : {}
    return {
      ...row,
      type: v.forcedType || v.resourceType,
      storageMode: v.storageMode,
      pages: v.entryCount,
      lastRefreshedAt: lastRefreshedOf(v),
      details: {
        url: v.url,
        mapVersion: v.mapVersion,
        stale: v.stale,
        focus: isPlainObject(r.focus) ? r.focus : {},
        summary: login && viewer.actorId ? null : v.summary,
        summarySource: v.summarySource,
        report: v.report,
        ingestedWith: snapshot,
        hasLogin: login,
        lastError: v.lastError,
      },
    }
  })

  const counts = await activeCounts(
    { ownerId, projectId, personId: viewer.personId, actorId: viewer.actorId },
    project?.attackSkillConfig ?? null,
  )
  return { v2: true, viewerIsOwner, resources, counts }
}
