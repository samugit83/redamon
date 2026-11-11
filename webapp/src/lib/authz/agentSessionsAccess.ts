/**
 * Which shell sessions a person sees and drives (HD-01, HD-02).
 *
 * The Kali sandbox runs one msfconsole for the whole instance, so the agent's session
 * list holds every user's Metasploit sessions, the background jobs (the handlers that
 * catch them) and the netcat/socat listeners. A session belongs to the chat whose run
 * opened it (the session manager's session-to-chat map), the chat to its conversation
 * (`Conversation.sessionId`, unique) and the conversation to its project.
 *
 * - A session or listener of a project the effective user owns is visible.
 * - Every other one, the untagged ones and all jobs need `shell_sessions_all`
 *   (admins, the `shell_sessions` legacy grant, the escape hatch for pre-upgrade
 *   accounts), judged on the signed-in account: acting as someone never borrows
 *   their grant.
 *
 * The list leaves out what the caller may not see, with no count of it. Interact and
 * kill look their target up in the same list and refuse anything else, so an id that
 * is not in the caller's list does not exist for them (404).
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getEffectiveUser, requireSession } from '@/lib/session'
import { loadPrincipal, type Principal } from './principal'
import { sharedToolAccess, type SharedToolAccess } from './sharedTools'

type Row = Record<string, unknown> & { id?: unknown; chat_session_id?: unknown }
type ProjectRow = Row & { project_id: string | null }

export interface VisibleSessions {
  sessions: ProjectRow[]
  jobs: Row[]
  non_msf_sessions: ProjectRow[]
  cache_age_seconds?: unknown
  agent_busy?: unknown
}

export interface SessionsViewer {
  /** The signed-in account, as the database holds it now. */
  principal: Principal
  /** Whose projects' sessions are the caller's own: the account an admin acts as, else the caller. */
  effectiveUserId: string
  /** `shell_sessions_all` for the signed-in account (not counted as a use). */
  all: SharedToolAccess
}

export type SessionAccessVia = 'owner' | NonNullable<SharedToolAccess['via']>

export interface SessionTarget {
  projectId: string | null
  via: SessionAccessVia
}

interface ChatProject {
  projectId: string
  ownerId: string
}

/** The caller, or the 401 / coded 500 the route returns. A failed account read throws. */
export async function resolveSessionsViewer(): Promise<SessionsViewer | NextResponse> {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const principal = await loadPrincipal(session.userId)
  const effective = principal ? await getEffectiveUser() : null
  if (!principal || !effective) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  // Listing is polled every few seconds: not a use of the escape hatch (a drive is).
  const all = await sharedToolAccess(principal, 'shell_sessions_all', { record: false })
  return { principal, effectiveUserId: effective.userId, all }
}

function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((r): r is Row => !!r && typeof r === 'object') : []
}

function chatId(row: Row): string | null {
  return typeof row.chat_session_id === 'string' && row.chat_session_id ? row.chat_session_id : null
}

/** The project of each chat id, from one read of the conversations. */
async function chatProjects(chatIds: (string | null)[]): Promise<Map<string, ChatProject>> {
  const wanted = [...new Set(chatIds.filter((c): c is string => !!c))]
  const out = new Map<string, ChatProject>()
  if (wanted.length === 0) return out
  const found = await prisma.conversation.findMany({
    where: { sessionId: { in: wanted } },
    select: { sessionId: true, projectId: true, project: { select: { userId: true } } },
  })
  for (const c of found) out.set(c.sessionId, { projectId: c.projectId, ownerId: c.project.userId })
  return out
}

function payloadParts(payload: unknown) {
  const p = payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : {}
  return { p, sessions: rows(p.sessions), jobs: rows(p.jobs), listeners: rows(p.non_msf_sessions) }
}

/** The agent's session list as `viewer` may see it, each session and listener naming its project. */
export async function visibleSessions(payload: unknown, viewer: SessionsViewer): Promise<VisibleSessions> {
  const { p, sessions, jobs, listeners } = payloadParts(payload)
  const projects = await chatProjects([...sessions, ...listeners].map(chatId))
  const tag = (row: Row): ProjectRow => {
    const chat = chatId(row)
    return { ...row, project_id: (chat && projects.get(chat)?.projectId) || null }
  }
  const seen = (row: Row): boolean => {
    if (viewer.all.allowed) return true
    const chat = chatId(row)
    return !!chat && projects.get(chat)?.ownerId === viewer.effectiveUserId
  }
  const out: VisibleSessions = {
    sessions: sessions.filter(seen).map(tag),
    jobs: viewer.all.allowed ? jobs : [],
    non_msf_sessions: listeners.filter(seen).map(tag),
  }
  if ('cache_age_seconds' in p) out.cache_age_seconds = p.cache_age_seconds
  if ('agent_busy' in p) out.agent_busy = p.agent_busy
  return out
}

/**
 * Whether `viewer` may drive the session or job `id` of the agent's list, and through what.
 * Null when it is not in the caller's view (the route answers 404). Driving another
 * project's session under the escape hatch is a use, recorded as such.
 */
export async function authorizeSessionTarget(
  payload: unknown,
  viewer: SessionsViewer,
  kind: 'session' | 'job',
  id: string,
): Promise<SessionTarget | null> {
  const { sessions, jobs } = payloadParts(payload)
  const row = (kind === 'session' ? sessions : jobs).find(r => String(r.id) === id)
  if (!row) return null
  let projectId: string | null = null
  if (kind === 'session') {
    const chat = chatId(row)
    const project = chat ? (await chatProjects([chat])).get(chat) : undefined
    projectId = project?.projectId ?? null
    if (project && project.ownerId === viewer.effectiveUserId) return { projectId, via: 'owner' }
  }
  if (!viewer.all.allowed || !viewer.all.via) return null
  if (viewer.all.via === 'compat') await sharedToolAccess(viewer.principal, 'shell_sessions_all')
  return { projectId, via: viewer.all.via }
}
