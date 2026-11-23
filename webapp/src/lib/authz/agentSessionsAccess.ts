/**
 * Which shell sessions a person sees and drives (HD-01, HD-02).
 *
 * The agent's session list gathers every running Kali sandbox's Metasploit sessions, background
 * jobs (the handlers that catch them) and netcat/socat listeners. A session belongs to the chat
 * whose run opened it (the session manager's session-to-chat map), the chat to its conversation
 * (`Conversation.sessionId`, unique) and the conversation to its project.
 *
 * - A session or listener of a project the effective user owns is visible, and of a
 *   project shared with them at `agent:sessions`' level (W+X: Read + Write with
 *   Exploitation & shells, which counts only with the owner's consent; step 5.10),
 *   as `projectAccess()` answers it now. An admin acting as a collaborator reaches the
 *   share at read (D-22) and sees none of its sessions that way.
 * - A background job (a handler) belongs to no project, but to the sandbox it runs in (D-D): the
 *   person sees and stops the jobs of their own sandbox in the view they work in, as the agent
 *   tagged the row (`own`; an admin acting as a member works in that member's `act_as` sandbox, so
 *   that one, never the member's own). Never another person's.
 * - Every other one, the unattributed ones and every other job need `shell_sessions_all`
 *   (admins, the `shell_sessions` legacy grant, the escape hatch for pre-upgrade
 *   accounts), judged on the signed-in account: acting as someone never borrows
 *   their grant.
 *
 * The list leaves out what the caller may not see, with no count of it. Interact and
 * kill look their target up in the same list and refuse anything else, so an id that
 * is not in the caller's list does not exist for them (404).
 *
 * Every person's sandbox runs its own console, which numbers its sessions from 1 (group 1, TD-11):
 * the agent tags each session, job and listener with its `sandbox` instance, and a target is the
 * pair (instance, number). The pair is looked up whole and its own project authorized, so a number
 * the caller may drive in one sandbox never reaches the same number in another. A row without an
 * instance tag stands for no project and is never a drive target.
 *
 * A sandbox's root answers its session manager, chat ids included, so a per-user row counts for its
 * chat's project only when the agent's own tags (`sandbox_user`, `sandbox_view`, which the agent adds
 * from the sandbox handle after the sandbox's row) name the person who wrote that chat AND the project
 * is one that person's sandbox mounts for that view (the gateway's mount list, read fresh). Otherwise
 * the row is unattributed: only holders of every session see it. The
 * tags never reach the browser (the instance stays opaque, TD-11). Rows whose id is not the session
 * manager's shape are dropped: the id goes into a browser URL.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getEffectiveUser, requireSession } from '@/lib/session'
import { VIEWS, type SandboxView } from '@/lib/sandbox/contract'
import { sandboxProjectsFor } from '@/lib/sandbox/gateway'
import { orchestratorList, validInstance, validUserId } from '@/lib/sandbox/orchestratorClient'
import { PERMISSIONS } from './permissions'
import { loadPrincipal, type Principal } from './principal'
import { meetsLevel, projectAccess } from './projectAccess'
import { sharedToolAccess, type SharedToolAccess } from './sharedTools'
import { visibleProjects } from './visibleProjects'

type Row = Record<string, unknown> & { id?: unknown; chat_session_id?: unknown; sandbox?: unknown }
type ProjectRow = Row & { project_id: string | null }

export interface VisibleSessions {
  sessions: ProjectRow[]
  jobs: Row[]
  non_msf_sessions: ProjectRow[]
  cache_age_seconds?: unknown
  /**
   * The sandbox instances whose console runs a command of the agent now (each sandbox has its own
   * console): of the instances this viewer has a row of, or all of them for holders of every session.
   */
  busy?: string[]
  /** How many sandboxes the agent could not ask: their sessions may be out of date or missing. */
  unavailable_count?: number
  /**
   * Their instance ids: all of them for holders of every session; for anyone else only those that
   * could hold a row this viewer may see (`unavailableForViewer`), whose last rows the browser keeps.
   */
  unavailable?: string[]
}

/**
 * The tags the agent adds to each per-user row from the sandbox handle, after the sandbox's own
 * fields, so the sandbox cannot set them: whose sandbox the row comes from, and which view.
 */
export const SANDBOX_PERSON_FIELD = 'sandbox_user'
export const SANDBOX_VIEW_FIELD = 'sandbox_view'

// The session manager's ids (mcp/servers/metasploit_server.py): an integer for a Metasploit session
// or job, `raw-<milliseconds>` for a listener.
const NUMBER_ID = /^\d{1,10}$/
const LISTENER_ID = /^raw-\d{1,20}$/

function wellShaped(row: Row, kind: 'number' | 'listener'): boolean {
  if (kind === 'listener') return typeof row.id === 'string' && LISTENER_ID.test(row.id)
  if (typeof row.id === 'number') return Number.isSafeInteger(row.id) && row.id >= 0
  return typeof row.id === 'string' && NUMBER_ID.test(row.id)
}

/** The person and view whose sandbox a row comes from, as the agent tagged it; null when absent or malformed. */
export function sandboxPersonOf(row: Row): { userId: string; view: SandboxView } | null {
  const userId = row[SANDBOX_PERSON_FIELD]
  const view = row[SANDBOX_VIEW_FIELD]
  if (!validUserId(userId) || !(VIEWS as readonly unknown[]).includes(view)) return null
  return { userId, view: view as SandboxView }
}

/** The row as the browser gets it: without the agent's person and view tags. */
function withoutPerson<T extends Row>(row: T): T {
  const { [SANDBOX_PERSON_FIELD]: _person, [SANDBOX_VIEW_FIELD]: _view, ...rest } = row
  return rest as T
}

/** A sandbox instance as the agent and the drive routes name it: six hex characters. */
export function isSandboxInstance(value: unknown): value is string {
  return validInstance(value)
}

/** The instance a row of the agent's list belongs to; null for a row without one. */
function rowSandbox(row: Row): string | null {
  return typeof row.sandbox === 'string' && row.sandbox ? row.sandbox : null
}

export interface SessionsViewer {
  /** The signed-in account, as the database holds it now. */
  principal: Principal
  /** Whose projects' sessions are the caller's own: the account an admin acts as, else the caller. */
  effectiveUserId: string
  /** `shell_sessions_all` for the signed-in account (not counted as a use). */
  all: SharedToolAccess
}

/** `share`: a project shared with the person at W+X; `own_sandbox`: a job of the caller's own sandbox (D-D). */
export type SessionAccessVia = 'owner' | 'share' | 'own_sandbox' | NonNullable<SharedToolAccess['via']>

export interface SessionTarget {
  projectId: string | null
  via: SessionAccessVia
  /** The person whose sandbox runs it, as the agent tagged the row (per-user rows only), for the audit. */
  sandboxUser?: string
  /** That sandbox's view, as tagged: the drive names the person and view along with the instance. */
  sandboxView?: SandboxView
}

export interface ChatProject {
  projectId: string
  /** The project's owner. */
  ownerId: string
  /** Who wrote the conversation. */
  authorId: string | null
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

/** The sandbox view the caller works in: an admin acting as a member works in that member's `act_as` sandbox. */
function viewerSandboxView(viewer: SessionsViewer): SandboxView {
  return viewer.principal.id !== viewer.effectiveUserId ? 'act_as' : 'own'
}

/**
 * Whether a row comes from the caller's own sandbox in the view the caller works in, as the agent
 * tagged it (the sandbox cannot set the tags), naming its instance.
 */
function fromViewerSandbox(row: Row, viewer: SessionsViewer): boolean {
  if (!validInstance(row.sandbox)) return false
  const person = sandboxPersonOf(row)
  return !!person && person.userId === viewer.effectiveUserId && person.view === viewerSandboxView(viewer)
}

function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((r): r is Row => !!r && typeof r === 'object' && !Array.isArray(r)) : []
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
    select: { sessionId: true, projectId: true, userId: true, project: { select: { userId: true } } },
  })
  for (const c of found) out.set(c.sessionId, { projectId: c.projectId, ownerId: c.project.userId, authorId: c.userId ?? null })
  return out
}

/**
 * Whether a row's chat may stand for its project. A row counts only when it names its sandbox
 * instance, the agent's person tag names the chat's author, and the project is that person's own or
 * in their sandbox's mount list for the tagged view (read once per person and view; a failed read
 * attributes nothing). A row without an instance attributes nothing. Each call makes one judge, so a
 * list is judged against one read of the mount lists.
 */
export function chatAttribution(): (row: Row, chat: ChatProject | undefined) => Promise<ChatProject | undefined> {
  const mounts = new Map<string, Promise<string[] | null>>()
  const mountsOf = (userId: string, view: SandboxView): Promise<string[] | null> => {
    const key = `${view}:${userId}`
    let list = mounts.get(key)
    if (!list) {
      list = sandboxProjectsFor(userId, { actingAs: view === 'act_as' }).catch(() => null)
      mounts.set(key, list)
    }
    return list
  }
  return async (row, chat) => {
    if (!chat || !validInstance(row.sandbox)) return undefined
    const person = sandboxPersonOf(row)
    if (!person || chat.authorId !== person.userId) return undefined
    if (chat.ownerId === person.userId) return chat
    return (await mountsOf(person.userId, person.view))?.includes(chat.projectId) ? chat : undefined
  }
}

/** The project each row's chat stands for, judged by `chatAttribution`. */
async function attributedProjects(list: Row[]): Promise<Map<Row, ChatProject>> {
  const chats = await chatProjects(list.map(chatId))
  const judge = chatAttribution()
  const out = new Map<Row, ChatProject>()
  for (const row of list) {
    const chat = chatId(row)
    const project = await judge(row, chat ? chats.get(chat) : undefined)
    if (project) out.set(row, project)
  }
  return out
}

const SESSIONS_LEVEL = PERMISSIONS['agent:sessions'].level ?? 'O'

/**
 * Of `projects`, those another person owns whose shell sessions the viewer may use: shared with them
 * at `agent:sessions`' level, asked of `projectAccess()` once per project (under act-as as acted).
 * The list is polled every few seconds and the sandbox holds every user's sessions, so with sharing
 * not in force (visibleProjects admits no share) nothing is read.
 */
async function sharedShellProjects(viewer: SessionsViewer, projects: Iterable<ChatProject>): Promise<Set<string>> {
  const subject = { userId: viewer.effectiveUserId }
  const actingAs = viewer.principal.id !== viewer.effectiveUserId
  const others = new Set<string>()
  for (const p of projects) if (p.ownerId !== viewer.effectiveUserId) others.add(p.projectId)
  const reached = new Set<string>()
  if (others.size === 0 || !(await visibleProjects(subject)).withShares) return reached
  for (const projectId of others) {
    const access = actingAs
      ? await projectAccess(subject, projectId, { actingAs: true })
      : await projectAccess(subject, projectId)
    if (access && meetsLevel(access, SESSIONS_LEVEL)) reached.add(projectId)
  }
  return reached
}

/** The agent's answer, each list keeping only rows whose id has the session manager's shape. */
export function payloadParts(payload: unknown) {
  const p = payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : {}
  return {
    p,
    sessions: rows(p.sessions).filter((r) => wellShaped(r, 'number')),
    jobs: rows(p.jobs).filter((r) => wellShaped(r, 'number')),
    listeners: rows(p.non_msf_sessions).filter((r) => wellShaped(r, 'listener')),
  }
}

/** The sandbox instances the agent could not ask, once each; null when it named none. */
export function unavailableInstances(payload: unknown): string[] | null {
  const p = payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : {}
  return Array.isArray(p.unavailable) ? [...new Set(p.unavailable.filter(isSandboxInstance))] : null
}

/** The agent's session list as `viewer` may see it, each session and listener naming its project. */
export async function visibleSessions(payload: unknown, viewer: SessionsViewer): Promise<VisibleSessions> {
  const { p, sessions, jobs, listeners } = payloadParts(payload)
  const projects = await attributedProjects([...sessions, ...listeners])
  const shared = viewer.all.allowed ? new Set<string>() : await sharedShellProjects(viewer, projects.values())
  const labels = viewer.all.allowed ? await rowLabels([...sessions, ...jobs, ...listeners], projects) : new Map<Row, RowLabels>()
  const labelled = <T extends Row>(row: Row, shown: T): T => ({ ...shown, ...labels.get(row) })
  const tag = (row: Row): ProjectRow => labelled(row, { ...withoutPerson(row), project_id: projects.get(row)?.projectId ?? null })
  const seen = (row: Row): boolean => {
    if (viewer.all.allowed) return true
    const project = projects.get(row)
    return !!project && (project.ownerId === viewer.effectiveUserId || shared.has(project.projectId))
  }
  const out: VisibleSessions = {
    sessions: sessions.filter(seen).map(tag),
    jobs: (viewer.all.allowed ? jobs : jobs.filter((row) => fromViewerSandbox(row, viewer))).map((row) => labelled(row, withoutPerson(row))),
    non_msf_sessions: listeners.filter(seen).map(tag),
  }
  if ('cache_age_seconds' in p) out.cache_age_seconds = p.cache_age_seconds
  const busy = busyInstances(p)
  if (busy) {
    // Another person's instance id names a sandbox the viewer has no business with.
    const shown = new Set([...out.sessions, ...out.jobs, ...out.non_msf_sessions].map(rowSandbox))
    out.busy = viewer.all.allowed ? busy : busy.filter((i) => shown.has(i))
  }
  const unavailable = unavailableInstances(p)
  if (unavailable) {
    out.unavailable_count = unavailable.length
    // Another person's instance id names a sandbox the viewer has no business with.
    out.unavailable = viewer.all.allowed ? unavailable : await unavailableForViewer(unavailable, viewer)
  }
  return out
}

/** The instances whose console the agent reports busy, once each; null when it named none. */
function busyInstances(p: Record<string, unknown>): string[] | null {
  return Array.isArray(p.busy) ? [...new Set(p.busy.filter(isSandboxInstance))] : null
}

/** What a holder of every session sees on a row besides its own fields: whose sandbox, which project. */
interface RowLabels {
  person_label?: string
  project_label?: string
}

const LABEL_MAX = 120

function labelText(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim()
  return clean ? clean.slice(0, LABEL_MAX) : null
}

/**
 * Whose sandbox and which project each row is, for a holder of every session only (gap G-33): their
 * list mixes every person's sandboxes, which all number from 1, so a kill or a stop there would act
 * on someone's shell without saying whose. The person comes from the agent's tags, never the
 * sandbox's own fields. A label is a display hint: a failed read labels nothing.
 */
async function rowLabels(list: Row[], projects: Map<Row, ChatProject>): Promise<Map<Row, RowLabels>> {
  const out = new Map<Row, RowLabels>()
  const people = new Set<string>()
  for (const row of list) {
    const person = sandboxPersonOf(row)
    if (person) people.add(person.userId)
  }
  const projectIds = new Set([...projects.values()].map((p) => p.projectId))
  let names = new Map<string, string>()
  let projectNames = new Map<string, string>()
  try {
    const [users, rowsOfProjects] = await Promise.all([
      people.size ? prisma.user.findMany({ where: { id: { in: [...people] } }, select: { id: true, name: true, email: true } }) : [],
      projectIds.size ? prisma.project.findMany({ where: { id: { in: [...projectIds] } }, select: { id: true, name: true } }) : [],
    ])
    names = new Map(users.flatMap((u) => {
      const label = labelText(u.name) ?? labelText(u.email)
      return label ? [[u.id, label] as const] : []
    }))
    projectNames = new Map(rowsOfProjects.flatMap((r) => {
      const label = labelText(r.name)
      return label ? [[r.id, label] as const] : []
    }))
  } catch {
    return out
  }
  for (const row of list) {
    const labels: RowLabels = {}
    const person = sandboxPersonOf(row)
    const name = person ? names.get(person.userId) : undefined
    if (person && name) labels.person_label = person.view === 'act_as' ? `${name} (act-as)` : name
    const project = projects.get(row)
    const projectName = project ? projectNames.get(project.projectId) : undefined
    if (projectName) labels.project_label = projectName
    if (labels.person_label || labels.project_label) out.set(row, labels)
  }
  return out
}

/**
 * Of the instances that did not answer, those that could hold a row `viewer` may see (S16b): the
 * browser keeps a silent sandbox's last rows only for the instances named to it. A per-user row counts
 * for its chat's project only when that project is in the sandbox person's mount list for its view
 * (`chatAttribution`), so an instance can hold such a row only when it is the viewer's own, or its
 * mount list holds a project whose sessions the viewer may see (her own, or shared with her at the
 * sessions level, as `visibleSessions` judges a row). No other instance id is sent (S16 F3); when the
 * running sandboxes cannot be read, none is named.
 */
async function unavailableForViewer(instances: string[], viewer: SessionsViewer): Promise<string[]> {
  const named = new Set<string>()
  if (instances.length > 0) {
    let running = new Map<string, RunningSandbox[]>()
    try {
      running = await runningByInstance()
    } catch {
      running = new Map()
    }
    for (const instance of instances) {
      for (const sandbox of running.get(instance) ?? []) {
        if (await holdsViewerRows(viewer, sandbox)) {
          named.add(instance)
          break
        }
      }
    }
  }
  return instances.filter((i) => named.has(i))
}

/**
 * While a sandbox stays silent every viewer's poll asks the naming, so its reads are kept: the
 * running list process-wide for NAMING_RUNNING_TTL_MS, each verdict for NAMING_VERDICT_TTL_MS.
 */
export const NAMING_RUNNING_TTL_MS = 5_000
/**
 * A share withdrawn may therefore still name its sandbox's instance to the viewer for up to this
 * long: acceptable only because naming keeps rows the viewer was already sent (the browser adds
 * none) and every drive is authorized again, fresh, by the drive routes.
 */
export const NAMING_VERDICT_TTL_MS = 10_000
const VERDICTS_MAX = 2_000

interface RunningSandbox {
  userId: string
  view: SandboxView
}

let runningRead: { at: number; map: Promise<Map<string, RunningSandbox[]>> } | null = null
const verdicts = new Map<string, { at: number; verdict: Promise<boolean> }>()

export function resetUnavailableNamingForTests(): void {
  runningRead = null
  verdicts.clear()
}

/**
 * The running sandboxes by instance (ids are unique per person only, so an instance may name more
 * than one), from the orchestrator's list alone. Only person and view are kept: the list's hosts and
 * tokens are dropped here. A failed read is not kept.
 */
function runningByInstance(): Promise<Map<string, RunningSandbox[]>> {
  const now = Date.now()
  if (runningRead && now - runningRead.at < NAMING_RUNNING_TTL_MS) return runningRead.map
  const map = orchestratorList().then((list) => {
    const out = new Map<string, RunningSandbox[]>()
    for (const s of list.sandboxes) {
      if (!validInstance(s.instance) || !validUserId(s.user_id) || !(VIEWS as readonly unknown[]).includes(s.view)) continue
      out.set(s.instance, [...(out.get(s.instance) ?? []), { userId: s.user_id, view: s.view }])
    }
    return out
  })
  const read = { at: now, map }
  runningRead = read
  map.catch(() => {
    if (runningRead === read) runningRead = null
  })
  return map
}

/** Whether `sandbox` could hold a row the viewer may see; one verdict per viewer, person and view, kept a while. */
function holdsViewerRows(viewer: SessionsViewer, sandbox: RunningSandbox): Promise<boolean> {
  const key = `${viewer.principal.id}>${viewer.effectiveUserId}|${sandbox.view}:${sandbox.userId}`
  const now = Date.now()
  const kept = verdicts.get(key)
  if (kept && now - kept.at < NAMING_VERDICT_TTL_MS) return kept.verdict
  if (verdicts.size >= VERDICTS_MAX) {
    for (const [k, v] of verdicts) if (now - v.at >= NAMING_VERDICT_TTL_MS) verdicts.delete(k)
    if (verdicts.size >= VERDICTS_MAX) verdicts.clear()
  }
  // A failed read names nothing: the browser then keeps nothing of that sandbox.
  const verdict = judgeViewerRows(viewer, sandbox).catch(() => false)
  verdicts.set(key, { at: now, verdict })
  return verdict
}

async function judgeViewerRows(viewer: SessionsViewer, { userId, view }: RunningSandbox): Promise<boolean> {
  if (userId === viewer.effectiveUserId) return true
  const mounted = await sandboxProjectsFor(userId, { actingAs: view === 'act_as' })
  if (mounted.length === 0) return false
  const projects = await prisma.project.findMany({ where: { id: { in: mounted } }, select: { id: true, userId: true } })
  const reached = projects.map((p) => ({ projectId: p.id, ownerId: p.userId, authorId: null }))
  if (reached.some((p) => p.ownerId === viewer.effectiveUserId)) return true
  return (await sharedShellProjects(viewer, reached)).size > 0
}

/**
 * Whether `viewer` may drive the session or job `id` of sandbox `sandbox` in the agent's list, and
 * through what. The pair is matched whole; a row without an instance is never a target.
 * Null when it is not in the caller's view (the route answers 404). A job of the caller's own
 * sandbox, in the view they work in, is theirs (D-D). Driving another project's session, or
 * another sandbox's job, under the escape hatch is a use, recorded as such.
 */
export async function authorizeSessionTarget(
  payload: unknown,
  viewer: SessionsViewer,
  kind: 'session' | 'job',
  id: string,
  sandbox: string,
): Promise<SessionTarget | null> {
  if (!validInstance(sandbox)) return null
  const { sessions, jobs } = payloadParts(payload)
  const matches = (kind === 'session' ? sessions : jobs).filter(r => String(r.id) === id && rowSandbox(r) === sandbox)
  // One console never lists a number twice; two rows for one pair is an answer this cannot trust.
  if (matches.length !== 1) return null
  const row = matches[0]
  const person = sandboxPersonOf(row)
  const sandboxPerson = person ? { sandboxUser: person.userId, sandboxView: person.view } : {}
  let projectId: string | null = null
  if (kind === 'job' && fromViewerSandbox(row, viewer)) return { projectId, via: 'own_sandbox', ...sandboxPerson }
  if (kind === 'session') {
    const project = (await attributedProjects([row])).get(row)
    projectId = project?.projectId ?? null
    if (project && project.ownerId === viewer.effectiveUserId) return { projectId, via: 'owner', ...sandboxPerson }
    if (project && (await sharedShellProjects(viewer, [project])).has(project.projectId)) return { projectId, via: 'share', ...sandboxPerson }
  }
  if (!viewer.all.allowed || !viewer.all.via) return null
  if (viewer.all.via === 'compat') await sharedToolAccess(viewer.principal, 'shell_sessions_all')
  return { projectId, via: viewer.all.via, ...sandboxPerson }
}
