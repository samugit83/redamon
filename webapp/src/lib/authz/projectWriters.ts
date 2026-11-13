/**
 * Who is writing a project's graph right now, and whether a second person may start (step 5.11,
 * SH-40, OQ-35; feature document §6.8.6).
 *
 * graphWriters.ts answers "is anything writing?" for activation and the scan starts. This answers
 * "who": every live writer with the person behind it, so a start by someone else can be refused
 * naming them (409 `project_writer_busy`) and the ProjectWriters banner can say "<person> is running
 * <kind> on this project". The writers and their person:
 *   - a scan of any kind: the orchestrator's `/system/active-scans`, `actor_user_id` (step 5.5)
 *   - an agent session: a flagged Conversation the agent confirms live, its author (`sub`, step 5.3)
 *   - a triage run: TriageRun.actorUserId
 *   - a mute-rule apply: NodeFilterRun.actorUserId
 * A writer whose person is not recorded (a run the orchestrator adopted after a restart, a scan
 * started before step 5.5) counts as the owner's: every start was the owner's before sharing.
 *
 * The same person may run several things at once, as before (an agent run beside a scan); only a
 * second PERSON is refused. "Person" is the effective user, as each writer records it: an admin
 * acting as the owner is the owner.
 *
 * Runs only with sharing in force (RBAC_SHARING_ENABLED and Root's policy): without it nobody else
 * reaches the project, and nothing is read (DV-30). A source that cannot be read (the orchestrator,
 * the agent, the database) makes the answer unverified: the owner's start goes ahead as before,
 * anyone else's is refused (fail closed), each with an `[rbac]` log line.
 *
 * Agent runs start over the chat socket long after its ticket was checked, so the agent asks again
 * before each run starts (/api/internal/agent/writer-check, agentic/writer_check.py), and gets
 * secondWriterResponse's answer for the ticket's person.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { runningSessionAuthors } from '@/lib/agentSessions'
import { findLiveTriageRun } from '@/lib/triageRun'
import { nodeFilterHeartbeatIsStale } from '@/lib/nodeFilterRun'
import { sharingInForce } from './sharingPolicy'
import { accountTypeOf, loadInstanceRoot, type AccountType } from './root'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const ACTIVE_SCANS_TIMEOUT_MS = 5_000
// The orchestrator lists only these already; checked again so an older one cannot widen it.
const ACTIVE_SCAN_STATUSES = new Set(['starting', 'running', 'paused', 'stopping'])

export type WriterKind =
  | 'full_recon' | 'partial_recon' | 'gvm' | 'github_hunt' | 'trufflehog' | 'supply_chain' | 'ai_attack'
  | 'scan' | 'agent' | 'triage' | 'node_filter'

/** Completes "<person> is running <phrase> on this project". */
export const WRITER_KIND_PHRASE: Record<WriterKind, string> = {
  full_recon: 'a full recon scan',
  partial_recon: 'a partial recon',
  gvm: 'a GVM vulnerability scan',
  github_hunt: 'a GitHub Secret Hunt',
  trufflehog: 'a Secret Multiscanner scan',
  supply_chain: 'a supply-chain scan',
  ai_attack: 'an AI attack-surface scan',
  scan: 'a scan',
  agent: 'an agent session',
  triage: 'a triage run',
  node_filter: 'a mute-rule apply',
}

const SCAN_KINDS = new Set<WriterKind>(['full_recon', 'partial_recon', 'gvm', 'github_hunt', 'trufflehog', 'supply_chain', 'ai_attack'])

export type SecondWriterPolicy = 'refuse' | 'notice'

/**
 * What a start does while another person writes the project (OQ-35): 'refuse' until experiment E10
 * records that an agent run and a scan writing one project at once cause no constraint error,
 * deadlock or lost update; then 'notice' (the banner names them, the start goes ahead).
 */
export const SECOND_WRITER_POLICY: SecondWriterPolicy = 'refuse'

export interface LiveWriter {
  kind: WriterKind
  /** The effective user behind it; an unrecorded one is the owner. */
  personId: string
}

export interface ProjectWriters {
  writers: LiveWriter[]
  /** The sources that could not be read: 'scans', 'agent', 'database'. */
  unverified: string[]
}

async function scanWriters(projectId: string, ownerId: string): Promise<LiveWriter[]> {
  const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/system/active-scans`, { method: 'GET' }, { timeoutMs: ACTIVE_SCANS_TIMEOUT_MS })
  if (!res.ok) throw new Error(`the orchestrator answered HTTP ${res.status}`)
  const scans = (await res.json())?.scans
  if (!Array.isArray(scans)) throw new Error('the orchestrator answered without a scan list')
  return scans
    .filter((s: { project_id?: unknown; status?: unknown }) => s?.project_id === projectId && ACTIVE_SCAN_STATUSES.has(String(s.status)))
    .map((s: { kind?: unknown; actor_user_id?: unknown }) => ({
      kind: SCAN_KINDS.has(s.kind as WriterKind) ? s.kind as WriterKind : 'scan',
      personId: typeof s.actor_user_id === 'string' && s.actor_user_id ? s.actor_user_id : ownerId,
    }))
}

async function agentWriters(projectId: string): Promise<LiveWriter[]> {
  const authors = await runningSessionAuthors(projectId)
  if ('failure' in authors) throw new Error(`the agent could not say which sessions are live (${authors.failure.code})`)
  return authors.userIds.map(personId => ({ kind: 'agent' as const, personId }))
}

async function databaseWriters(projectId: string): Promise<LiveWriter[]> {
  const [triage, applies] = await Promise.all([
    findLiveTriageRun(projectId),
    prisma.nodeFilterRun.findMany({
      where: { projectId, status: 'running' },
      select: { actorUserId: true, heartbeatAt: true },
    }),
  ])
  const now = Date.now()
  return [
    ...(triage ? [{ kind: 'triage' as const, personId: triage.actorUserId }] : []),
    ...applies.filter(r => !nodeFilterHeartbeatIsStale(r.heartbeatAt, now)).map(r => ({ kind: 'node_filter' as const, personId: r.actorUserId })),
  ]
}

/** Every live writer of the project with its person, and the sources that could not be read. */
export async function readProjectWriters(projectId: string, ownerId: string): Promise<ProjectWriters> {
  const sources: Array<[string, Promise<LiveWriter[]>]> = [
    ['scans', scanWriters(projectId, ownerId)],
    ['agent', agentWriters(projectId)],
    ['database', databaseWriters(projectId)],
  ]
  const writers: LiveWriter[] = []
  const unverified: string[] = []
  const settled = await Promise.allSettled(sources.map(([, read]) => read))
  settled.forEach((result, i) => {
    if (result.status === 'fulfilled') writers.push(...result.value)
    else {
      unverified.push(sources[i][0])
      console.error(`[rbac] project_writer_unverified project=${projectId} source=${sources[i][0]}:`, result.reason)
    }
  })
  return { writers, unverified }
}

export interface WriterPerson {
  /** Empty for a deleted account. */
  name: string
  email: string | null
  accountType: AccountType | null
  deleted: boolean
}

async function peopleById(ids: string[]): Promise<Map<string, WriterPerson>> {
  const unique = [...new Set(ids)]
  if (unique.length === 0) return new Map()
  const [accounts, root] = await Promise.all([
    prisma.user.findMany({ where: { id: { in: unique } }, select: { id: true, name: true, email: true, role: true } }),
    loadInstanceRoot(),
  ])
  const byId = new Map(accounts.map(a => [a.id, a]))
  return new Map(unique.map(id => {
    const a = byId.get(id)
    const person: WriterPerson = a
      ? { name: a.name ?? '', email: a.email, accountType: accountTypeOf(a, root), deleted: false }
      : { name: '', email: null, accountType: null, deleted: true }
    return [id, person]
  }))
}

/** How a refusal names a person in text: a name alone is not an identity, the email is (F-21). */
export function personText(person: WriterPerson | undefined): string {
  if (!person || person.deleted) return 'a deleted account'
  if (person.name && person.email) return `${person.name} (${person.email})`
  return person.email ?? 'someone'
}

export interface SecondWriterInput {
  projectId: string
  /** The person starting: the effective user; null means the owner (a schedule from before 5.5). */
  personId: string | null
  /** The project's owner when the caller already read it. */
  ownerId?: string
}

export interface SecondWriterRefusal {
  status: 409
  code: 'project_writer_busy'
  error: string
  /** "<person> is running <kind>", or why it could not be verified. */
  busy: string
}

async function ownerOf(projectId: string): Promise<string | null> {
  const project = await prisma.project.findUnique({ where: { id: projectId }, select: { userId: true } })
  return project?.userId ?? null
}

/**
 * Null when this person may start a writer on the project now, else the 409 that names who holds
 * it. Call it where the start holds the project's graph lock (projectGraphLock.ts), so two people
 * starting at once meet each other here: the second start runs after the first one's orchestrator
 * answer, and sees it. The chat ticket and the agent's per-run check ask it outside the lock: an
 * agent run holds none, so a scan start and an agent run within the same instant can both pass
 * (README.SECURITY_POSTURE §20). A missing project is null: the start path answers its own 404.
 */
export async function secondWriterRefusal(
  input: SecondWriterInput,
  opts: { policy?: SecondWriterPolicy } = {},
): Promise<SecondWriterRefusal | null> {
  if ((opts.policy ?? SECOND_WRITER_POLICY) !== 'refuse') return null
  if (!(await sharingInForce()).enabled) return null
  const ownerId = input.ownerId ?? await ownerOf(input.projectId)
  if (!ownerId) return null
  const person = input.personId ?? ownerId

  const { writers, unverified } = await readProjectWriters(input.projectId, ownerId)
  const other = writers.find(w => w.personId !== person)
  if (other) {
    const holder = personText((await peopleById([other.personId])).get(other.personId))
    const busy = `${holder} is running ${WRITER_KIND_PHRASE[other.kind]}`
    console.warn(`[rbac] project_writer_busy project=${input.projectId} person=${person} holder=${other.personId} kind=${other.kind}`)
    return {
      status: 409,
      code: 'project_writer_busy',
      busy,
      error: `${busy} on this project. One person writes a project at a time: wait for it to finish, or ask them to stop it.`,
    }
  }
  if (unverified.length > 0) {
    if (person === ownerId) {
      console.warn(`[rbac] project_writer_unverified project=${input.projectId} person=${person}: the owner's start goes ahead (${unverified.join(', ')})`)
      return null
    }
    console.warn(`[rbac] project_writer_busy project=${input.projectId} person=${person} unverified=${unverified.join(',')}`)
    const busy = `whether someone else is writing this project could not be verified (${unverified.join(', ')})`
    return {
      status: 409,
      code: 'project_writer_busy',
      busy,
      error: `Nothing was started: ${busy}. Try again shortly.`,
    }
  }
  return null
}

/** secondWriterRefusal as a route's answer. */
export async function secondWriterResponse(input: SecondWriterInput): Promise<NextResponse | null> {
  const refused = await secondWriterRefusal(input)
  if (!refused) return null
  return NextResponse.json({ error: refused.error, code: refused.code, busy: refused.busy }, { status: refused.status })
}

export interface OtherWriter {
  kind: WriterKind
  phrase: string
  person: WriterPerson
}

export interface OtherWritersView {
  /** One per person and kind, never the viewer's own. */
  writers: OtherWriter[]
  /** A source could not be read: the list may be short. */
  unverified: boolean
  /** Whether a start by the viewer is refused while these run (SECOND_WRITER_POLICY). */
  startsRefused: boolean
}

/** The banner's answer: who else is writing the project, by name, email and account type. */
export async function otherWritersView(projectId: string, ownerId: string, viewerId: string): Promise<OtherWritersView> {
  const { writers, unverified } = await readProjectWriters(projectId, ownerId)
  const seen = new Set<string>()
  const others = writers.filter(w => {
    const key = `${w.personId}|${w.kind}`
    if (w.personId === viewerId || seen.has(key)) return false
    seen.add(key)
    return true
  })
  const people = await peopleById(others.map(w => w.personId))
  return {
    writers: others.map(w => ({ kind: w.kind, phrase: WRITER_KIND_PHRASE[w.kind], person: people.get(w.personId)! })),
    unverified: unverified.length > 0,
    startsRefused: SECOND_WRITER_POLICY === 'refuse',
  }
}
