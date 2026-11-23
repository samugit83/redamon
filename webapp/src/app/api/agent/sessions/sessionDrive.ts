/**
 * The shared part of the routes that drive a Metasploit session or job (interact, kill):
 * look the target up in the caller's view of the agent's list, audit the drive before it is
 * forwarded, and record its outcome.
 *
 * A target is the pair (sandbox instance, number) (group 1, TD-11): every per-user sandbox numbers
 * its sessions from 1, so the route takes `?sandbox=<instance>` (required), the pair is looked up
 * whole and authorized by its own project, and the agent is sent that same instance with the
 * person and view the agent tagged the row with. They come from the agent's list, never from the
 * request: the caller cannot choose whose sandbox it reaches, only which of the entries it may see.
 *
 * Server-side only.
 */
import { randomUUID } from 'node:crypto'
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAudit, writeAuditTx, type AuditEntry } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import type { AgentFetchOptions } from '@/lib/agentFetch'
import {
  authorizeSessionTarget,
  isSandboxInstance,
  unavailableInstances,
  visibleSessions,
  type SessionsViewer,
  type SessionTarget,
} from '@/lib/authz/agentSessionsAccess'
import { agentErrorResponse, callAgent } from '../agentProxy'

export type DriveKind = 'session' | 'job'

/**
 * The instance the request names (`?sandbox=`), or the route's 400: none named, or not an instance.
 * Decided before any lookup and the same for every number, so it tells nothing about which sessions
 * exist.
 */
export function driveSandbox(request: NextRequest): string | NextResponse {
  const params = request.nextUrl.searchParams
  if (!params.has('sandbox')) {
    return NextResponse.json({ error: 'Name the Kali sandbox the session runs in (?sandbox=)', code: 'sandbox_required' }, { status: 400 })
  }
  const sandbox = params.get('sandbox')
  if (isSandboxInstance(sandbox)) return sandbox
  return NextResponse.json({ error: 'sandbox must name a Kali sandbox instance', code: 'invalid_sandbox' }, { status: 400 })
}

/**
 * The target, or the route's answer: the agent's failure; 503 `sandbox_unavailable` when the named
 * sandbox did not answer the agent's list and is one the viewer's own list names as silent (the
 * panel keeps its last rows, so a 404 would say the session is gone); else 404 for anything outside
 * the caller's view. The 503 names nothing new: the viewer's list already carries that instance.
 */
export async function findDriveTarget(
  viewer: SessionsViewer,
  kind: DriveKind,
  id: string,
  sandbox: string,
  failed: string,
): Promise<SessionTarget | NextResponse> {
  const call = await callAgent('/sessions', { cache: 'no-store' }, failed)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, failed)
  const payload: unknown = await call.res.json()
  const target = await authorizeSessionTarget(payload, viewer, kind, id, sandbox)
  if (target) return target
  if (unavailableInstances(payload)?.includes(sandbox) && (await visibleSessions(payload, viewer)).unavailable?.includes(sandbox)) {
    return NextResponse.json(
      { error: 'That Kali sandbox did not answer; try again in a moment', code: 'sandbox_unavailable' },
      { status: 503 },
    )
  }
  return NextResponse.json({ error: 'Not found' }, { status: 404 })
}

/**
 * The agent's route for the drive, naming the same instance the target was found in and, when the
 * agent tagged its row, that sandbox's person and view. Instance ids are unique per person only, so
 * the agent then resolves the drive to that person's sandbox or to none (agentic/api.py
 * `_session_target`), even if the sandboxes changed since the list was read.
 */
export function drivePath(
  kind: DriveKind,
  id: string,
  action: 'interact' | 'kill',
  sandbox: string,
  target: Pick<SessionTarget, 'sandboxUser' | 'sandboxView'> = {},
): string {
  const query = new URLSearchParams({ sandbox })
  if (target.sandboxUser && target.sandboxView) {
    query.set('sandbox_user', target.sandboxUser)
    query.set('sandbox_view', target.sandboxView)
  }
  return `/${kind === 'session' ? 'sessions' : 'jobs'}/${encodeURIComponent(id)}/${action}?${query}`
}

export type DriveAction = 'agent.session_interact' | 'agent.session_kill' | 'agent.job_kill'

/**
 * What became of a forwarded drive. `no_answer`: the agent did not answer in time or could not be
 * reached, so the drive may still have run (the session manager runs a command that waited for the
 * console even when the agent has stopped waiting, unless it sees the agent hang up first).
 */
export type DriveOutcome = 'ran' | 'busy' | 'no_answer' | 'failed'

export interface DriveAudit {
  entry: AuditEntry
  /** Ties the outcome row to its attempt. */
  driveId: string
}

function withOutcome(audit: DriveAudit, outcome: DriveOutcome | 'attempted', status?: number): AuditEntry {
  const after = audit.entry.after as Record<string, unknown>
  return { ...audit.entry, after: { ...after, outcome, driveId: audit.driveId, ...(status ? { status } : {}) } }
}

/**
 * The drive's `attempted` row, written before anything is forwarded and in `auditedTransaction`: a
 * row that cannot be written throws, the route answers 500, and nothing reaches the agent. The row
 * cannot wait for the answer: the drive may run with none. It names the session as
 * `<instance>:<number>` and whose sandbox it runs in (`sandboxUser`) when the agent named the person.
 * Never the command text.
 */
export async function beginDriveAudit(
  action: DriveAction,
  kind: DriveKind,
  id: string,
  instance: string,
  viewer: SessionsViewer,
  target: SessionTarget,
): Promise<DriveAudit> {
  const actor = auditActorOf(viewer.principal, viewer.effectiveUserId)
  const actingAs = actor.onBehalfOfUserId ? { actingAsUserId: actor.onBehalfOfUserId } : {}
  const audit: DriveAudit = {
    entry: {
      ...actorFields(actor),
      action,
      targetType: kind === 'session' ? 'msf_session' : 'msf_job',
      targetId: `${instance}:${id}`,
      after: {
        projectId: target.projectId, via: target.via, sandbox: instance,
        ...(target.sandboxUser ? { sandboxUser: target.sandboxUser } : {}), ...actingAs,
      },
      source: 'ui',
    },
    driveId: randomUUID(),
  }
  await auditedTransaction(prisma, (tx) => writeAuditTx(tx, withOutcome(audit, 'attempted')))
  return audit
}

/** The console ran the drive (it answers `busy: true` when the agent holds it). */
export function driveRan(body: unknown): boolean {
  return !!body && typeof body === 'object' && (body as { busy?: unknown }).busy !== true
}

/**
 * Forwards an audited drive to the agent and records its outcome as a second row with the same
 * `driveId` (best effort: the attempt is already recorded). Answers what the route answers.
 */
export async function forwardAuditedDrive(
  audit: DriveAudit,
  path: string,
  init: RequestInit,
  failed: string,
  opts?: AgentFetchOptions,
): Promise<NextResponse> {
  const call = await callAgent(path, init, failed, opts)
  if (!call.ok) {
    await writeAudit(withOutcome(audit, 'no_answer', call.response.status))
    return call.response
  }
  if (!call.res.ok) {
    await writeAudit(withOutcome(audit, call.res.status === 504 ? 'no_answer' : 'failed', call.res.status))
    return agentErrorResponse(call.res, failed)
  }
  const answer = await call.res.json()
  await writeAudit(withOutcome(audit, driveRan(answer) ? 'ran' : 'busy'))
  return NextResponse.json(answer)
}
