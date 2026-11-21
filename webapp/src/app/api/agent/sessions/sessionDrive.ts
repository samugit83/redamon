/**
 * The shared part of the routes that drive a Metasploit session or job (interact, kill):
 * look the target up in the caller's view of the agent's list, and audit the drive.
 *
 * A target is the pair (sandbox instance, number) (group 1, TD-11): every per-user sandbox numbers
 * its sessions from 1, so the route takes `?sandbox=<instance>`, the pair is looked up whole and
 * authorized by its own project, and the agent is sent that same instance. In per-user mode the
 * parameter is required; without it only the untagged rows of the shared container match. The
 * instance comes from the agent's list, never as a person or a view: the caller cannot choose whose
 * sandbox it reaches, only which of the entries it may see.
 *
 * Server-side only.
 */
import { NextResponse, type NextRequest } from 'next/server'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import {
  authorizeSessionTarget,
  isSandboxInstance,
  type SessionsViewer,
  type SessionTarget,
} from '@/lib/authz/agentSessionsAccess'
import { SHARED_INSTANCE } from '@/lib/sandbox/contract'
import { sandboxMode } from '@/lib/sandbox/gateway'
import { agentErrorResponse, callAgent } from '../agentProxy'

export type DriveKind = 'session' | 'job'

/** The instance the request names (`?sandbox=`), null when it names none, or the route's 400. */
export function driveSandbox(request: NextRequest): string | null | NextResponse {
  const params = request.nextUrl.searchParams
  if (!params.has('sandbox')) return null
  const sandbox = params.get('sandbox')
  if (isSandboxInstance(sandbox)) return sandbox
  return NextResponse.json({ error: 'sandbox must name a Kali sandbox instance', code: 'invalid_sandbox' }, { status: 400 })
}

/** Per-user mode as the orchestrator last named it; unknown (an outage) is never taken for per-user. */
async function perUserMode(): Promise<boolean> {
  try {
    return (await sandboxMode()) === 'per_user'
  } catch {
    return false
  }
}

/**
 * The target, or the route's answer: the agent's failure, 400 when per-user mode needs an instance
 * the request did not name, or 404 for anything outside the caller's view. The 400 is decided after
 * the lookup and the same for every number, so it tells nothing about which sessions exist.
 */
export async function findDriveTarget(
  viewer: SessionsViewer,
  kind: DriveKind,
  id: string,
  sandbox: string | null,
  failed: string,
): Promise<SessionTarget | NextResponse> {
  const call = await callAgent('/sessions', { cache: 'no-store' }, failed)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, failed)
  const target = await authorizeSessionTarget(await call.res.json(), viewer, kind, id, sandbox)
  if (target) return target
  if (sandbox === null && (await perUserMode())) {
    return NextResponse.json({ error: 'Name the Kali sandbox the session runs in (?sandbox=)', code: 'sandbox_required' }, { status: 400 })
  }
  return NextResponse.json({ error: 'Not found' }, { status: 404 })
}

/** The agent's route for the drive, naming the same instance the target was found in. */
export function drivePath(kind: DriveKind, id: string, action: 'interact' | 'kill', sandbox: string | null): string {
  const path = `/${kind === 'session' ? 'sessions' : 'jobs'}/${encodeURIComponent(id)}/${action}`
  return sandbox === null ? path : `${path}?sandbox=${encodeURIComponent(sandbox)}`
}

/**
 * One audit row per drive that reached the console, naming the session as `<instance>:<number>` and,
 * for a per-user sandbox, whose sandbox it runs in (`sandboxUser`). Never the command text.
 */
export async function auditDrive(
  action: 'agent.session_interact' | 'agent.session_kill' | 'agent.job_kill',
  kind: DriveKind,
  id: string,
  sandbox: string | null,
  viewer: SessionsViewer,
  target: SessionTarget,
): Promise<void> {
  const actor = auditActorOf(viewer.principal, viewer.effectiveUserId)
  const actingAs = actor.onBehalfOfUserId ? { actingAsUserId: actor.onBehalfOfUserId } : {}
  const instance = sandbox ?? SHARED_INSTANCE
  await writeAudit({
    ...actorFields(actor),
    action,
    targetType: kind === 'session' ? 'msf_session' : 'msf_job',
    targetId: `${instance}:${id}`,
    after: {
      projectId: target.projectId, via: target.via, sandbox: instance,
      ...(target.sandboxUser ? { sandboxUser: target.sandboxUser } : {}), ...actingAs,
    },
    source: 'ui',
  })
}

/** The console ran the drive (it answers `busy: true` when the agent holds it). */
export function driveRan(body: unknown): boolean {
  return !!body && typeof body === 'object' && (body as { busy?: unknown }).busy !== true
}
