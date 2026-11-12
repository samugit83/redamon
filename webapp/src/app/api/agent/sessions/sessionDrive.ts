/**
 * The shared part of the routes that drive a Metasploit session or job (interact, kill):
 * look the target up in the caller's view of the agent's list, and audit the drive.
 * Server-side only.
 */
import { NextResponse } from 'next/server'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import {
  authorizeSessionTarget,
  type SessionsViewer,
  type SessionTarget,
} from '@/lib/authz/agentSessionsAccess'
import { agentErrorResponse, callAgent } from '../agentProxy'

export type DriveKind = 'session' | 'job'

/** The target, or the route's answer: the agent's failure, or 404 for anything outside the caller's view. */
export async function findDriveTarget(
  viewer: SessionsViewer,
  kind: DriveKind,
  id: string,
  failed: string,
): Promise<SessionTarget | NextResponse> {
  const call = await callAgent('/sessions', { cache: 'no-store' }, failed)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, failed)
  const target = await authorizeSessionTarget(await call.res.json(), viewer, kind, id)
  return target ?? NextResponse.json({ error: 'Not found' }, { status: 404 })
}

/** One audit row per drive that reached the console. Never the command text. */
export async function auditDrive(
  action: 'agent.session_interact' | 'agent.session_kill' | 'agent.job_kill',
  kind: DriveKind,
  id: string,
  viewer: SessionsViewer,
  target: SessionTarget,
): Promise<void> {
  const actor = auditActorOf(viewer.principal, viewer.effectiveUserId)
  const actingAs = actor.onBehalfOfUserId ? { actingAsUserId: actor.onBehalfOfUserId } : {}
  await writeAudit({
    ...actorFields(actor),
    action,
    targetType: kind === 'session' ? 'msf_session' : 'msf_job',
    targetId: id,
    after: { projectId: target.projectId, via: target.via, ...actingAs },
    source: 'ui',
  })
}

/** The console ran the drive (it answers `busy: true` when the agent holds it). */
export function driveRan(body: unknown): boolean {
  return !!body && typeof body === 'object' && (body as { busy?: unknown }).busy !== true
}
