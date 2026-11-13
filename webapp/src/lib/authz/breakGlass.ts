/**
 * Root's break-glass on a project (step 4.14; SH-18, SH-47; feature document §4.5, §6.3): read
 * access to everything the project holds, Raw data & files included (private conversations from
 * Phase 5), for a reason and at most BREAKGLASS_MAX_MINUTES, behind POST and DELETE
 * /api/projects/[id]/breakglass.
 *
 * - Only with sharing in force, only for the confirmed Root (`projects:administer`, then
 *   `requireRootPower`: Root's own password), never while acting as someone, never on Root's own
 *   project. projectAccess honours a row only while it is unexpired AND its holder still holds
 *   `projects:administer`, so a Root transfer ends it at once.
 * - Opening writes the `ProjectBreakGlass` row and its `project.breakglass` audit row in one
 *   transaction (fail closed: no row, no access); the owner then gets a notice at their next sign-in
 *   (best effort: the audit row is in their activity feed whatever happens). Closing early deletes
 *   the person's rows on the project with a `project.breakglass.end` row in one transaction. Expiry
 *   needs no row: the opening row names it, and the expiry sweep (step 4.15) removes dead rows.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAudit, writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { safeErrorCode } from '@/lib/routeErrors'
import { appendNotice, breakGlassNotice } from './accountNotices'
import { now } from './clock'
import { NOT_WHILE_ACTING_AS } from './actAsRefusals'

export const BREAKGLASS_ACTION = 'project.breakglass'
export const BREAKGLASS_END_ACTION = 'project.breakglass.end'
export const BREAKGLASS_PERMISSION = 'projects:administer'
export const BREAKGLASS_MAX_MINUTES = 240
export const BREAKGLASS_REASON_MAX_LENGTH = 500

export interface BreakGlassActor {
  id: string
  name: string
  email: string
}

export interface BreakGlassProject {
  id: string
  userId: string
  name: string
}

export interface BreakGlassRequest {
  reason: string
  durationMinutes: number
}

function invalidField(field: string, error: string): NextResponse {
  return NextResponse.json({ error, code: 'invalid_field', field }, { status: 400 })
}

/** The reason (required) and the duration (whole minutes, 1 to BREAKGLASS_MAX_MINUTES); else the 400. */
export function parseBreakGlassRequest(body: Record<string, unknown>): BreakGlassRequest | NextResponse {
  const reason = typeof body.reason === 'string' ? body.reason.trim() : ''
  if (!reason) return invalidField('reason', 'Say why you need break-glass access: a reason is required.')
  if (reason.length > BREAKGLASS_REASON_MAX_LENGTH) {
    return invalidField('reason', `reason is longer than ${BREAKGLASS_REASON_MAX_LENGTH} characters`)
  }
  const minutes = body.durationMinutes
  if (typeof minutes !== 'number' || !Number.isSafeInteger(minutes) || minutes < 1 || minutes > BREAKGLASS_MAX_MINUTES) {
    return invalidField('durationMinutes', `durationMinutes must be a whole number of minutes from 1 to ${BREAKGLASS_MAX_MINUTES}`)
  }
  return { reason, durationMinutes: minutes }
}

/** The project break-glass would open, or null when it does not exist. */
export async function breakGlassProject(projectId: string): Promise<BreakGlassProject | null> {
  return prisma.project.findUnique({ where: { id: projectId }, select: { id: true, userId: true, name: true } })
}

/** Root reads its own project as its owner: break-glass is for someone else's. */
export function ownProjectRefusal(project: BreakGlassProject, actorId: string): NextResponse | null {
  if (project.userId !== actorId) return null
  return NextResponse.json({ error: 'You own this project: break-glass is for a project of another account.', code: 'own_project' }, { status: 400 })
}

/**
 * Oversight and break-glass are the real person's own powers, never used through an account acted
 * as: 403 `not_while_acting_as`, with the `act_as.refused` row every such refusal writes (best
 * effort; the refusal stands either way).
 */
export async function refuseWhileActing(
  actor: { id: string; email?: string | null },
  actingAs: { id: string; name?: string | null; email?: string | null } | null | undefined,
  action: 'break_glass' | 'oversight',
): Promise<NextResponse | null> {
  if (!actingAs) return null
  await writeAudit({
    actorId: actor.id,
    onBehalfOfUserId: actingAs.id,
    ...(actor.email ? { actorEmail: actor.email } : {}),
    action: 'act_as.refused',
    targetType: 'user',
    targetId: actingAs.id,
    after: { action },
    source: 'api',
  })
  const who = actingAs.name || actingAs.email || 'another account'
  const what = action === 'break_glass' ? 'break-glass access' : 'reading projects by oversight'
  return NextResponse.json({
    error: `Not available while acting as ${who}: ${what} is your own and is never used through another account. Stop acting as them first.`,
    code: NOT_WHILE_ACTING_AS,
    action,
  }, { status: 403 })
}

/**
 * Opens break-glass: the row and its audit row in one transaction (a failure throws and opens
 * nothing), then the owner's notice.
 */
export async function openBreakGlass(
  actor: BreakGlassActor,
  project: BreakGlassProject,
  asked: BreakGlassRequest,
): Promise<{ id: string; projectId: string; expiresAt: string; durationMinutes: number }> {
  const at = now()
  const expiresAt = new Date(at.getTime() + asked.durationMinutes * 60_000)
  const row = await auditedTransaction(prisma, async (tx) => {
    const created = await tx.projectBreakGlass.create({
      data: { projectId: project.id, userId: actor.id, reason: asked.reason, expiresAt },
      select: { id: true },
    })
    await writeAuditTx(tx, {
      actorId: actor.id,
      actorEmail: actor.email,
      projectId: project.id,
      permission: BREAKGLASS_PERMISSION,
      action: BREAKGLASS_ACTION,
      targetType: 'project',
      targetId: project.id,
      after: { breakGlassId: created.id, reason: asked.reason, durationMinutes: asked.durationMinutes, expiresAt: expiresAt.toISOString() },
      source: 'api',
    })
    return created
  })
  try {
    await appendNotice(project.userId, breakGlassNotice({
      by: { id: actor.id, name: actor.name, email: actor.email },
      at,
      reason: asked.reason,
      durationMinutes: asked.durationMinutes,
      project: { id: project.id, name: project.name },
    }))
  } catch (err) {
    console.error(`[rbac] break-glass notice not written project=${project.id} code=${safeErrorCode(err)}`)
  }
  return { id: row.id, projectId: project.id, expiresAt: expiresAt.toISOString(), durationMinutes: asked.durationMinutes }
}

/**
 * Ends the person's break-glass on the project before its expiry: every row of theirs there goes,
 * with one `project.breakglass.end` row, in one transaction. Answers how many unexpired rows ended
 * (0: nothing was open, nothing written).
 */
export async function closeBreakGlass(actor: { id: string; email?: string | null }, projectId: string): Promise<number> {
  const at = now()
  return auditedTransaction(prisma, async (tx) => {
    const open = await tx.projectBreakGlass.findMany({
      where: { projectId, userId: actor.id, expiresAt: { gt: at } },
      select: { id: true, expiresAt: true },
    })
    if (open.length === 0) return 0
    await tx.projectBreakGlass.deleteMany({ where: { projectId, userId: actor.id } })
    await writeAuditTx(tx, {
      actorId: actor.id,
      ...(actor.email ? { actorEmail: actor.email } : {}),
      projectId,
      permission: BREAKGLASS_PERMISSION,
      action: BREAKGLASS_END_ACTION,
      targetType: 'project',
      targetId: projectId,
      before: { breakGlassIds: open.map((r) => r.id), expiresAt: open.map((r) => r.expiresAt.toISOString()) },
      after: { endedBy: 'closed' },
      source: 'api',
    })
    return open.length
  })
}
