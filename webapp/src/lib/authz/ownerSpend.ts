/**
 * The record of a collaborator spending the project owner's credentials (C1; step 5.6; GV-12): one
 * `credits.used` audit row per spend, `{feature, actor}` with the project, written before the spend
 * and fail closed (no row, no spend). The owner's own use writes nothing. Kept apart from
 * ownerCredentials.ts so the scan start paths and the feature routes import only this and the audit
 * helpers. The usage report reads the rows back (ownerCredentials.ts `collaboratorSpends`).
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditActorOf, sessionActor, type AuditActor } from '@/lib/auditActor'
import { safeErrorCode } from '@/lib/routeErrors'
import { requireLevel, type PermissionContext } from './guards'

/** What a collaborator spent the owner's credentials on, as the `credits.used` row names it. */
export type SpendFeature =
  | 'report_narratives'
  | 'roe_parse'
  | 'command_whisperer'
  | 'multi_mute'
  | 'text_to_cypher'
  | 'scan'
  | 'triage_run'
  | 'agent_session'
  | 'codefix_session'
  | 'shell_session'

export const SPEND_FEATURES: readonly SpendFeature[] = Object.freeze([
  'report_narratives', 'roe_parse', 'command_whisperer', 'multi_mute', 'text_to_cypher', 'scan', 'triage_run',
  'agent_session', 'codefix_session', 'shell_session',
])

export interface OwnerCredentialSpend {
  projectId: string
  /** The project's owner, whose credentials are spent. */
  ownerId: string
  /** The person the spend is for (the effective user, the collaborator). */
  userId: string
  /** The person signed in, and the account acted as, for the audit convention; the person when absent. */
  actor?: AuditActor
  feature: SpendFeature
  /** The permission the spend used, when one applies. */
  permission?: string
  source?: 'api' | 'system'
}

/** Written only for someone else's spend: false for the owner. */
export const spendsOwnerCredentials = (spend: Pick<OwnerCredentialSpend, 'ownerId' | 'userId'>): boolean =>
  spend.userId !== '' && spend.userId !== spend.ownerId

/**
 * Writes `credits.used` for a collaborator's spend of the owner's credentials, before the spend.
 * The owner's own use writes nothing. A row that cannot be written throws, so the caller spends
 * nothing (fail closed).
 */
export async function recordOwnerCredentialSpend(spend: OwnerCredentialSpend): Promise<boolean> {
  if (!spendsOwnerCredentials(spend)) return false
  const actor = spend.actor ?? auditActorOf({ id: spend.userId }, spend.userId)
  await writeAuditTx(prisma, {
    actorId: actor.actorId ?? spend.userId,
    ...(actor.onBehalfOfUserId ? { onBehalfOfUserId: actor.onBehalfOfUserId } : {}),
    ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
    projectId: spend.projectId,
    ...(spend.permission ? { permission: spend.permission } : {}),
    action: 'credits.used',
    targetType: 'project',
    targetId: spend.projectId,
    after: { feature: spend.feature, actor: spend.userId },
    source: spend.source ?? 'api',
  })
  return true
}

/**
 * For a feature route whose permission sits below Use AI agent: a non-owner needs `W+A` (Use AI agent,
 * which counts only with the owner's consent) before anything is spent. The owner passes.
 */
export function ownerCredentialRefusal(auth: PermissionContext): NextResponse | null {
  if (!auth.access) throw new Error('[rbac] ownerCredentialRefusal needs a context that checked a project')
  return auth.access.level === 'owner' ? null : requireLevel(auth, 'W+A')
}

/**
 * The route's `credits.used` row for a collaborator's spend, right before the agent call: null when it
 * is written or not needed, else the 503 the route returns (nothing was spent).
 */
export async function recordFeatureSpend(auth: PermissionContext, feature: SpendFeature): Promise<NextResponse | null> {
  if (!auth.access) throw new Error('[rbac] recordFeatureSpend needs a context that checked a project')
  const spend: OwnerCredentialSpend = {
    projectId: auth.access.project.id,
    ownerId: auth.access.project.userId,
    userId: auth.effective.userId,
    feature,
    permission: auth.permission,
  }
  if (!spendsOwnerCredentials(spend)) return null
  spend.actor = auditActorOf(sessionActor(auth.session), auth.effective.userId)
  try {
    await recordOwnerCredentialSpend(spend)
    return null
  } catch (err) {
    console.error(`[rbac] credits.used not recorded project=${spend.projectId} user=${spend.userId} feature=${feature}: ${safeErrorCode(err)}`)
    return NextResponse.json(
      { error: "This use of the project owner's credentials could not be recorded, so nothing was spent. Try again.", code: 'spend_not_recorded' },
      { status: 503 },
    )
  }
}
