/**
 * Audit rows for workspace uploads and imports, written once the agent accepted
 * the job. The actor is the SESSION user, so under act-as it is the real admin;
 * the simulated user is recorded beside it. The facts come from the agent's
 * answer (read from its own session), never from the browser's body.
 *
 * Server-side only.
 */
import { writeAudit } from '@/lib/audit'
import { getEffectiveUser, getSession } from '@/lib/session'

/** The simulated user's id when an admin is acting as someone else, else undefined. */
export async function actingAsUserId(): Promise<string | undefined> {
  const [session, eff] = await Promise.all([getSession(), getEffectiveUser()])
  if (!session || !eff) return undefined
  return eff.userId !== session.userId ? eff.userId : undefined
}

export async function auditWorkspaceAction(
  action: 'workspace.upload' | 'workspace.import' | 'workspace.resync',
  projectId: string,
  after: Record<string, unknown>,
): Promise<void> {
  const session = await getSession()
  const actingAs = await actingAsUserId()
  await writeAudit({
    actorId: session?.userId ?? null,
    action,
    targetType: 'project',
    targetId: projectId,
    after: actingAs ? { ...after, actingAsUserId: actingAs } : after,
    source: 'ui',
  })
}
