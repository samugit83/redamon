/**
 * Audit rows for workspace uploads and imports, written once the agent accepted
 * the job. The actor is the SESSION user, so under act-as it is the real admin;
 * the simulated user is recorded beside it (`onBehalfOfUserId`, and
 * `after.actingAsUserId` as before that column existed). The facts come from the agent's
 * answer (read from its own session), never from the browser's body.
 *
 * Server-side only.
 */
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActor } from '@/lib/auditActor'

/** The simulated user's id when an admin is acting as someone else, else undefined. */
export async function actingAsUserId(): Promise<string | undefined> {
  return (await auditActor()).onBehalfOfUserId ?? undefined
}

export async function auditWorkspaceAction(
  action: 'workspace.upload' | 'workspace.import' | 'workspace.resync',
  projectId: string,
  after: Record<string, unknown>,
): Promise<void> {
  const actor = await auditActor()
  const actingAs = actor.onBehalfOfUserId
  await writeAudit({
    ...actorFields(actor),
    action,
    targetType: 'project',
    targetId: projectId,
    after: actingAs ? { ...after, actingAsUserId: actingAs } : after,
    source: 'ui',
  })
}
