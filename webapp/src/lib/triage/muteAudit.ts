/**
 * The `muted_nodes.muted` row of a single mute from the app (HD-14): the row shape
 * the MCP mute tools write (`lib/mcp/muteTools.ts`), with source `ui`. The actor is
 * the real signed-in account; the project owner an admin was acting as goes in
 * `onBehalfOfUserId` and, as before that column existed, in `after.actingAsUserId`.
 */
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf, signedInActor } from '@/lib/auditActor'
import type { TriageCaller } from '@/lib/triageClient'

/** The person signed in; none outside a request scope, where the owner is the actor as before. */
async function realActor(): Promise<{ id: string; email: string | null } | null> {
  try {
    return await signedInActor()
  } catch {
    return null
  }
}

/**
 * Called with the agent's answer to a `mute`. Only a mute that landed is written:
 * an already-muted finding was left exactly as it was, and a refusal or a failure
 * changed nothing. `person` is the effective user the mute is attributed to
 * (routeCaller `triagePerson`): the collaborator on a shared project, never the
 * tenant; it defaults to the tenant, the owner, as before step 5.2.
 */
export async function auditSingleMute(
  caller: TriageCaller,
  answer: { status: number; body: Record<string, unknown> },
  mute: { key: string; reason: string; graphId?: string },
  person: string = caller.userId,
): Promise<void> {
  if (answer.status !== 200 || answer.body.muted !== true || answer.body.already === true) return
  const actor = auditActorOf((await realActor()) ?? { id: person }, person)
  await writeAudit({
    ...actorFields(actor),
    action: 'muted_nodes.muted',
    targetType: 'project',
    targetId: caller.projectId,
    after: {
      reason: mute.reason,
      count: 1,
      items: [{
        key: mute.key,
        label: typeof answer.body.label === 'string' ? answer.body.label : null,
        outcome: 'muted',
      }],
      ...(mute.graphId ? { graphId: mute.graphId } : {}),
      ...(actor.onBehalfOfUserId ? { actingAsUserId: actor.onBehalfOfUserId } : {}),
    },
    source: 'ui',
  })
}
