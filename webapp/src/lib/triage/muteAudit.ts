/**
 * The `muted_nodes.muted` row of a single mute from the app (HD-14): the row shape
 * the MCP mute tools write (`lib/mcp/muteTools.ts`), with source `ui`. The actor is
 * the real signed-in account; `actingAsUserId` names the project owner an admin
 * was acting as.
 */
import { writeAudit } from '@/lib/audit'
import { realActorUserId, type TriageCaller } from '@/lib/triageClient'

/**
 * Called with the agent's answer to a `mute`. Only a mute that landed is written:
 * an already-muted finding was left exactly as it was, and a refusal or a failure
 * changed nothing.
 */
export async function auditSingleMute(
  caller: TriageCaller,
  answer: { status: number; body: Record<string, unknown> },
  mute: { key: string; reason: string; graphId?: string },
): Promise<void> {
  if (answer.status !== 200 || answer.body.muted !== true || answer.body.already === true) return
  const realActor = await realActorUserId()
  await writeAudit({
    actorId: realActor ?? caller.userId,
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
      ...(realActor && realActor !== caller.userId ? { actingAsUserId: caller.userId } : {}),
    },
    source: 'ui',
  })
}
