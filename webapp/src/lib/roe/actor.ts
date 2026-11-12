import { auditActor } from '@/lib/auditActor'
import type { EffectiveUser } from '@/lib/session'

/**
 * The admin behind a request made while acting as `eff`, or null.
 *
 * The RoE audits record the effective user as actor, so a RoE applied by an admin
 * simulating a user would read as the user's own act: they carry the admin in
 * `after`.
 */
export async function actingAdminId(eff: EffectiveUser): Promise<string | null> {
  try {
    const actor = await auditActor(eff)
    return actor.onBehalfOfUserId ? actor.actorId : null
  } catch {
    return null
  }
}
