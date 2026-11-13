/**
 * The job credential of one scan start (T15, step 1.16) and the person who started it
 * (step 5.5, D-14), as the orchestrator request fields they travel in. Every start path
 * (startFullScan, dispatchStart for the queue and the scheduler, the six manual start
 * routes) spreads this into its body after its own checks, right before its one
 * orchestrator call.
 *
 * The orchestrator verifies the credential, runs the scan container under its tenant
 * (the owner) and hands it to the container, whose calls back to the webapp and the
 * agent need it beside the scanner key. `actor_user_id` is who the per-user admission
 * ceiling counts: the person whose permission check let the start through (a
 * collaborator on the owner's project), the owner when the caller names nobody. The
 * credential's claims are unchanged: the actor never decides whose data the scan uses.
 * With no configured master key nothing can be minted: the start goes out without
 * either field and the orchestrator, which cannot verify one either, refuses it.
 */
import { CredentialRefused, mintJobCredential } from '@/lib/authz/machineCredential'
import { actorScanCap } from '@/lib/authz/quotas'
import { recordOwnerCredentialSpend } from '@/lib/authz/ownerSpend'

export interface ScanJobFields {
  job_credential?: string
  actor_user_id?: string
  /** The actor's maxConcurrentScans quota (step 6.8), present only when one is set. */
  actor_max_concurrent?: number
}

export function scanJobCredential(
  projectId: string,
  ownerId: string,
  actorUserId: string | null | undefined,
): ScanJobFields {
  try {
    return {
      job_credential: mintJobCredential({ tenant: ownerId, projectId }),
      actor_user_id: actorUserId || ownerId,
    }
  } catch (err) {
    if (!(err instanceof CredentialRefused)) throw err
    console.warn(`[rbac] job credential not minted reason=${err.code} project=${projectId}`)
    return {}
  }
}

/**
 * Every start's fields (step 6.8): the credential and actor above, plus the actor's
 * maxConcurrentScans quota, which the orchestrator's admission applies to that same
 * actor as the smaller of it and RECON_MAX_CONCURRENT_PER_USER (one per-user cap, 5.5's).
 * Read before the start's orchestrator call, outside its try: a failed quota read throws
 * and starts nothing; it is never taken for an unreachable orchestrator. With the
 * governance switch off nothing is read and the fields are scanJobCredential's.
 *
 * A collaborator's scan spends the owner's scan keys and AI hooks (step 5.6, C1): its
 * `credits.used` row is written here, before the start, and a row that cannot be written
 * throws, so nothing starts. The owner's scans write nothing.
 */
export async function scanStartFields(
  projectId: string,
  ownerId: string,
  actorUserId: string | null | undefined,
): Promise<ScanJobFields> {
  if (actorUserId && actorUserId !== ownerId) {
    await recordOwnerCredentialSpend({
      projectId, ownerId, userId: actorUserId, feature: 'scan', source: 'system',
    })
  }
  const fields = scanJobCredential(projectId, ownerId, actorUserId)
  return fields.actor_user_id ? { ...fields, ...(await actorScanCap(fields.actor_user_id)) } : fields
}
