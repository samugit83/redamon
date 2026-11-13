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

export interface ScanJobFields {
  job_credential?: string
  actor_user_id?: string
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
