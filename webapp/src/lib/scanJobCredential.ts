/**
 * The job credential of one scan start (T15, step 1.16), as the orchestrator request
 * field it travels in. Every start path (startFullScan, dispatchStart for the queue and
 * the scheduler, the six manual start routes) spreads this into its body after its own
 * checks, right before its one orchestrator call.
 *
 * The orchestrator verifies it, admits the scan under its tenant and hands it to the
 * scan container, whose calls back to the webapp and the agent need it beside the
 * scanner key. With no configured master key nothing can be minted: the start goes
 * out without one and the orchestrator, which cannot verify one either, refuses it.
 */
import { CredentialRefused, mintJobCredential } from '@/lib/authz/machineCredential'

export function scanJobCredential(projectId: string, ownerId: string): { job_credential?: string } {
  try {
    return { job_credential: mintJobCredential({ tenant: ownerId, projectId }) }
  } catch (err) {
    if (!(err instanceof CredentialRefused)) throw err
    console.warn(`[rbac] job credential not minted reason=${err.code} project=${projectId}`)
    return {}
  }
}
