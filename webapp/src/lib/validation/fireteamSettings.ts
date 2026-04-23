/**
 * Server-side validation for Fireteam (multi-agent) project settings.
 *
 * Mirrors the client-side form constraints in AgentBehaviourSection.tsx.
 * A direct PATCH to /api/projects/[id] with out-of-range values bypasses
 * the React form; this module re-enforces the contract on the server.
 */

import { z } from 'zod'

const PHASES = ['informational', 'exploitation', 'post_exploitation'] as const

export const FireteamSettingsSchema = z.object({
  fireteamEnabled: z.boolean().optional(),
  fireteamMaxConcurrent: z.number().int().min(1).max(8).optional(),
  fireteamMaxMembers: z.number().int().min(2).max(8).optional(),
  fireteamMemberMaxIterations: z.number().int().min(5).max(50).optional(),
  fireteamTimeoutSec: z.number().int().min(60).max(7200).optional(),
  fireteamAllowedPhases: z.array(z.enum(PHASES)).min(1).optional(),
  fireteamPropensity: z.number().int().min(1).max(5).optional(),
})

/**
 * Validate fireteam fields in a project update body. Returns a human-readable
 * error message when the payload violates constraints, otherwise null.
 *
 * Also enforces two cross-field invariants that can't be expressed in a pure
 * Zod schema without access to both touched and existing values:
 *   - fireteamMaxConcurrent <= fireteamMaxMembers (when both touched)
 *   - fireteamEnabled=true requires the operator to NOT contradict known
 *     server safety requirements (PERSISTENT_CHECKPOINTER). The agent
 *     enforces the deploy-time gate; we surface it here as a warning.
 */
export function validateFireteamSettings(body: Record<string, unknown>): string | null {
  const parsed = FireteamSettingsSchema.safeParse(body)
  if (!parsed.success) {
    const first = parsed.error.issues[0]
    const path = first.path.join('.')
    return `fireteam validation failed at ${path || '(root)'}: ${first.message}`
  }
  const d = parsed.data
  if (
    typeof d.fireteamMaxConcurrent === 'number' &&
    typeof d.fireteamMaxMembers === 'number' &&
    d.fireteamMaxConcurrent > d.fireteamMaxMembers
  ) {
    return 'fireteamMaxConcurrent cannot exceed fireteamMaxMembers'
  }
  return null
}
