/**
 * The settings rules that span fields, shared by every path that writes them.
 *
 * Per-field bounds live in the registry and `validateValue`. What they cannot
 * express is a rule over SEVERAL fields - fireteam's concurrency may not exceed
 * its team size - or one that needs the operator's own configuration - a
 * supply-chain repository may only be on github.com or a GitHub Enterprise host
 * the operator registered. Those ran only inside the project form's PUT, so an
 * MCP write skipped them: `fireteamPropensity` 9 passed the registry's 0-10
 * bound while the form's own schema allows 1-5.
 *
 * `nextRow` is the EFFECTIVE row: the stored row with the change applied (the PUT
 * through guardProjectWrite and the MCP tools), or the whole new row at creation
 * (POST, create_project, the import). A rule over two fields - "only in IP mode",
 * "scan_all needs its confirmation" - cannot be judged on a partial body.
 *
 * Two rules also NORMALIZE `nextRow` in place: `attackSkillConfig` is replaced by
 * the form it may be stored in (lib/userSkills.ts normalizeUserSkillToggles: user ids
 * the owner does not have dropped, at most 20 of the owner's skills on, none quarantined),
 * and the hostname policy gets canonical filter entries and loses a scan_all
 * confirmation the mode no longer uses (scopeGroups.normalizeIpHostnamePolicy).
 * A caller that writes an object other than `nextRow` copies them back.
 */
import prisma from '@/lib/prisma'
import { normalizeUserSkillToggles, UserSkillError } from '@/lib/userSkills'
import { allowedGithubHosts } from '@/lib/github/ownerTarget'
import { validateFireteamSettings } from '@/lib/validation/fireteamSettings'
import { validateSupplyChainInput } from '@/lib/validation/supplyChainInput'
import {
  IP_HOSTNAME_FIELDS, type ScopeFields, ipHostnamePolicyProblem, normalizeIpHostnamePolicy,
} from '@/lib/scopeGroups'

/** What re-judges the hostname policy: its seven fields, the mode flip that makes
 *  it apply, and the engagement kind that refuses scan_all (decision D-03). */
export const IP_HOSTNAME_RULE_TRIGGERS: readonly string[] = [...IP_HOSTNAME_FIELDS, 'ipMode', 'engagementKind']

export const FIRETEAM_FIELDS = [
  'fireteamEnabled', 'fireteamMaxConcurrent', 'fireteamMaxMembers',
  'fireteamMemberMaxIterations', 'fireteamTimeoutSec', 'fireteamAllowedPhases',
  'fireteamPropensity',
] as const

/** The supply-chain fields that become a `git clone` argument or an account to enumerate. */
export const SUPPLY_CHAIN_INPUT_FIELDS = [
  'supplyChainRepoUrl', 'supplyChainInputMode', 'supplyChainRepoRef', 'supplyChainOrgName',
] as const

function pick(row: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of keys) if (Object.prototype.hasOwnProperty.call(row, key)) out[key] = row[key]
  return out
}

/**
 * The first cross-field rule `nextRow` breaks, or null. A rule runs only when
 * a key it covers is in `touchedKeys`, so an unrelated write is never refused
 * over a value it did not change.
 *
 * `actorUserId` decides which GitHub Enterprise host is allowed: the allowlist
 * comes from that user's settings, never from the request. `ownerUserId` is whose skills
 * the user-skill toggles may name: the project's owner (default: `nextRow.userId`, then
 * the actor). Pass null for a project with no owner, which may name none.
 */
export async function validateCrossFieldRules(
  nextRow: Record<string, unknown>,
  touchedKeys: Iterable<string>,
  actorUserId: string,
  opts: { ownerUserId?: string | null } = {},
): Promise<string | null> {
  const touched = new Set(touchedKeys)

  if (touched.has('attackSkillConfig') && Object.prototype.hasOwnProperty.call(nextRow, 'attackSkillConfig')) {
    const owner = opts.ownerUserId !== undefined
      ? opts.ownerUserId
      : typeof nextRow.userId === 'string' ? nextRow.userId : actorUserId
    try {
      nextRow.attackSkillConfig = await normalizeUserSkillToggles(prisma, owner, nextRow.attackSkillConfig)
    } catch (e) {
      if (e instanceof UserSkillError) return e.message
      throw e
    }
  }

  if (SUPPLY_CHAIN_INPUT_FIELDS.some(k => touched.has(k))) {
    const settings = await prisma.userSettings.findUnique({
      where: { userId: actorUserId }, select: { githubEnterpriseHost: true },
    }).catch(() => null)
    const problem = validateSupplyChainInput(
      pick(nextRow, SUPPLY_CHAIN_INPUT_FIELDS),
      allowedGithubHosts(settings?.githubEnterpriseHost),
    )
    if (problem) return problem
  }

  if (FIRETEAM_FIELDS.some(k => touched.has(k))) {
    const problem = validateFireteamSettings(pick(nextRow, FIRETEAM_FIELDS))
    if (problem) return problem
  }

  if (IP_HOSTNAME_RULE_TRIGGERS.some(k => touched.has(k))) {
    const problem = ipHostnamePolicyProblem(nextRow as ScopeFields)
    if (problem) return problem
    normalizeIpHostnamePolicy(nextRow)
  }

  return null
}

/**
 * One `FireteamSettingsAudit` row per fireteam field `after` changes.
 * Best-effort: an audit failure must not roll back a write that already landed.
 */
export async function writeFireteamAudit(
  projectId: string,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  actor: { userId: string | null; source: string },
): Promise<void> {
  try {
    const rows = FIRETEAM_FIELDS
      .filter(field => field in after && JSON.stringify(before[field]) !== JSON.stringify(after[field]))
      .map(field => ({
        projectId,
        userId: actor.userId,
        field,
        oldValue: (before[field] ?? null) as never,
        newValue: (after[field] ?? null) as never,
        source: actor.source,
      }))
    if (rows.length > 0) await prisma.fireteamSettingsAudit.createMany({ data: rows })
  } catch (e) {
    console.warn('Fireteam settings audit write failed:', e)
  }
}
