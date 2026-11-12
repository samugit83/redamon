import { Prisma, type PluginInstall, type PluginOverride } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { normalizeUserToggleMap, UserSkillError } from '@/lib/userSkills'
import { suggestVersionName } from '@/lib/userSkillNames'
import {
  USER_SKILL_AUDIT_TARGET, contentSha256, createUserSkillTx, lockUserSkills, originPair, refuseSkillWriteWhileActingAs,
  startLineageTx, type AuditActor,
} from '@/lib/userSkillWrites'
import { auditPlugin } from './audit'
import { POINT_PERMISSION } from './extensionPoints'
import * as ov from './overrides'
import { hasPermission, isRevoked } from './registry'
import { addedRiskLines } from './riskFlags'

/**
 * Saving a `user_skill.text` proposal as a NEW user skill (README.PLUGINS.md §7.6): the
 * person's approval, never the plugin's. The source skill is not changed; the new skill is
 * an ordinary one the person owns, with its lineage and the plugin version that proposed it.
 *
 * Two gates fail closed:
 * - the proposer must still be serving AT THE VERSION THAT MADE THE PROPOSAL: enabled,
 *   ready, not revoked and granted override:user_skill.text. A proposal from a version that
 *   was disabled, uninstalled, revoked or replaced since is run again, not trusted;
 * - the platform's risk flags are recomputed on the text, and a save must acknowledge
 *   exactly as many flagged lines as there are.
 *
 * One transaction: the owner's user-skill lock, then the set's scope lock (the order every
 * user-skill writer uses), the skill, the set marked `adopted`, the source joining a family
 * when it had none, and the project's toggles when a project is given.
 */
export type ProposerReason = 'uninstalled' | 'disabled' | 'not_ready' | 'revoked' | 'permission_missing' | 'version_changed'

export interface ProposerState {
  available: boolean
  reason: ProposerReason | null
  /** The version that made the proposal, and the one installed now. */
  proposedBy: string | null
  installed: string | null
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

export function metaOf(row: Pick<PluginOverride, 'meta'>): Record<string, unknown> {
  return isObj(row.meta) ? row.meta : {}
}

export function proposerState(plugin: PluginInstall | null, proposedVersion: unknown): ProposerState {
  const proposedBy = typeof proposedVersion === 'string' ? proposedVersion : null
  const installed = plugin?.activeVersion ?? null
  const reason: ProposerReason | null =
    !plugin || plugin.status === 'available' || plugin.status === 'uninstalling' ? 'uninstalled'
      : isRevoked(plugin) ? 'revoked'
        : !plugin.enabled ? 'disabled'
          : plugin.status !== 'ready' ? 'not_ready'
            : !hasPermission(plugin, POINT_PERMISSION[ov.USER_SKILL_POINT]) ? 'permission_missing'
              : !proposedBy || installed !== proposedBy ? 'version_changed'
                : null
  return { available: reason === null, reason, proposedBy, installed }
}

export const PROPOSER_MESSAGES: Record<ProposerReason, string> = {
  uninstalled: 'is not installed',
  disabled: 'is disabled',
  not_ready: 'is not ready',
  revoked: 'was revoked by the plugin catalog',
  permission_missing: 'is no longer allowed to propose versions of your skills',
  version_changed: 'is now at another version than the one that made this proposal',
}

export function proposerMessage(displayName: string, state: ProposerState): string {
  return `${displayName} is not available at the version that made this proposal ` +
    `(it ${PROPOSER_MESSAGES[state.reason ?? 'not_ready']}). Run it again, or delete this proposal.`
}

export interface AdoptInput {
  changeSetId: string
  /** The scope owner (the effective user), whose skill this becomes. */
  ownerId: string
  /** Who decides: the real session user (an admin acting as the owner is recorded as such). */
  actor: AuditActor & { actorId: string }
  name: unknown
  description?: unknown
  projectId?: string | null
  enableNew?: boolean
  disableSource?: boolean
  acknowledgedRiskLines?: unknown
}

export interface AdoptResult {
  skillId: string
  name: string
  version: number
}

const CHECK_VIOLATION = /23514|violates check constraint/i

function isCheckViolation(e: unknown): boolean {
  return (e instanceof Prisma.PrismaClientKnownRequestError || e instanceof Prisma.PrismaClientUnknownRequestError) &&
    CHECK_VIOLATION.test(e.message)
}

export async function adoptUserSkillVersion(input: AdoptInput): Promise<AdoptResult> {
  // Saving it writes the owner's skills: never by an admin acting as the owner (step 3.14).
  await refuseSkillWriteWhileActingAs(input.ownerId, input.actor)
  let outcome: {
    skill: { id: string; name: string; content: string; version: number | null }
    pluginId: string
    pluginVersion: string
    sourceId: string
    project: { id: string; before: unknown; after: unknown } | null
  }
  try {
    outcome = await prisma.$transaction(async (tx) => {
      await lockUserSkills(tx, input.ownerId)
      const rows = await ov.lockChangeSet(tx, input.changeSetId)
      const first = rows[0]
      if (first.extensionPoint !== ov.USER_SKILL_POINT || first.scopeType !== 'user' || first.scopeId !== input.ownerId) {
        throw new UserSkillError(404, 'not_found', 'Not found')
      }
      if (first.status !== 'proposed') throw new UserSkillError(409, 'already_decided', 'This proposal was already decided.')
      const meta = metaOf(first)

      const plugin = await tx.pluginInstall.findUnique({ where: { pluginId: first.pluginId } })
      const proposer = proposerState(plugin, meta.pluginVersion)
      if (!proposer.available) {
        const displayName = isObj(plugin?.manifest) && typeof plugin.manifest.displayName === 'string' ? plugin.manifest.displayName : first.pluginId
        throw new UserSkillError(409, 'proposer_unavailable', proposerMessage(displayName, proposer), { reason: proposer.reason })
      }

      const baseText = typeof meta.baseText === 'string' ? meta.baseText : ''
      const flagged = addedRiskLines(baseText, first.value).length
      if (flagged > 0 && input.acknowledgedRiskLines !== flagged) {
        throw new UserSkillError(409, 'risk_not_acknowledged',
          `This version adds ${flagged} line${flagged === 1 ? '' : 's'} flagged for review; read and acknowledge them to save it.`,
          { flagged })
      }

      const sourceId = first.targetGroup
      const source = await tx.userAttackSkill.findFirst({
        where: { id: sourceId, userId: input.ownerId },
        select: {
          id: true, name: true, lineageRootId: true, version: true, description: true, quarantinedAt: true,
          originChain: true, releasedFor: true,
        },
      })
      // A proposal built before the quarantine would otherwise carry the revoked text out of it.
      if (source?.quarantinedAt) {
        throw new UserSkillError(409, 'skill_quarantined',
          `"${source.name}" is quarantined. Read and release it in Global Settings before saving a version of it.`)
      }
      const sourceName = source?.name ?? (typeof meta.sourceName === 'string' ? meta.sourceName : 'Skill')
      const lineageRootId = source?.lineageRootId ?? sourceId
      const { version } = await suggestVersionName(tx, input.ownerId, { id: sourceId, name: sourceName, lineageRootId })
      // The new skill carries its source's proposed text on, so a revocation of any version
      // in the source's chain reaches it, even after the source is deleted.
      const originChain = [...new Set([...(source?.originChain ?? []), originPair(first.pluginId, String(meta.pluginVersion))])]
      const skill = await createUserSkillTx(tx, {
        userId: input.ownerId,
        name: input.name,
        description: input.description,
        content: first.value,
        lineage: {
          derivedFromId: source?.id ?? null,
          lineageRootId,
          version,
          originChangeSetId: first.changeSetId,
          originPluginId: first.pluginId,
          originPluginVersion: String(meta.pluginVersion),
          originChain,
          releasedFor: (source?.releasedFor ?? []).filter((p) => originChain.includes(p)),
        },
      })
      if (source) await startLineageTx(tx, source)
      await ov.markAdoptedIn(tx, rows, input.actor.actorId, { skillId: skill.id, name: skill.name })

      let project: { id: string; before: unknown; after: unknown } | null = null
      if (input.projectId && (input.enableNew || (input.disableSource && source))) {
        const row = await tx.project.findFirst({
          where: { id: input.projectId, userId: input.ownerId },
          select: { id: true, attackSkillConfig: true },
        })
        if (!row) throw new UserSkillError(404, 'project_not_found', 'That project is not yours.')
        const config = isObj(row.attackSkillConfig) ? row.attackSkillConfig : {}
        const user = isObj(config.user) ? { ...(config.user as Record<string, boolean>) } : {}
        if (input.enableNew) user[skill.id] = true
        if (input.disableSource && source) user[source.id] = false
        // builtIn is kept exactly as stored, absent included: filling it in would change
        // which built-in skills the agent runs.
        const after = { ...config, user: await normalizeUserToggleMap(tx, input.ownerId, user) }
        // Through Prisma, never raw SQL: updatedAt moves, so every form holding the old map
        // sees a stale save instead of writing the switch back.
        await tx.project.update({ where: { id: row.id }, data: { attackSkillConfig: after as Prisma.InputJsonValue } })
        project = { id: row.id, before: row.attackSkillConfig, after }
      }
      return {
        skill, pluginId: first.pluginId, pluginVersion: String(meta.pluginVersion), sourceId, project,
      }
    }, { timeout: 20_000 })
  } catch (e) {
    if (isCheckViolation(e)) {
      throw new UserSkillError(503, 'platform_not_ready',
        'The database does not accept saved proposals yet (its plugin constraints are out of date). Restart the webapp, then save again.')
    }
    if (e instanceof ov.PluginOverrideError) {
      if (e.code === 'not_found') throw new UserSkillError(404, 'not_found', 'Not found')
      throw new UserSkillError(409, 'already_decided', 'This proposal was already decided.')
    }
    throw e
  }

  const onBehalfOf = input.actor.onBehalfOf ? { onBehalfOf: input.actor.onBehalfOf } : {}
  await auditPlugin('plugin.override.adopt', {
    actorId: input.actor.actorId,
    pluginId: outcome.pluginId,
    targetType: 'plugin_change_set',
    targetId: input.changeSetId,
    after: {
      changeSetId: input.changeSetId,
      pluginVersion: outcome.pluginVersion,
      skillId: outcome.skill.id,
      name: outcome.skill.name,
      sourceId: outcome.sourceId,
      projectId: outcome.project?.id ?? null,
      enableNew: !!input.enableNew,
      disableSource: !!input.disableSource,
      ...onBehalfOf,
    },
    source: 'ui',
  })
  await writeAudit({
    actorId: input.actor.actorId,
    action: 'user_attack_skill.create',
    targetType: USER_SKILL_AUDIT_TARGET,
    targetId: outcome.skill.id,
    after: {
      name: outcome.skill.name,
      contentSha256: contentSha256(outcome.skill.content),
      userId: input.ownerId,
      origin: { changeSetId: input.changeSetId, pluginId: outcome.pluginId, pluginVersion: outcome.pluginVersion },
      derivedFrom: outcome.sourceId,
      version: outcome.skill.version,
      ...onBehalfOf,
    },
    source: 'ui',
  })
  if (outcome.project) {
    await writeAudit({
      actorId: input.actor.actorId,
      action: 'project.update',
      targetType: 'project',
      targetId: outcome.project.id,
      before: { attackSkillConfig: outcome.project.before ?? null },
      after: { changed: ['attackSkillConfig'], values: { attackSkillConfig: outcome.project.after }, ...onBehalfOf },
      source: 'ui',
    })
  }
  return { skillId: outcome.skill.id, name: outcome.skill.name, version: outcome.skill.version ?? 1 }
}
