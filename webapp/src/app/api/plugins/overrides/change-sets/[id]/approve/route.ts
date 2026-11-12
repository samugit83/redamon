import { NextResponse, type NextRequest } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { auditActor } from '@/lib/auditActor'
import { getEffectiveUser } from '@/lib/session'
import { auditPlugin } from '@/lib/plugins/audit'
import { bodyOwnerMatches, ownsScope, userScopeWriteRefusal } from '@/lib/plugins/changeSetAccess'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import * as ov from '@/lib/plugins/overrides'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import {
  SkillPartsRegistryError,
  clearSkillPartsCache,
  registryFailureText,
  registrySkill,
  validateSkillParts,
} from '@/lib/plugins/skillPartsRegistry'
import { adoptUserSkillVersion } from '@/lib/plugins/userSkillAdoption'
import { auditActorFor, userSkillErrorResponse } from '@/lib/userSkillWrites'

/**
 * POST /api/plugins/overrides/change-sets/[id]/approve: make a proposed version active
 * (design §6; OQ-08). The scope owner (or an admin acting as them) only; a user scope carries
 * `scopeOwnerId`, which must equal the effective user (the act-as cookie is site-wide; RV-33),
 * and follows the account write rule: an admin acting as a member who can sign in is refused,
 * one acting as a passwordless managed account is not (HD-23, OQ-49).
 *
 * The factory hashes AND texts come from the agent registry WITHOUT its cache, and the set is
 * re-validated by the agent's batch validator (whole-skill total included, so a lowered
 * PLUGIN_SKILL_TEXT_MAX_GROWTH is honoured). An approval the running agent could not apply is
 * refused, not stored: 503 when the agent has no /plugins/skill-parts.
 *
 * A `user_skill.text` set is never made active: it is SAVED AS A NEW USER SKILL of the
 * owner's (lib/plugins/userSkillAdoption.ts), with the body `{scopeOwnerId, name,
 * description?, projectId?, enableNew, disableSource, acknowledgedRiskLines}` and the answer
 * `{skillId, name, version}`. `projectId` must be a project the scope owner owns (strict,
 * never requireProjectAccess). Nothing of the agent registry is read for it.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const notFound = () => NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
const refuse = (status: number, code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status })

export const POST = pluginRoute('override approve', 'The proposal could not be approved; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { id } = await params
  const set = await ov.getChangeSet(id)
  if (!set || !(await ownsScope(set.scope, eff.userId))) return notFound()
  if (!bodyOwnerMatches(set.scope, eff.userId, parsed.body.scopeOwnerId)) {
    return refuse(403, 'wrong_owner', 'This version does not belong to the user you are acting as.')
  }
  const notAccountWriter = await userScopeWriteRefusal(set.scope)
  if (notAccountWriter) return notAccountWriter

  if (set.point === ov.USER_SKILL_POINT) {
    const body = parsed.body
    const skillActor = (await auditActor(eff)).actorId ?? eff.userId
    try {
      const saved = await adoptUserSkillVersion({
        changeSetId: id,
        ownerId: eff.userId,
        actor: { ...auditActorFor(skillActor, eff.userId), actorId: skillActor },
        name: body.name,
        description: body.description,
        projectId: typeof body.projectId === 'string' && body.projectId ? body.projectId : null,
        enableNew: body.enableNew === true,
        disableSource: body.disableSource === true,
        acknowledgedRiskLines: body.acknowledgedRiskLines,
      })
      return NextResponse.json(saved)
    } catch (e) {
      const refused = userSkillErrorResponse(e)
      if (refused) return refused
      throw e
    }
  }

  // Current factory hashes and texts, cache cleared so approval checks what the agent runs now.
  const hashes: Record<string, string> = {}
  const texts: Record<string, string> = {}
  try {
    clearSkillPartsCache()
    const skill = await registrySkill(set.targetGroup)
    if (!skill) return refuse(503, 'agent_outdated', 'The agent does not know this skill; rebuild it.')
    const byId = new Map(skill.parts.map((p) => [p.partId, p]))
    const changed: Record<string, string> = {}
    for (const part of set.parts) {
      const reg = byId.get(part.partId)
      if (reg) {
        hashes[part.targetKey] = reg.sha256
        texts[part.targetKey] = reg.text
      }
      changed[part.partId] = part.value
    }
    const verdict = await validateSkillParts(set.targetGroup, changed)
    if (!verdict.ok) {
      const errors = [...verdict.skill.errors, ...Object.values(verdict.parts).flatMap((p) => p.errors)]
      return refuse(422, 'over_limit', errors[0] ?? 'The proposed text is over the allowed size.', { errors })
    }
  } catch (e) {
    // Both agent_outdated (no endpoint) and agent_unreachable are 503: an approval RedAmon
    // cannot verify against the running agent is refused, not stored.
    // Whether the agent answered at all, and with which status, decides what to fix.
    if (e instanceof SkillPartsRegistryError) {
      const text = e.code === 'agent_unreachable' ? `${registryFailureText(e)}, so this approval cannot be checked now.` : e.message
      return refuse(503, e.code, text, e.failure.upstreamStatus ? { upstreamStatus: e.failure.upstreamStatus } : {})
    }
    throw e
  }

  // decidedBy is the audit actor: the real session user, even when an admin acts as the owner.
  const real = await auditActor(eff)
  const actor = real.actorId ?? eff.userId
  let result: ov.ApproveResult
  try {
    result = await ov.approve(id, actor, hashes, undefined, texts)
  } catch (e) {
    if (e instanceof ov.PluginStaleProposalError) {
      return refuse(409, 'stale_proposal', 'RedAmon’s factory text changed since this proposal; review it again.', { parts: e.targetKeys })
    }
    if (e instanceof ov.PluginOverrideError) {
      if (e.code === 'not_found') return notFound()
      if (e.code === 'wrong_state') return refuse(409, 'already_decided', 'This proposal was already decided.')
      return refuse(409, e.code, e.message)
    }
    throw e
  }

  await auditPlugin('plugin.override.approve', {
    actorId: actor,
    pluginId: set.pluginId,
    targetType: 'plugin_change_set',
    targetId: id,
    after: {
      point: set.point,
      targetGroup: set.targetGroup,
      scope: set.scope.type,
      scopeId: set.scope.id,
      revision: result.revision,
      ...(real.onBehalfOfUserId ? { onBehalfOf: real.onBehalfOfUserId } : {}),
      ...(result.replaced ? { replaced: result.replaced } : {}),
    },
    source: 'ui',
  })
  return NextResponse.json({ revision: result.revision })
})
