import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { signedInActor } from '@/lib/auditActor'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { DESCRIPTION_MAX_CHARS, UserSkillError } from '@/lib/userSkills'
import {
  USER_SKILL_AUDIT_TARGET, auditActorFor, contentSha256, createUserSkillTx, lockUserSkills,
} from '@/lib/userSkillWrites'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'

interface RouteParams {
  params: Promise<{ id: string }>
}

type SkipReason = 'duplicate' | 'limit' | 'fetchFailed' | 'tooLarge' | 'invalid'

const SKIP_FOR_CODE: Record<string, SkipReason> = {
  name_taken: 'duplicate',
  skill_limit: 'limit',
  content_too_large: 'tooLarge',
}

/**
 * POST /api/users/[id]/attack-skills/import-community - import every community agent skill.
 *
 * The same rules as an upload, through the same writer: the name a skill is CREATED with
 * is the one checked for duplicates (case- and space-insensitive, including names created
 * earlier in this import), and the cap is counted under the per-user lock. The texts are
 * fetched before the transaction, so no lock is held across the network.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused
    // It writes through createUserSkillTx under its own lock, past userSkillWrites' guard (step 3.14).
    const actingAs = await refuseWhileActingAsOn(id, 'write_agent_skills')
    if (actingAs) return actingAs

    let catalogRes: Response
    try {
      catalogRes = await agentFetch('/community-skills', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
      })
    } catch (error) {
      if (error instanceof AgentUnreachableError) {
        return upstreamFailureResponse('agent', error.cause_, 'Failed to fetch community skills catalog from agent service')
      }
      throw error
    }

    if (!catalogRes.ok) {
      return upstreamErrorResponse('agent', catalogRes, 'Failed to fetch community skills catalog from agent service')
    }

    const catalog = await catalogRes.json()
    const skills: Array<{ id: string; name: string; description?: string }> = catalog.skills || []
    const skippedBy: Record<SkipReason, number> = { duplicate: 0, limit: 0, fetchFailed: 0, tooLarge: 0, invalid: 0 }

    const candidates: { name: unknown; description: string | null; content: unknown; communityId: string }[] = []
    for (const skill of skills) {
      try {
        const contentRes = await agentFetch(`/community-skills/${encodeURIComponent(skill.id)}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
          cache: 'no-store',
        })
        if (!contentRes.ok) {
          skippedBy.fetchFailed++
          continue
        }
        const skillData = await contentRes.json()
        const rawDescription = skillData.description || skill.description || null
        candidates.push({
          name: skillData.name || skill.name,
          description: typeof rawDescription === 'string' ? rawDescription.slice(0, DESCRIPTION_MAX_CHARS) : null,
          content: typeof skillData.content === 'string' ? skillData.content : '',
          communityId: skill.id,
        })
      } catch {
        skippedBy.fetchFailed++
      }
    }

    const created = await prisma.$transaction(async (tx) => {
      await lockUserSkills(tx, id)
      const out: { id: string; name: string; content: string; communityId: string }[] = []
      for (const c of candidates) {
        try {
          const row = await createUserSkillTx(tx, { userId: id, name: c.name, description: c.description, content: c.content })
          out.push({ id: row.id, name: row.name, content: row.content, communityId: c.communityId })
        } catch (e) {
          if (!(e instanceof UserSkillError)) throw e
          skippedBy[SKIP_FOR_CODE[e.code] ?? 'invalid']++
        }
      }
      return out
    }, { timeout: 30_000 })

    const actor = auditActorFor((await signedInActor())?.id, id)
    for (const s of created) {
      await writeAudit({
        actorId: actor.actorId,
        action: 'user_attack_skill.import',
        targetType: USER_SKILL_AUDIT_TARGET,
        targetId: s.id,
        after: {
          name: s.name, contentSha256: contentSha256(s.content), userId: id,
          source: 'community', communityId: s.communityId,
          ...(actor.onBehalfOf ? { onBehalfOf: actor.onBehalfOf } : {}),
        },
        source: actor.source,
      })
    }

    const skipped = Object.values(skippedBy).reduce((a, b) => a + b, 0)
    return NextResponse.json({
      imported: created.length,
      importedIds: created.map((s) => s.id),
      skipped,
      skippedBy,
      total: skills.length,
    })
  } catch (error) {
    return internalError(error, 'Failed to import community attack skills')
  }
}
