import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/session'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { releaseUserSkill, userSkillErrorResponse } from '@/lib/userSkillWrites'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'

interface RouteParams {
  params: Promise<{ id: string; skillId: string }>
}

/**
 * POST /api/users/[id]/attack-skills/[skillId]/release - lift the quarantine a revoked
 * plugin version put on a skill saved from its proposal.
 *
 * The owner only, by a strict match on the session user: not the admin bypass of
 * requireUserAccess, not an admin acting as the owner, not a service key. Releasing says
 * "I read this text and I trust it", which only its owner can say.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!sameOrigin(request)) return crossOriginResponse()
  try {
    const { id, skillId } = await params
    const session = await getSession()
    if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (session.userId !== id) {
      return NextResponse.json({ error: 'Only the owner of this skill can release it.', code: 'owner_only' }, { status: 403 })
    }
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused
    const skill = await releaseUserSkill({ userId: id, skillId }, { actorId: session.userId, source: 'ui' })
    return NextResponse.json(skill)
  } catch (error) {
    const refused = userSkillErrorResponse(error)
    if (refused) return refused
    return internalError(error, 'Failed to release the skill', { log: 'Failed to release attack skill' })
  }
}
