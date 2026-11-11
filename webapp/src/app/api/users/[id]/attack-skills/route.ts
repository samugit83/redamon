import { NextRequest, NextResponse } from 'next/server'
import { getSession, requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { nameKeys } from '@/lib/userSkillNames'
import { USER_SKILL_POINT } from '@/lib/plugins/overrides'
import {
  USER_SKILL_SELECT, auditActorFor, createUserSkill, userSkillErrorResponse,
} from '@/lib/userSkillWrites'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/users/[id]/attack-skills - the user's skills, newest first, without their text.
 *
 * Each carries its version and lineage, the source it was saved from, its quarantine, the
 * proposals waiting for review (`pendingChangeSetIds`), and `duplicateName` when another of
 * the user's skills has the same name by the uniqueness rule (a name taken before the rule
 * existed; rename one).
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'read' })
    if (__denied) return __denied

    const skills = await prisma.userAttackSkill.findMany({
      where: { userId: id },
      select: { ...USER_SKILL_SELECT, derivedFrom: { select: { name: true } } },
      orderBy: { createdAt: 'desc' },
    })
    const pending = await prisma.pluginOverride.findMany({
      where: { extensionPoint: USER_SKILL_POINT, scopeType: 'user', scopeId: id, status: 'proposed' },
      select: { changeSetId: true, targetGroup: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    })
    const pendingBySkill = new Map<string, string[]>()
    for (const p of pending) {
      const list = pendingBySkill.get(p.targetGroup) ?? []
      if (!list.includes(p.changeSetId)) list.push(p.changeSetId)
      pendingBySkill.set(p.targetGroup, list)
    }
    const keys = await nameKeys(prisma, skills.map((s) => s.name))
    const keyCount = new Map<string, number>()
    for (const k of keys) keyCount.set(k, (keyCount.get(k) ?? 0) + 1)

    return NextResponse.json(skills.map((s, i) => ({
      ...s,
      derivedFromName: s.derivedFrom?.name ?? null,
      derivedFrom: undefined,
      pendingChangeSetIds: pendingBySkill.get(s.id) ?? [],
      duplicateName: (keyCount.get(keys[i]) ?? 0) > 1,
    })))
  } catch (error) {
    return internalError(error, 'Failed to fetch attack skills')
  }
}

// POST /api/users/[id]/attack-skills - Create skill { name, description?, content }
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const body = await request.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'The body must be a JSON object' }, { status: 400 })
    }
    const session = await getSession()
    const skill = await createUserSkill(
      { userId: id, name: body.name, description: body.description, content: body.content },
      auditActorFor(session?.userId, id),
    )
    return NextResponse.json(skill, { status: 201 })
  } catch (error) {
    const refused = userSkillErrorResponse(error)
    if (refused) return refused
    return internalError(error, 'Failed to create attack skill')
  }
}
