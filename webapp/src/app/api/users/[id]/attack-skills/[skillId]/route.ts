import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { signedInActor } from '@/lib/auditActor'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import {
  auditActorFor, deleteUserSkill, updateUserSkill, userSkillErrorResponse,
} from '@/lib/userSkillWrites'
import { requireSelfPermission } from '@/lib/authz/selfService'

interface RouteParams {
  params: Promise<{ id: string; skillId: string }>
}

// GET /api/users/[id]/attack-skills/[skillId] - Full skill with content (for download)
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, skillId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'read' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused

    const skill = await prisma.userAttackSkill.findFirst({
      where: { id: skillId, userId: id },
    })

    if (!skill) {
      return NextResponse.json({ error: 'Skill not found' }, { status: 404 })
    }

    return NextResponse.json(skill)
  } catch (error) {
    return internalError(error, 'Failed to fetch attack skill')
  }
}

/**
 * PUT /api/users/[id]/attack-skills/[skillId] - rename, describe or replace the text.
 * Only name, description and content are read: lineage, provenance and quarantine are
 * never writable here.
 */
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, skillId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused
    const body = await request.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'The body must be a JSON object' }, { status: 400 })
    }
    const actorId = (await signedInActor())?.id
    const updated = await updateUserSkill(
      { userId: id, skillId, name: body.name, description: body.description, content: body.content },
      auditActorFor(actorId, id),
    )
    return NextResponse.json(updated)
  } catch (error) {
    const refused = userSkillErrorResponse(error)
    if (refused) return refused
    return internalError(error, 'Failed to update attack skill')
  }
}

/**
 * DELETE /api/users/[id]/attack-skills/[skillId] - the skill, its proposals still waiting
 * for review, and its toggle in every project of the owner, in one transaction.
 */
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, skillId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused
    const actorId = (await signedInActor())?.id
    const result = await deleteUserSkill({ userId: id, skillId }, auditActorFor(actorId, id))
    return NextResponse.json({ success: true, ...result })
  } catch (error) {
    const refused = userSkillErrorResponse(error)
    if (refused) return refused
    return internalError(error, 'Failed to delete attack skill')
  }
}
