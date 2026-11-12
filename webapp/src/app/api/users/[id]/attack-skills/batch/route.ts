import { NextRequest, NextResponse } from 'next/server'
import { signedInActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { MAX_SKILL_BATCH_BYTES } from '@/lib/userSkills'
import { requireOwnBrowserRequest } from '@/lib/userSkillRouteGuard'
import { safeErrorCode } from '@/lib/routeErrors'
import { auditActorFor, createUserSkillsBatch, userSkillErrorResponse } from '@/lib/userSkillWrites'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/users/[id]/attack-skills/batch {items: [{name, description?, content, nameSource?,
 * descriptionSource?, aiModel?}], enableInProjectId?} → 201 {created, enabled, leftOff,
 * enableSkipped?}. All or nothing: a refused batch answers 409 `batch_refused` with every
 * refused item's index and reason, and nothing is saved.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  // Before anything reads the body: past 10 MB the proxy would truncate it into "Invalid JSON".
  if (Number(request.headers.get('content-length') || 0) > MAX_SKILL_BATCH_BYTES) {
    return NextResponse.json(
      { error: 'This batch is larger than 8 MB; upload it in smaller batches.', code: 'batch_too_large' }, { status: 413 })
  }
  try {
    const { id } = await params
    const eff = await requireOwnBrowserRequest(request, id)
    if (eff instanceof NextResponse) return eff
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const result = await createUserSkillsBatch(
      { userId: id, items: parsed.body.items, enableInProjectId: parsed.body.enableInProjectId },
      auditActorFor((await signedInActor())?.id, id),
    )
    return NextResponse.json(result, { status: 201 })
  } catch (error) {
    const refused = userSkillErrorResponse(error)
    if (refused) return refused
    // Its kind only: a Prisma message can quote the query's values, and an item's text can hold anything.
    const code = (error as { code?: unknown } | null)?.code
    console.error('Failed to upload a skill batch:', error instanceof Error ? error.name : typeof error, code ?? '')
    return NextResponse.json({ error: 'Failed to upload the skills', code: safeErrorCode(error) }, { status: 500 })
  }
}
