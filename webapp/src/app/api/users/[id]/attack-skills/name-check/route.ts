import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { MAX_SKILLS_PER_BATCH } from '@/lib/userSkills'
import { requireOwnBrowserRequest } from '@/lib/userSkillRouteGuard'
import { checkNames, isNameTaken, nameProblem, normalizeName, suggestVersionName } from '@/lib/userSkillNames'
import { requireSelfPermission } from '@/lib/authz/selfService'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/users/[id]/attack-skills/name-check?name=&sourceId=&exceptId= →
 * `{available, normalized, suggestion, reason?}`.
 *
 * Read-only, and it tells nothing the list route does not already show the same caller.
 * `sourceId` makes the suggestion the next version of that skill (`<root> vN`); `exceptId`
 * is the skill being renamed, whose own name does not count as taken. The write checks
 * again under its lock: this is the form's early answer, not the rule.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'read' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused
    const qs = request.nextUrl.searchParams
    const normalized = normalizeName(qs.get('name') ?? '')
    const exceptId = qs.get('exceptId') || undefined
    const sourceId = qs.get('sourceId') || undefined

    const source = sourceId
      ? await prisma.userAttackSkill.findFirst({
          where: { id: sourceId, userId: id }, select: { id: true, name: true, lineageRootId: true },
        })
      : null
    const problem = nameProblem(normalized)
    const taken = problem ? false : await isNameTaken(prisma, id, normalized, exceptId)
    const needSuggestion = !!source || taken
    const suggestion = needSuggestion
      ? (await suggestVersionName(prisma, id, source ?? { id: exceptId ?? '', name: normalized || 'Skill', lineageRootId: null })).name
      : null
    return NextResponse.json({
      available: !problem && !taken,
      normalized,
      suggestion,
      ...(problem ? { reason: problem.code } : taken ? { reason: 'name_taken' } : {}),
    })
  } catch (error) {
    return internalError(error, 'Failed to check the name', { log: 'Failed to check a skill name' })
  }
}

// Far above a real name: a typed 101-character name is answered name_too_long, not refused.
const MAX_RAW_NAME_CHARS = 1000

/**
 * POST .../name-check {names: string[]} → {results: NameCheckResult[]} in order: the upload
 * dialog's early answer for a whole batch, duplicates inside the batch included.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const eff = await requireOwnBrowserRequest(request, id)
    if (eff instanceof NextResponse) return eff
    const selfRefused = await requireSelfPermission(request, id, 'self:attack_skills')
    if (selfRefused) return selfRefused
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const names = parsed.body.names
    if (!Array.isArray(names) || names.length < 1 || names.length > MAX_SKILLS_PER_BATCH
      || !names.every((n) => typeof n === 'string' && n.length <= MAX_RAW_NAME_CHARS)) {
      return NextResponse.json(
        { error: `names must be 1 to ${MAX_SKILLS_PER_BATCH} strings`, code: 'names_invalid' }, { status: 400 })
    }
    return NextResponse.json({ results: await checkNames(prisma, id, names as string[]) })
  } catch (error) {
    return internalError(error, 'Failed to check the names', { log: 'Failed to check skill names' })
  }
}
