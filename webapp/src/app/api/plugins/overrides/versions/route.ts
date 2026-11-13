import { NextResponse, type NextRequest } from 'next/server'
import { getEffectiveUser } from '@/lib/session'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { buildVersionsModel } from '@/lib/plugins/versionsModel'
import { buildUserSkillVersionsModel } from '@/lib/plugins/userSkillVersionsModel'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/overrides/versions?point=skill.text&group=<skill>&projectId=<id>: the
 * versions of a built-in skill in the effective user's scope, plus the project's when `projectId`
 * names one whose scope they decide (the owner, or a co-owner with Manage: `ownsScope`; design §6).
 * Another user's scope is never listed.
 *
 * `point=user_skill.text&group=<skill id>`: one of the effective user's own skills, its
 * proposals and its family of saved versions (lib/plugins/userSkillVersionsModel.ts);
 * another user's skill is a 404.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('override versions', 'The versions could not be read; see the webapp log.', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const url = new URL(request.url)
  const point = url.searchParams.get('point')
  const group = url.searchParams.get('group') ?? ''
  const projectId = url.searchParams.get('projectId')
  if (point === 'user_skill.text') {
    const model = await buildUserSkillVersionsModel(eff.userId, group, projectId)
    if (!model) return NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
    return NextResponse.json(model, { headers: { 'Cache-Control': 'no-store' } })
  }
  if (point !== 'skill.text') {
    return NextResponse.json({ error: 'Only skill.text and user_skill.text versions are listed here.', code: 'bad_point' }, { status: 400 })
  }
  const model = await buildVersionsModel(eff.userId, group, projectId, { actingAs: !!auth.actingAs })
  if (!model) return NextResponse.json({ error: 'No such built-in skill.', code: 'unknown_skill' }, { status: 404 })
  return NextResponse.json(model, { headers: { 'Cache-Control': 'no-store' } })
})
