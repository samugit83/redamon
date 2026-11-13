import { NextResponse, type NextRequest } from 'next/server'
import { getEffectiveUser } from '@/lib/session'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { buildSummaryModel } from '@/lib/plugins/summaryModel'
import { scopeRefusal, scopeRefusalResponse } from '@/lib/plugins/changeSetAccess'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/overrides/summary?projectId=<id>: per built-in skill, the plugin version
 * that governs this project, whether it applies, and the pending count — so project settings
 * can show a chip, Versions and Reset only where something applies (design §6). Only whoever
 * decides the project's proposals reads it (the owner, a co-owner with Manage; step 5.10); a
 * collaborator below Manage gets the 403 naming `plugins:use` and level M, which the Agent Skills
 * section reads as "no plugin facts", like a person without `plugins:use`; another's is a 404.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('override summary', 'The plugin skill versions could not be read; see the webapp log.', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const projectId = new URL(request.url).searchParams.get('projectId')
  if (!projectId) return NextResponse.json({ error: 'projectId is required.', code: 'bad_request' }, { status: 400 })
  const opts = { actingAs: !!auth.actingAs }
  const refused = await scopeRefusal({ type: 'project', id: projectId }, eff.userId, opts)
  if (refused) return scopeRefusalResponse(refused, 'plugins:use')
  const model = await buildSummaryModel(eff.userId, projectId, opts)
  if (!model) return NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
  return NextResponse.json(model, { headers: { 'Cache-Control': 'no-store' } })
})
