import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginAllowedFor } from '@/lib/plugins/accessRules'
import { isValidPluginId } from '@/lib/plugins/ids'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { buildPluginDetail, viewerIsAdmin } from '@/lib/plugins/pageModel'
import { getSession } from '@/lib/session'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/[pluginId]: one plugin's entry; versions on disk, data usage and rollback for an admin.
 * A plugin the Plugins page hides from the viewer (accessRules.ts) is not known to them either.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('plugin details', "The plugin's details could not be read; see the webapp log.", async (
  request: NextRequest,
  { params }: { params: Promise<{ pluginId: string }> },
) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const user = await requireEffectiveUser()
  if (user instanceof NextResponse) return user
  const { pluginId } = await params
  if (!isValidPluginId(pluginId)) {
    return NextResponse.json({ error: 'Invalid plugin id.', code: 'invalid_plugin_id' }, { status: 400 })
  }
  const session = await getSession()
  const managesPlugins = !!session && (await viewerIsAdmin(session.userId))
  const shown = managesPlugins || (await pluginAllowedFor(user.userId, pluginId))
  const out = shown ? await buildPluginDetail(pluginId, managesPlugins) : null
  if (!out) return NextResponse.json({ error: `Plugin ${pluginId} is not known.`, code: 'not_found' }, { status: 404 })
  return NextResponse.json(out, { headers: { 'Cache-Control': 'no-store' } })
})
