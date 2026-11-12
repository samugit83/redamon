import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { isValidPluginId } from '@/lib/plugins/ids'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { buildPluginDetail, viewerIsAdmin } from '@/lib/plugins/pageModel'
import { getSession } from '@/lib/session'

/** GET /api/plugins/[pluginId]: one plugin's entry; versions on disk, data usage and rollback for an admin. */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('plugin details', "The plugin's details could not be read; see the webapp log.", async (
  _request: NextRequest,
  { params }: { params: Promise<{ pluginId: string }> },
) => {
  const user = await requireEffectiveUser()
  if (user instanceof NextResponse) return user
  const { pluginId } = await params
  if (!isValidPluginId(pluginId)) {
    return NextResponse.json({ error: 'Invalid plugin id.', code: 'invalid_plugin_id' }, { status: 400 })
  }
  const session = await getSession()
  const managesPlugins = !!session && (await viewerIsAdmin(session.userId))
  const out = await buildPluginDetail(pluginId, managesPlugins)
  if (!out) return NextResponse.json({ error: `Plugin ${pluginId} is not known.`, code: 'not_found' }, { status: 404 })
  return NextResponse.json(out, { headers: { 'Cache-Control': 'no-store' } })
})
