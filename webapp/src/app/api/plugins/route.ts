import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { buildPluginsPage, viewerIsAdmin } from '@/lib/plugins/pageModel'
import { getSession } from '@/lib/session'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins: the Plugins page model (lib/plugins/pageModel.ts) for whoever holds
 * plugins:use; management details only for whoever holds platform:plugins, read fresh from the database.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('plugins page', 'The Plugins page could not be read; see the webapp log.', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const user = await requireEffectiveUser()
  if (user instanceof NextResponse) return user
  const session = await getSession()
  const managesPlugins = !!session && (await viewerIsAdmin(session.userId))
  return NextResponse.json(await buildPluginsPage(managesPlugins), { headers: { 'Cache-Control': 'no-store' } })
})
