import { NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { buildPluginsPage, viewerIsAdmin } from '@/lib/plugins/pageModel'
import { getSession } from '@/lib/session'

/**
 * GET /api/plugins: the Plugins page model (lib/plugins/pageModel.ts) for any signed-in
 * user; management details only for whoever holds platform:plugins, read fresh from the database.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('plugins page', 'The Plugins page could not be read; see the webapp log.', async () => {
  const user = await requireEffectiveUser()
  if (user instanceof NextResponse) return user
  const session = await getSession()
  const managesPlugins = !!session && (await viewerIsAdmin(session.userId))
  return NextResponse.json(await buildPluginsPage(managesPlugins), { headers: { 'Cache-Control': 'no-store' } })
})
