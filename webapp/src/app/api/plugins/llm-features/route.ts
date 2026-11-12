import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { listPluginLlmFeatures } from '@/lib/plugins/pluginLlmFeatures'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/llm-features: the plugin tiles of Models by feature,
 * `[{featureId, pluginId, label, description}]`. Any signed-in user: each saves the
 * choice for their own account.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('llm features', 'The plugin model features could not be read; see the webapp log.', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  return NextResponse.json(await listPluginLlmFeatures(), { headers: { 'Cache-Control': 'no-store' } })
})
