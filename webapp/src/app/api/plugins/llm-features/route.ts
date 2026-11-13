import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginAccessFor } from '@/lib/plugins/accessRules'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { listPluginLlmFeatures } from '@/lib/plugins/pluginLlmFeatures'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/llm-features: the plugin tiles of Models by feature,
 * `[{featureId, pluginId, label, description}]`. Any signed-in user: each saves the
 * choice for their own account, for the plugins available to them (accessRules.ts).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('llm features', 'The plugin model features could not be read; see the webapp log.', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const [features, access] = await Promise.all([listPluginLlmFeatures(), pluginAccessFor(eff.userId)])
  return NextResponse.json(features.filter((f) => access.allows(f.pluginId)), { headers: { 'Cache-Control': 'no-store' } })
})
