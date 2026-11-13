import { NextResponse, type NextRequest } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { accessRulesView, saveAccessRules } from '@/lib/plugins/accessRuleAdmin'
import { allowlistsInForce } from '@/lib/plugins/accessRules'
import { isValidPluginId } from '@/lib/plugins/ids'
import { errorResponse, pluginRoute, requirePluginAdmin } from '@/lib/plugins/lifecycleRoutes'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { getSession } from '@/lib/session'

/**
 * GET and PUT /api/plugins/[pluginId]/access-rules (GV-16): the member permission sets a plugin is
 * limited to, and the sets a rule may name (lib/plugins/accessRuleAdmin.ts). platform:plugins, the
 * account read again from the database as on every plugin admin route; PUT `{setIds}` is same-origin
 * JSON. With RBAC_GOVERNANCE_ENABLED off the rules are ignored, and these routes do not exist (404).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

type Params = { params: Promise<{ pluginId: string }> }

const notFound = () => errorResponse(404, 'not_found', 'Not found')

export const GET = pluginRoute('access rules read', "The plugin's access rules could not be read; see the webapp log.", async (
  _request: NextRequest,
  { params }: Params,
) => {
  if (!allowlistsInForce()) return notFound()
  const admin = await requirePluginAdmin()
  if (admin instanceof NextResponse) return admin
  const { pluginId } = await params
  if (!isValidPluginId(pluginId)) return notFound()
  return NextResponse.json(await accessRulesView(pluginId), { headers: { 'Cache-Control': 'no-store' } })
})

export const PUT = pluginRoute('access rules change', "The plugin's access rules could not be saved; see the webapp log.", async (
  request: NextRequest,
  { params }: Params,
) => {
  if (!allowlistsInForce()) return notFound()
  const admin = await requirePluginAdmin()
  if (admin instanceof NextResponse) return admin
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const { pluginId } = await params
  if (!isValidPluginId(pluginId)) return notFound()
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const session = await getSession()
  if (!session) return errorResponse(401, 'unauthorized', 'Sign in first.')
  return saveAccessRules(request, session, pluginId, parsed.body)
})
