import { NextResponse, type NextRequest } from 'next/server'
import { auditActor } from '@/lib/auditActor'
import { getEffectiveUser } from '@/lib/session'
import { auditPlugin } from '@/lib/plugins/audit'
import { ownsScope, scopeRefusal, scopeRefusalResponse, userScopeWriteRefusal } from '@/lib/plugins/changeSetAccess'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import * as ov from '@/lib/plugins/overrides'
import { buildReviewModel } from '@/lib/plugins/reviewModel'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/overrides/change-sets/[id]: the review model (lib/plugins/reviewModel.ts).
 * DELETE /api/plugins/overrides/change-sets/[id]: deletes a non-active version.
 * Only whoever decides the scope may read or delete: the scope owner (or an admin acting as them),
 * or on a project scope a co-owner with Manage (step 5.10); another user's set is a 404 (X9), and
 * a collaborator below Manage reads a 404 and is told the level when deleting.
 * Deleting a user-scope version also follows the account write rule (HD-23).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const notFound = () => NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })

export const GET = pluginRoute('override review read', 'The proposal could not be read; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const { id } = await params
  const set = await ov.getChangeSet(id)
  if (!set || !(await ownsScope(set.scope, eff.userId, { actingAs: !!auth.actingAs }))) return notFound()
  // A project the scope owner owns only (the model reads it with that owner): the review of
  // a user-skill proposal opened from a project shows that project's toggles.
  const model = await buildReviewModel(id, { projectId: new URL(request.url).searchParams.get('projectId') })
  if (!model) return notFound()
  return NextResponse.json(model, { headers: { 'Cache-Control': 'no-store' } })
})

export const DELETE = pluginRoute('override delete', 'The version could not be deleted; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const auth = await requirePermission(request, 'plugins:approve_overrides')
  if (auth instanceof NextResponse) return auth
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const { id } = await params
  const set = await ov.getChangeSet(id)
  if (!set) return notFound()
  const refused = await scopeRefusal(set.scope, eff.userId, { actingAs: !!auth.actingAs })
  if (refused) return scopeRefusalResponse(refused, 'plugins:approve_overrides')
  const notAccountWriter = await userScopeWriteRefusal(set.scope)
  if (notAccountWriter) return notAccountWriter
  try {
    await ov.deleteChangeSet(id)
  } catch (e) {
    if (e instanceof ov.PluginOverrideError && e.code === 'active_not_deletable') {
      return NextResponse.json({ error: e.message, code: e.code }, { status: 409 })
    }
    if (e instanceof ov.PluginOverrideError && e.code === 'not_found') return notFound()
    throw e
  }
  const real = await auditActor(eff)
  await auditPlugin('plugin.override.delete', {
    actorId: real.actorId ?? eff.userId,
    pluginId: set.pluginId,
    targetType: 'plugin_change_set',
    targetId: id,
    after: {
      point: set.point,
      targetGroup: set.targetGroup,
      scope: set.scope.type,
      scopeId: set.scope.id,
      revision: set.revision,
      ...(real.onBehalfOfUserId ? { onBehalfOf: real.onBehalfOfUserId } : {}),
    },
    source: 'ui',
  })
  return NextResponse.json({ deleted: true })
})
