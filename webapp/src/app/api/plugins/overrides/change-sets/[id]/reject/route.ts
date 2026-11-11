import { NextResponse, type NextRequest } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { getEffectiveUser, getSession } from '@/lib/session'
import { auditPlugin } from '@/lib/plugins/audit'
import { bodyOwnerMatches, ownsScope, userScopeWriteRefusal } from '@/lib/plugins/changeSetAccess'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import * as ov from '@/lib/plugins/overrides'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'

/** POST /api/plugins/overrides/change-sets/[id]/reject: a pending proposal is rejected (design §6). */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const notFound = () => NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })

export const POST = pluginRoute('override reject', 'The proposal could not be rejected; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { id } = await params
  const set = await ov.getChangeSet(id)
  if (!set || !(await ownsScope(set.scope, eff.userId))) return notFound()
  if (!bodyOwnerMatches(set.scope, eff.userId, parsed.body.scopeOwnerId)) {
    return NextResponse.json({ error: 'This version does not belong to the user you are acting as.', code: 'wrong_owner' }, { status: 403 })
  }
  const notAccountWriter = await userScopeWriteRefusal(set.scope)
  if (notAccountWriter) return notAccountWriter

  const session = await getSession()
  const actor = session?.userId ?? eff.userId
  try {
    await ov.reject(id, actor)
  } catch (e) {
    if (e instanceof ov.PluginOverrideError) {
      if (e.code === 'not_found') return notFound()
      if (e.code === 'wrong_state') {
        return NextResponse.json({ error: 'This proposal was already decided.', code: 'already_decided' }, { status: 409 })
      }
      return NextResponse.json({ error: e.message, code: e.code }, { status: 409 })
    }
    throw e
  }
  await auditPlugin('plugin.override.reject', {
    actorId: actor,
    pluginId: set.pluginId,
    targetType: 'plugin_change_set',
    targetId: id,
    after: {
      point: set.point,
      targetGroup: set.targetGroup,
      scope: set.scope.type,
      scopeId: set.scope.id,
      ...(session && session.userId !== eff.userId ? { onBehalfOf: eff.userId } : {}),
    },
    source: 'ui',
  })
  return NextResponse.json({ rejected: true })
})
