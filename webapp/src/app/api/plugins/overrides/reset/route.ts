import { NextResponse, type NextRequest } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { getEffectiveUser, getSession } from '@/lib/session'
import { auditPlugin } from '@/lib/plugins/audit'
import { isBuiltinSkill } from '@/lib/plugins/builtinSkills'
import { bodyOwnerMatches, scopeRefusal, scopeRefusalResponse, userScopeWriteRefusal } from '@/lib/plugins/changeSetAccess'
import { internalErrorResponse, pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import * as ov from '@/lib/plugins/overrides'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requirePermission } from '@/lib/authz/guards'

/**
 * POST /api/plugins/overrides/reset: the scope's active version of a skill becomes `cleared`,
 * so factory text (or, for a project, the owner's user-scope version) runs again (design §6;
 * TD-18, OQ-23). Core UI, so it works whatever state the plugin is in — disabled, uninstalled
 * with data kept — because it never touches the plugin. Only the scope owner, or an admin
 * acting as them, or on a project a co-owner with Manage (step 5.10); a user-scope reset carries
 * the scope owner id (X9) and follows the account write rule (HD-23).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

export const POST = pluginRoute('override reset', 'The skill could not be reset; see the webapp log.', async (request: NextRequest) => {
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const auth = await requirePermission(request, 'plugins:approve_overrides')
  if (auth instanceof NextResponse) return auth
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const body = parsed.body
  const group = body.group
  const scopeType = body.scopeType
  if (body.point !== 'skill.text' || !isBuiltinSkill(group)) {
    return NextResponse.json({ error: 'A skill.text reset names a built-in skill.', code: 'bad_request' }, { status: 400 })
  }
  let scope: ov.OverrideScope
  if (scopeType === 'user') {
    scope = { type: 'user', id: typeof body.scopeOwnerId === 'string' ? body.scopeOwnerId : eff.userId }
  } else if (scopeType === 'project') {
    if (typeof body.projectId !== 'string' || !body.projectId) {
      return NextResponse.json({ error: 'A project reset needs projectId.', code: 'bad_request' }, { status: 400 })
    }
    scope = { type: 'project', id: body.projectId }
  } else {
    return NextResponse.json({ error: 'scopeType is user or project.', code: 'bad_request' }, { status: 400 })
  }

  if (!bodyOwnerMatches(scope, eff.userId, isObj(body) ? body.scopeOwnerId : undefined)) {
    return NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
  }
  const refused = await scopeRefusal(scope, eff.userId, { actingAs: !!auth.actingAs })
  if (refused) return scopeRefusalResponse(refused, 'plugins:approve_overrides')
  const notAccountWriter = await userScopeWriteRefusal(scope)
  if (notAccountWriter) return notAccountWriter

  const session = await getSession()
  const actor = session?.userId ?? eff.userId
  const result = await ov.reset(scope, 'skill.text', group, actor)
  if (result) {
    // The reset is done: a failure reading the set for its audit entry must not read as a
    // failed reset, which a retry would then find already cleared.
    let pluginId: string
    try {
      pluginId = (await ov.getChangeSet(result.changeSetId))?.pluginId ?? 'unknown'
    } catch (e) {
      return internalErrorResponse(e, 'override reset audit', 'The skill was reset, but its audit entry could not be written; see the webapp log.', {
        committed: true,
        cleared: true,
        revision: result.revision,
      })
    }
    await auditPlugin('plugin.override.reset', {
      actorId: actor,
      pluginId,
      targetType: 'plugin_change_set',
      targetId: result.changeSetId,
      after: { point: 'skill.text', targetGroup: group, scope: scope.type, scopeId: scope.id, clearedRevision: result.revision },
      source: 'ui',
    })
  }
  return NextResponse.json({ cleared: !!result, revision: result?.revision ?? null })
})
