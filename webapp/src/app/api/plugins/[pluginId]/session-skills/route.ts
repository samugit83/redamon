import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { sessionRunningCheck } from '@/lib/agentSessions'
import { getEffectiveUser } from '@/lib/session'
import { strictContext } from '@/lib/plugins/actions'
import { isValidPluginId } from '@/lib/plugins/ids'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import * as ov from '@/lib/plugins/overrides'
import { findInstall, servesActions } from '@/lib/plugins/registry'
import { pickableSessionSkills } from '@/lib/plugins/sessionPick'
import { suggestedSkill } from '@/lib/plugins/sessionSkills'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/[pluginId]/session-skills?sessionId=&projectId= - the skill picker's
 * list (platform 1.1.0): the skills the session used, of the points this plugin is granted
 * and declares, with why a skill cannot be picked (deleted, credentials, quarantined),
 * whether the agent is running in the session, and the suggested pick.
 *
 * The same ownership check as an action start, and the same answers when the plugin does
 * not serve, except that an unknown plugin is `plugin_not_found`: the picker tells it from a
 * session that has no conversation yet, which is `not_found`. A built-in skill carries the
 * version that applies in the project.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const refuse = (status: number, code: string, error: string) => NextResponse.json({ error, code }, { status })

export const GET = pluginRoute('session skills', 'The skills of this session could not be read; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ pluginId: string }> },
) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const { pluginId } = await params
  if (!isValidPluginId(pluginId)) return refuse(404, 'plugin_not_found', 'No such plugin.')
  const plugin = await findInstall(pluginId)
  if (!plugin || ['available', 'installing', 'uninstalling'].includes(plugin.status)) {
    return refuse(404, 'plugin_not_found', 'No such plugin.')
  }
  if (plugin.revokedReason == null && plugin.enabled && plugin.status === 'updating') {
    return refuse(409, 'plugin_updating', 'This plugin is being updated; try again in a moment.')
  }
  if (!servesActions(plugin)) return refuse(409, 'plugin_unavailable', 'This plugin is disabled or not ready.')

  const qs = request.nextUrl.searchParams
  const sessionId = qs.get('sessionId')
  if (!sessionId) return refuse(400, 'invalid_context', 'sessionId is required')
  const context = await strictContext({ projectId: qs.get('projectId'), sessionId }, eff.userId)
  if (context instanceof NextResponse) return context
  const conversation = await prisma.conversation.findUnique({
    where: { id: context.conversationId! },
    select: { id: true, projectId: true, sessionId: true, agentRunning: true, updatedAt: true },
  })
  if (!conversation) return refuse(404, 'not_found', 'Not found')

  const [check, skills] = await Promise.all([
    sessionRunningCheck(conversation),
    pickableSessionSkills(plugin, conversation.id, eff.userId),
  ])
  const withVersions = await Promise.all(skills.map(async (s) => {
    if (s.kind !== 'builtin' || !context.projectId) return s
    const set = await ov.effectiveForProject(context.projectId, s.target).catch(() => null)
    return { ...s, revision: set && set.applies ? set.revision : ov.FACTORY_REVISION }
  }))
  // `agentCheck`: why 'unverified', so the picker can say whether the agent was down, slow or failing.
  return NextResponse.json(
    {
      running: check.running,
      ...(check.failure ? { agentCheck: check.failure } : {}),
      skills: withVersions,
      suggested: suggestedSkill(skills)?.ref ?? null,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  )
})
