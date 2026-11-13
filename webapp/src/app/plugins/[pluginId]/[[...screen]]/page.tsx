import { notFound } from 'next/navigation'
import { rbacFlags } from '@/lib/authz/flags'
import { pluginAllowedFor } from '@/lib/plugins/accessRules'
import { resolveNavScreen } from '@/lib/plugins/navScreens'
import { getEffectiveUser } from '@/lib/session'
import { PluginNavClient } from './PluginNavClient'

/**
 * /plugins/<pluginId>[/<screen...>]: a plugin's own page (design §6 `nav` point). Static
 * siblings such as /plugins/external-link take precedence, which is why those names are
 * reserved plugin ids. The strict CSP for these paths is set by the middleware.
 */
export const dynamic = 'force-dynamic'

/** A plugin the viewer may not use (accessRules.ts) has no page for them, as it has no nav entry. */
async function viewerMayOpen(pluginId: string): Promise<boolean> {
  if (!rbacFlags().governance) return true
  const eff = await getEffectiveUser()
  return !!eff && (await pluginAllowedFor(eff.userId, pluginId))
}

export default async function PluginNavPage({
  params,
  searchParams,
}: {
  params: Promise<{ pluginId: string; screen?: string[] }>
  searchParams: Promise<{ k?: string | string[] }>
}) {
  const { pluginId, screen } = await params
  const nav = await resolveNavScreen(pluginId, screen)
  if (!nav || !(await viewerMayOpen(pluginId))) notFound()
  const { k } = await searchParams
  return <PluginNavClient nav={nav} handoffKey={typeof k === 'string' ? k : null} />
}
