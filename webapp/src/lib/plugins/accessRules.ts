import { capabilitiesInForce } from '@/lib/authz/can'
import { rbacFlags } from '@/lib/authz/flags'
import { loadPrincipal } from '@/lib/authz/principal'
import { readAccessRules, type PluginAccessRule } from './accessRuleStore'

/**
 * Per-plugin allowlists (GV-16, feature document §5.12). A plugin with no rule is available to
 * everyone holding plugins:use; a plugin with rules only to the people holding one of its listed
 * permission sets, and always to whoever holds platform:plugins (who manages it). The platform is
 * generic: a rule names a catalog id that comes from an admin, never from code.
 *
 * Asked for the account the plugin works for: the effective user of a browser request and the call
 * token's user (`sub`) at the Gateway. So an admin acting as someone gets what that person gets,
 * and an action already running loses the Gateway at the next call once its person loses the plugin.
 *
 * Holding a set means being under it in the capability resolution (capabilities.ts `sets`): a set
 * assigned, the instance default set or *Default member* for a member never assigned, an admin's
 * profile. An account that is gone or not active holds none.
 *
 * With RBAC_GOVERNANCE_ENABLED off the rules are ignored and nothing is read (DV-30). The rules are
 * read on every check, so a rule an admin adds applies to the next request; the person's sets come
 * through the principal cache (RBAC_AUTHZ_CACHE_MS), as for every permission. A failed read throws,
 * never reads as allowed.
 */
export interface PluginAccess {
  allows(pluginId: string): boolean
}

const EVERY_PLUGIN: PluginAccess = Object.freeze({ allows: () => true })

function setsByPlugin(rules: readonly PluginAccessRule[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()
  for (const r of rules) {
    const sets = out.get(r.pluginId)
    if (sets) sets.add(r.setId)
    else out.set(r.pluginId, new Set([r.setId]))
  }
  return out
}

async function decide(userId: string, rules: readonly PluginAccessRule[]): Promise<PluginAccess> {
  const listed = setsByPlugin(rules)
  if (listed.size === 0) return EVERY_PLUGIN
  const principal = await loadPrincipal(userId)
  const capabilities = principal ? await capabilitiesInForce(principal) : null
  if (capabilities?.has('platform:plugins')) return EVERY_PLUGIN
  const held = new Set((capabilities?.sets ?? []).map((s) => s.id))
  return Object.freeze({
    allows(pluginId: string): boolean {
      const sets = listed.get(pluginId)
      return !sets || [...sets].some((id) => held.has(id))
    },
  })
}

/** Which plugins the account may use: for a list (the Plugins page, the contributions). */
export async function pluginAccessFor(userId: string): Promise<PluginAccess> {
  if (!rbacFlags().governance) return EVERY_PLUGIN
  return decide(userId, await readAccessRules())
}

/** Whether the account may use this one plugin: reads only that plugin's rules. */
export async function pluginAllowedFor(userId: string, pluginId: string): Promise<boolean> {
  if (!rbacFlags().governance) return true
  return (await decide(userId, await readAccessRules(pluginId))).allows(pluginId)
}

/** The refusal text of a plugin an admin limited to sets the person holds none of. */
export const PLUGIN_NOT_ALLOWED_MESSAGE =
  'An administrator made this plugin available only to chosen permission sets, and you hold none of them.'
