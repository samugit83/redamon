import { capabilitiesInForce } from '@/lib/authz/can'
import { rbacFlags } from '@/lib/authz/flags'
import { loadPrincipal } from '@/lib/authz/principal'
import { agentRowOf, isInstanceProviderKind, summaryOf, type InstanceLlmProviderRecord, type InstanceProviderSummary } from './rows'
import { readByoLlmForbidden, readInstanceProviders, readProviderAssignments } from './store'

/**
 * Who may use an instance provider (step 6.11, GV-15): whoever holds a permission set the provider
 * is assigned to, and nobody else. Holding a set means being under it in the capability resolution
 * (capabilities.ts `sets`): a set assigned, the instance default set or *Default member* for a member
 * never assigned, an admin's profile. An account that is gone or not active holds none, and Root is
 * offered a provider only through a set it holds, like everyone. There is no other way in: no
 * permission, no override and no admin bypass names a provider.
 *
 * On a project the owner's entitlements decide (C1, D-06): the agent fetches the OWNER's provider
 * list for every run of the project, whoever starts it, so a collaborator spends the owner's
 * instance providers exactly as the owner's own keys, never their own.
 *
 * With RBAC_GOVERNANCE_ENABLED off no provider is offered or resolved and nothing is read (DV-30): a
 * project saved on an `instance/` model then fails closed in the agent (instance_provider_unavailable).
 * The assignments are read on every call, so a provider Root removes from a set is gone from the
 * next fetch; the person's sets come through the principal cache (RBAC_AUTHZ_CACHE_MS). A failed read
 * throws, never reads as "no provider" where it would change what the agent may use.
 */
export function instanceProvidersInForce(): boolean {
  return rbacFlags().governance
}

/** The instance providers this account may use, in creation order. */
export async function entitledInstanceProviders(userId: string): Promise<InstanceLlmProviderRecord[]> {
  if (!instanceProvidersInForce()) return []
  const assignments = await readProviderAssignments()
  if (assignments.length === 0) return []
  const principal = await loadPrincipal(userId)
  if (!principal) return []
  const held = new Set((await capabilitiesInForce(principal)).sets.map((s) => s.id))
  const ids = [...new Set(assignments.filter((a) => held.has(a.setId)).map((a) => a.providerId))]
  if (ids.length === 0) return []
  // A row of a kind the agent cannot build as a chat model never leaves the webapp.
  return (await readInstanceProviders(ids)).filter((p) => isInstanceProviderKind(p.providerType))
}

/** The same list as the person sees it: names and kinds, never a key, an endpoint or a header. */
export async function entitledProviderSummaries(userId: string): Promise<InstanceProviderSummary[]> {
  return (await entitledInstanceProviders(userId)).map(summaryOf)
}

/**
 * Whether the account's own providers are withheld from the agent: Root set `byoLlmForbidden` and
 * the account does not hold self:llm_providers. The permission already hides the list, the add and
 * the models route from such an account; this also stops the agent using rows it added before.
 */
export async function ownProvidersWithheld(userId: string): Promise<boolean> {
  if (!instanceProvidersInForce() || !(await readByoLlmForbidden())) return false
  const principal = await loadPrincipal(userId)
  if (!principal) return true
  return !(await capabilitiesInForce(principal)).has('self:llm_providers')
}

/**
 * The provider list the agent receives for `ownerId` (`?internal=true`, master key only): the
 * account's own rows, unless withheld, then one marked row per instance provider it may use.
 */
export async function agentProviderList<T>(ownerId: string, ownRows: readonly T[]): Promise<Array<T | Record<string, unknown>>> {
  if (!instanceProvidersInForce()) return [...ownRows]
  const [withheld, instance] = await Promise.all([ownProvidersWithheld(ownerId), entitledInstanceProviders(ownerId)])
  return [...(withheld ? [] : ownRows), ...instance.map((p) => agentRowOf(p, ownerId))]
}
