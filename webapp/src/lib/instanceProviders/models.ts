import { instanceModelId, listingRowOf, type InstanceLlmProviderRecord } from './rows'

/** The agent's Agent in the Loop group: never an instance provider's model. */
const LOOP_GROUP = 'Agent in the Loop'
const isLoopId = (id: unknown): boolean => typeof id === 'string' && id.trim().startsWith('loop/')

export type ModelGroups = Record<string, Array<Record<string, unknown> & { id: string }>>

/**
 * The pickers' groups for the instance providers a person may use (step 6.11). The agent lists each
 * provider's models as it lists a user row's (`listOne`, its POST /models on the internal network,
 * the key in the body as for the person's own rows), and each id becomes
 * `instance/<providerId>/<id>`, the only id the agent builds from an instance row. One group per
 * provider, named after it; the loop group the agent adds to every answer is dropped.
 */
export async function instanceModelGroups(
  providers: readonly InstanceLlmProviderRecord[],
  listOne: (rows: Record<string, unknown>[]) => Promise<ModelGroups>,
): Promise<ModelGroups> {
  const listed = await Promise.all(providers.map(async (p) => ({ p, groups: await listOne([listingRowOf(p)]) })))
  const out: ModelGroups = {}
  for (const { p, groups } of listed) {
    const models = Object.entries(groups)
      .filter(([group]) => group !== LOOP_GROUP)
      .flatMap(([, list]) => (Array.isArray(list) ? list : []))
      .filter((m) => m && typeof m.id === 'string' && m.id && !isLoopId(m.id))
      .map((m) => ({ ...m, id: instanceModelId(p.id, m.id) }))
    let name = `Instance: ${p.name}`
    if (name in out) name = `${name} (${p.id})`
    out[name] = models
  }
  return out
}
