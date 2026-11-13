/**
 * What a reader of a project's graph gets of it (step 4.6; SH-07, NF-10): the one place every
 * graph output a collaborator can reach passes its nodes through, after the read and after the
 * cache, so a rule about what a reader may see is written once.
 *
 * Every access reads the owner's graph as it is today: the read areas give a Read collaborator,
 * an overseer and break-glass the graph (feature document §6.2), and the tenant was already the
 * project (every graph read filters on `project_id`, never on the caller). What a reader without
 * Raw data & files loses is decided in step 4.9: chain step content, and the recon-found secret
 * values of DISPLAY_ONLY_PROPS (OQ-R7, open with the owner).
 *
 * A view that changes the nodes must change `etag` too (one suffix per kind of view): GET
 * /api/graph answers 304 to a browser holding the etag it sent, so a reader whose access shrank
 * would keep the full graph it cached. It never writes into the graph it was given: the cached
 * copy is shared by every reader of the project.
 */
import type { ProjectAccess } from './projectAccess'

export interface GraphPayload {
  nodes: readonly unknown[]
  links: readonly unknown[]
  etag?: string
}

/** The graph as `access` may read it; null (no project checked) reads as not the owner. */
export function graphReadView<G extends GraphPayload>(graph: G, _access: ProjectAccess | null): G {
  return graph
}
