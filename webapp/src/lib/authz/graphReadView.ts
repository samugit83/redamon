/**
 * What a reader of a project's graph gets of it (step 4.6; SH-07, NF-10): the one place every
 * graph output a collaborator can reach passes its nodes through, after the read and after the
 * cache, so a rule about what a reader may see is written once.
 *
 * Every access reads the owner's graph (feature document §6.2): the tenant is the project, never
 * the caller. A reader whose access reaches `R*` (the owner, a share with Raw data & files,
 * break-glass) gets it whole. Below `R*` (a Read share without Raw data, oversight) the view
 * (step 4.9; SH-30):
 *   - takes the chain-step content off the chain nodes, and the raw-data properties of any node
 *     (`stripStepContent`; RAW_DATA_GRAPH_PROPS is empty while OQ-R7 is open);
 *   - withholds a saved view's tabular rows (format.ts shape 2, `type: 'QueryResult'`). A column is
 *     any expression the query wrote: `s.thought`, the same under an alias, a function of it, a map
 *     projection, a list or path of whole nodes. No rule over the answer tells them apart, so a
 *     reader without Raw data gets the graph-shaped rows of a view only.
 *
 * A view that changes the nodes changes `etag` too, by a suffix naming what this view leaves out:
 * GET /api/graph answers 304 to a browser holding the etag it sent, so a reader whose access shrank
 * would otherwise keep the full graph it cached, and a release that strips more must not answer 304
 * to a browser holding the old view. A view that changed nothing keeps the etag: its body is the
 * same. It never writes into the graph it was given: the cached copy is shared by every reader of
 * the project.
 */
import { createHash } from 'crypto'
import type { ProjectAccess } from './projectAccess'
import {
  RAW_DATA_GRAPH_PROPS, STEP_CONTENT_BY_LABEL, readsStepContent, stripStepContent, type StepContentNode,
} from './stepContent'

export interface GraphPayload {
  nodes: readonly unknown[]
  links: readonly unknown[]
  etag?: string
}

/** The type format.ts gives the virtual node it builds for each tabular row of a saved view. */
export const TABULAR_ROW_TYPE = 'QueryResult'

export const READ_VIEW_ETAG_SUFFIX = '-r' + createHash('sha256')
  .update(JSON.stringify([STEP_CONTENT_BY_LABEL, RAW_DATA_GRAPH_PROPS, TABULAR_ROW_TYPE]))
  .digest('hex')
  .slice(0, 8)

function isTabularRow(node: unknown): boolean {
  return !!node && typeof node === 'object' && (node as { type?: unknown }).type === TABULAR_ROW_TYPE
}

/** The graph as `access` may read it; null (no project checked) reads as below `R*`. */
export function graphReadView<G extends GraphPayload>(graph: G, access: ProjectAccess | null): G {
  if (readsStepContent(access)) return graph
  const all = graph.nodes as StepContentNode[]
  const graphRows = all.filter(node => !isTabularRow(node))
  const nodes = stripStepContent(graphRows, access)
  if (graphRows.length === all.length && nodes === graphRows) return graph
  const view = { ...graph, nodes } as G
  if (typeof graph.etag === 'string') view.etag = graph.etag + READ_VIEW_ETAG_SUFFIX
  return view
}
