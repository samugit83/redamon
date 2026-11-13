/**
 * Attack-chain step content is raw data (§6.6, SH-30): a reader below `R*` sees a chain's structure
 * and findings, never what the agent thought, ran or got back.
 *
 * The agent writes the content on `ChainStep` nodes (agentic/orchestrator_helpers/chain_graph_writer.py):
 * `thought`, `reasoning`, `output_summary`, `output_analysis`, plus `tool_args_summary` (the command
 * line, which can carry credentials and target paths) and `error_message` (a failed tool's output).
 * Two other chain nodes carry copies of it, so they lose them too: a failed step's `ChainFailure`
 * holds the same `error_message` and, as `lesson_learned`, the step's `output_analysis`
 * (think_node.py writes both from the step); a phase change's `ChainDecision` holds the agent's
 * `reason` for asking it. The structure stays: ids, chain, iteration, phase, tool name, success,
 * duration, agent, failure and decision types, who decided, the timestamps. `ChainFinding`s are
 * findings, readable at Read.
 *
 * One helper for every output that serialises chain-node properties: `/api/graph` and
 * graph-views/execute (through graphReadView.ts), `versions/[versionId]/graph`, the export's
 * `neo4j/nodes.json`, and the MCP query tools (step 4.10). `stripStepContent(nodes, access)`
 * answers the same array when the access reaches `R*` (the owner, a share with Raw data & files,
 * break-glass) or when no node holds a raw property; otherwise a copy in which only the nodes that
 * held one are new objects. The input is never changed, so a cached graph stays whole for the next
 * reader.
 */
import { meetsLevel, type ProjectAccess } from './projectAccess'

export const STEP_CONTENT_LABEL = 'ChainStep'

export const STEP_CONTENT_PROPS: readonly string[] = Object.freeze([
  'thought',
  'reasoning',
  'output_summary',
  'output_analysis',
  'tool_args_summary',
  'error_message',
])

/** The content each chain label carries; a label not named here keeps every property. */
export const STEP_CONTENT_BY_LABEL: Readonly<Record<string, readonly string[]>> = Object.freeze({
  [STEP_CONTENT_LABEL]: STEP_CONTENT_PROPS,
  ChainFailure: Object.freeze(['error_message', 'lesson_learned']),
  ChainDecision: Object.freeze(['reason']),
})

/**
 * Properties of any node that are raw data as well, taken from the same readers on the same outputs.
 *
 * Empty: the recon-found secret values and the links with a secret left in them (`DISPLAY_ONLY_PROPS`,
 * lib/secrets/secretProps.ts) stay visible at Read, as the read areas are written (§6.2). OQ-R7 is
 * open with the owner: whether they are Raw data. Its option (a) is this one line,
 * `Object.freeze([...DISPLAY_ONLY_PROPS])`, for the outputs above; the Insights redzone routes that
 * project them into columns of their own (`secrets`, `routeExposure`, `paramMatrix`) and the reports
 * are not graph nodes and would need their own change.
 */
export const RAW_DATA_GRAPH_PROPS: readonly string[] = Object.freeze([])

/**
 * A graph node as an output serialises it: `type` is the label in the render shape (`/api/graph`,
 * the snapshot payload, a saved view); the export and the MCP tools give `labels`.
 */
export interface StepContentNode {
  type?: string
  labels?: readonly string[]
  properties: Record<string, unknown>
}

/** Whether the access may read step content; null (no project decided) may not. */
export function readsStepContent(access: Pick<ProjectAccess, 'level' | 'toggles'> | null | undefined): boolean {
  return !!access && meetsLevel(access as ProjectAccess, 'R*')
}

export function stripStepContent<N extends StepContentNode>(nodes: N[], access: Pick<ProjectAccess, 'level' | 'toggles'> | null | undefined): N[] {
  if (readsStepContent(access)) return nodes
  return withoutRawProps(nodes, RAW_DATA_GRAPH_PROPS)
}

function labelsOf(node: StepContentNode): readonly string[] {
  if (Array.isArray(node.labels)) return node.labels
  return typeof node.type === 'string' ? [node.type] : []
}

function stepContentOf(node: StepContentNode): readonly string[] {
  return labelsOf(node).flatMap(label => (Object.hasOwn(STEP_CONTENT_BY_LABEL, label) ? STEP_CONTENT_BY_LABEL[label] : []))
}

/**
 * The nodes without their step content and without `rawProps` on any node: the same array when no
 * node held one. Exported for the OQ-R7 test, which runs option (a)'s list through it.
 */
export function withoutRawProps<N extends StepContentNode>(nodes: N[], rawProps: readonly string[]): N[] {
  let changed = false
  const out = nodes.map(node => {
    const properties = node?.properties
    if (!properties || typeof properties !== 'object') return node
    const held = [...stepContentOf(node), ...rawProps].filter(key => Object.hasOwn(properties, key))
    if (held.length === 0) return node
    changed = true
    const kept = { ...properties }
    for (const key of held) delete kept[key]
    return { ...node, properties: kept }
  })
  return changed ? out : nodes
}
