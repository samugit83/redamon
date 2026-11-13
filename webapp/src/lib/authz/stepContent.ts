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
 * `reason` for asking it. An `exploit_success` `ChainFinding` carries `commands_used` (the
 * Metasploit console lines word for word, the same text `tool_args_summary` holds) and `password`
 * (the credential the step cracked); an `AttackChain` carries `final_outcome`, the model's own
 * completion reason (chain_graph_writer.py). The structure stays: ids, chain, iteration, phase, tool
 * name, success, duration, agent, failure and decision types, who decided, the timestamps. The rest
 * of a `ChainFinding` (title, evidence, module, target, username) is a finding, readable at Read.
 *
 * One helper for every output that serialises chain-node properties: `/api/graph` and
 * graph-views/execute (through graphReadView.ts), `versions/[versionId]/graph`, the delta of two
 * versions, the export's `neo4j/nodes.json`, and the MCP query tools (step 4.10). `stripStepContent(nodes, access)`
 * answers the same array when the access reaches `R*` (the owner, a share with Raw data & files,
 * break-glass) or when no node holds a raw property; otherwise a copy in which only the nodes that
 * held one are new objects. The input is never changed, so a cached graph stays whole for the next
 * reader.
 */
import { DISPLAY_ONLY_PROPS } from '@/lib/secrets/secretProps'
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
  ChainFinding: Object.freeze(['commands_used', 'password']),
  AttackChain: Object.freeze(['final_outcome']),
})

/**
 * Node properties beyond step content that are raw data too: `anyNode` on every node, `byLabel`
 * only on a node with that label (a key that is a secret on one label and ordinary text on another).
 */
export interface RawGraphProps {
  readonly anyNode: readonly string[]
  readonly byLabel: Readonly<Record<string, readonly string[]>>
}

/**
 * OQ-R7 option (a): the recon-found secret values and the links with a secret left in them
 * (`DISPLAY_ONLY_PROPS`, lib/secrets/secretProps.ts) on any node, and a `Secret` node's
 * `matched_text`, JS Recon's full match (graph_db js_recon_mixin.py). `isSecretValueProp` calls
 * `matched_text` a secret value on a Secret only; on a Vulnerability it is the evidence a template
 * matched, readable at Read.
 */
export const OQ_R7_OPTION_A: RawGraphProps = Object.freeze({
  anyNode: Object.freeze([...DISPLAY_ONLY_PROPS]),
  byLabel: Object.freeze({ Secret: Object.freeze(['matched_text']) }),
})

/**
 * What a reader below `R*` loses beyond step content: `RAW_DATA_GRAPH_PROPS` on any node,
 * `RAW_DATA_GRAPH_PROPS_BY_LABEL` on a node with that label. Option (b) of OQ-R7, the pinned
 * current choice: nothing, the recon-found secret values stay visible at Read as the read areas are
 * written (§6.2). Option (a) sets them to `OQ_R7_OPTION_A.anyNode` and `OQ_R7_OPTION_A.byLabel`.
 * Every output that goes through `stripStepContent` follows them: `/api/graph`,
 * graph-views/execute, `versions/[versionId]/graph`, the delta of two versions
 * (`projects/[id]/delta`: its nodes, previous properties and overlay), the export's
 * `neo4j/nodes.json` and the MCP query tools. They do not reach the Insights redzone routes, which
 * project the values into columns of their own (`secrets`, `routeExposure`, `paramMatrix`), nor
 * the reports: option (a) needs its own change there.
 */
export const RAW_DATA_GRAPH_PROPS: readonly string[] = Object.freeze([])
export const RAW_DATA_GRAPH_PROPS_BY_LABEL: Readonly<Record<string, readonly string[]>> = Object.freeze({})

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
  return withoutRawProps(nodes, { anyNode: RAW_DATA_GRAPH_PROPS, byLabel: RAW_DATA_GRAPH_PROPS_BY_LABEL })
}

function labelsOf(node: StepContentNode): readonly string[] {
  if (Array.isArray(node.labels)) return node.labels
  return typeof node.type === 'string' ? [node.type] : []
}

function byLabelOf(node: StepContentNode, map: Readonly<Record<string, readonly string[]>>): readonly string[] {
  return labelsOf(node).flatMap(label => (Object.hasOwn(map, label) ? map[label] : []))
}

/**
 * The nodes without their step content and without `rawProps`: the same array when no node held
 * one. Exported for the OQ-R7 test, which runs option (a) through it.
 */
export function withoutRawProps<N extends StepContentNode>(nodes: N[], rawProps: RawGraphProps): N[] {
  let changed = false
  const out = nodes.map(node => {
    const properties = node?.properties
    if (!properties || typeof properties !== 'object') return node
    const held = [...byLabelOf(node, STEP_CONTENT_BY_LABEL), ...rawProps.anyNode, ...byLabelOf(node, rawProps.byLabel)]
      .filter(key => Object.hasOwn(properties, key))
    if (held.length === 0) return node
    changed = true
    const kept = { ...properties }
    for (const key of held) delete kept[key]
    return { ...node, properties: kept }
  })
  return changed ? out : nodes
}
