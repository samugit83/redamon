/**
 * Attack-chain step content is raw data (§6.6, SH-30): a reader below `R*` sees a chain's structure
 * and findings, never what the agent thought, ran or got back.
 *
 * The agent writes the content on `ChainStep` nodes (agentic/orchestrator_helpers/chain_graph_writer.py):
 * `thought`, `reasoning`, `output_summary`, `output_analysis`, plus `tool_args_summary` (the command
 * line, which can carry credentials and target paths) and `error_message` (a failed tool's output).
 * The structure stays: ids, chain, iteration, phase, tool name, success, duration, agent and the
 * timestamps.
 *
 * One helper for every output that serialises chain-step properties (step 4.7 builds it for the
 * version graph; step 4.9 applies it to /api/graph, graph-views/execute, the export and the MCP query
 * tools): `stripStepContent(nodes, access)` answers the same array when the access reaches `R*` (the
 * owner, a share with Raw data & files, break-glass), else a copy whose `ChainStep` nodes lack those
 * properties. The input is never changed, so a cached graph stays whole for the next reader.
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

/** A rendered graph node: `/api/graph`'s and the snapshot payload's shape (`type` is the label). */
export interface StepContentNode {
  type: string
  properties: Record<string, unknown>
}

/** Whether the access may read step content; null (no project decided) may not. */
export function readsStepContent(access: Pick<ProjectAccess, 'level' | 'toggles'> | null | undefined): boolean {
  return !!access && meetsLevel(access as ProjectAccess, 'R*')
}

export function stripStepContent<N extends StepContentNode>(nodes: N[], access: Pick<ProjectAccess, 'level' | 'toggles'> | null | undefined): N[] {
  if (readsStepContent(access)) return nodes
  return nodes.map(node => {
    if (node.type !== STEP_CONTENT_LABEL || !node.properties) return node
    const properties = { ...node.properties }
    for (const key of STEP_CONTENT_PROPS) delete properties[key]
    return { ...node, properties }
  })
}
