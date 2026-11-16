/**
 * The MCP server's graph calls into the agent.
 *
 * The MCP layer never touches Neo4j itself. It resolves a personal access token
 * to ONE user, then hands that resolved identity to the agent, where
 * `scope_query` enforces isolation server-side whatever Cypher is produced and
 * the P0-4 bounds cap the cost. This module is only the transport.
 *
 * It calls the agent DIRECTLY with the internal key, never through
 * `/api/agent/text-to-cypher`: that route is a session-authenticated proxy for
 * the browser, it returns the query rather than running it, and routing through
 * it would mean asserting a client identity we have already resolved properly.
 *
 * Every call carries an explicit timeout. An inherited unbounded default would
 * let a slow agent hold an MCP request open until the client gives up, which
 * the caller cannot distinguish from an empty answer.
 */
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { McpToolError } from '@/lib/mcp/errors'

const NL_QUERY_TIMEOUT_MS = 120_000
const EXEC_TIMEOUT_MS = 60_000
const SCHEMA_TIMEOUT_MS = 10_000

export interface GraphRecords {
  records: unknown[]
  truncated?: boolean
  cypher?: string
}

async function agentPost(path: string, body: unknown, timeoutMs: number): Promise<Response> {
  return fetch(`${agentBaseUrl()}${path}`, {
    method: 'POST',
    headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  })
}

/** Parse an agent error body into a safe, caller-facing message. */
async function agentFailure(resp: Response, context: string): Promise<never> {
  let detail: Record<string, unknown> = {}
  try {
    detail = await resp.json()
  } catch {
    // Non-JSON body: nothing safe to quote.
  }
  // The agent's own error strings are already normalised (P0-3/P0-4), so the
  // two documented ones are quoted; anything else becomes a generic line.
  const known = typeof detail.error === 'string' ? detail.error : ''
  const stage = detail.stage === 'generate' || detail.stage === 'execute' ? detail.stage : null
  // A refusal quotes the caller's query (a pattern, a name), which may be a model's: the caller
  // gets it below, the log only the status and the stage.
  console.error(`[mcp] ${context} failed status=${resp.status} stage=${stage ?? 'none'}`)

  if (stage === 'generate') {
    throw new McpToolError(
      known || 'Could not turn that question into a query. Try rephrasing it.',
      'generate_failed'
    )
  }
  if (stage === 'execute' || resp.status === 413) {
    throw new McpToolError(
      known || 'The query could not be run. Narrow it and try again.',
      'execute_failed'
    )
  }
  // /graph/exec sets no `stage`, so every refusal it writes used to be replaced
  // by the generic line below - on the one path where the agent composed the
  // query itself and could actually fix it. "write operation rejected (MERGE);
  // read-only" and "give every node pattern an explicit label" are written FOR
  // the caller; discarding them turned a one-line correction into a retry loop.
  // Only 4xx: a 5xx is the deployment's problem and its text is not the
  // caller's to act on (the agent logs the exception and returns a generic
  // string there anyway).
  if (known && resp.status >= 400 && resp.status < 500) {
    throw new McpToolError(known, 'query_rejected')
  }
  throw new McpToolError(`${context} failed.`, 'agent_failed')
}

/**
 * Natural language -> tenant-scoped rows. Generation and execution failures are
 * reported separately, so the caller retries the right half: rephrasing fixes a
 * generation failure and does nothing for an execution one.
 */
export async function nlQuery(
  userId: string,
  projectId: string,
  question: string
): Promise<GraphRecords> {
  let resp: Response
  try {
    resp = await agentPost(
      '/graph/nl-query',
      { question, user_id: userId, project_id: projectId },
      NL_QUERY_TIMEOUT_MS
    )
  } catch (err) {
    console.error('[mcp] nl-query transport error:', err)
    // NEVER an empty result: "nothing found" and "could not ask" must not look
    // the same to an agent reporting on a security surface.
    throw new McpToolError('The query service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) await agentFailure(resp, 'nl-query')
  return (await resp.json()) as GraphRecords
}

/** Run a fixed or caller-supplied read-only Cypher through /graph/exec. */
export async function execCypher(
  userId: string,
  projectId: string,
  cypher: string
): Promise<GraphRecords> {
  let resp: Response
  try {
    resp = await agentPost(
      '/graph/exec',
      {
        op: 'cypher',
        cypher,
        user_id: userId,
        project_id: projectId,
        // Opts this read into the agent's MCP concurrency ceiling, so a looping
        // external agent cannot monopolise the Neo4j pool the UI shares.
        source: 'mcp',
      },
      EXEC_TIMEOUT_MS
    )
  } catch (err) {
    console.error('[mcp] graph/exec transport error:', err)
    throw new McpToolError('The graph service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) await agentFailure(resp, 'graph query')
  return (await resp.json()) as GraphRecords
}

// The schema is static per build, so one successful fetch is enough for the
// life of the process. After that `graph_schema` genuinely cannot fail on a
// dependency, which is what makes it the tool that still answers when Neo4j
// and the database are down.
let schemaCache: string | null = null

export async function graphSchemaDoc(): Promise<string> {
  if (schemaCache) return schemaCache
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}/graph/schema-doc`, {
      headers: internalKeyHeaders(),
      signal: AbortSignal.timeout(SCHEMA_TIMEOUT_MS),
    })
  } catch (err) {
    console.error('[mcp] schema-doc transport error:', err)
    throw new McpToolError('The schema service is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) {
    console.error(`[mcp] schema-doc failed (${resp.status})`)
    throw new McpToolError('The schema could not be loaded.', 'agent_failed')
  }
  const body = (await resp.json()) as { schema?: unknown }
  if (typeof body.schema !== 'string' || !body.schema) {
    throw new McpToolError('The schema could not be loaded.', 'agent_failed')
  }
  schemaCache = body.schema
  return schemaCache
}

/** Test seam: the cache is process-global by design. */
export function __resetSchemaCache(): void {
  schemaCache = null
}
