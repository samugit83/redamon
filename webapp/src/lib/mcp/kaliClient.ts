/**
 * The MCP server's Kali calls into the agent.
 *
 * Same shape as graphClient.ts and for the same reason: the MCP layer resolves
 * a personal access token to ONE user and then hands that resolved identity to
 * the agent, which owns every decision about the kali-sandbox. The webapp holds
 * no MCP_AUTH_TOKEN and speaks no MCP to the worker, so a webapp compromise
 * does not become a channel into the target-facing tier.
 *
 * Every call carries an explicit timeout. An inherited unbounded default would
 * let a slow agent hold an MCP request open until the client gives up, which
 * the caller cannot distinguish from an empty answer.
 */
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { McpToolError } from '@/lib/mcp/errors'
import {
  KALI_EXEC_ERROR_CODES,
  MODAL_HARD_BODY,
  MODAL_RAM_BODY,
  SANDBOX_REFUSED,
  type KALI_EXEC_STATUS_STARTING,
  type KaliExecErrorCode,
} from '@/lib/sandbox/contract'

const TOOLBOX_TIMEOUT_MS = 10_000

// The catalogue is static per build (it is a constant in the agent image), so
// one successful fetch is enough for the life of the process. After that
// kali_toolbox genuinely cannot fail on a dependency, which is what makes it
// the tool that still answers when the kali-sandbox is down.
let toolboxCache: string | null = null

export async function kaliToolboxDoc(): Promise<string> {
  if (toolboxCache) return toolboxCache
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}/kali/toolbox`, {
      headers: internalKeyHeaders(),
      signal: AbortSignal.timeout(TOOLBOX_TIMEOUT_MS),
    })
  } catch (err) {
    console.error('[mcp] kali toolbox transport error:', err)
    // NEVER an empty catalogue: "this image ships no tools" and "could not ask"
    // must not look the same to an agent deciding what it can run.
    throw new McpToolError('The Kali toolbox is unavailable.', 'agent_unreachable')
  }
  if (!resp.ok) {
    console.error(`[mcp] kali toolbox failed (${resp.status})`)
    throw new McpToolError('The Kali toolbox could not be loaded.', 'agent_failed')
  }
  const body = (await resp.json()) as { toolbox?: unknown }
  if (typeof body.toolbox !== 'string' || !body.toolbox) {
    // Logged like the !resp.ok branch above. Without this the endpoint
    // answering 200 with the WRONG SHAPE left nothing in any log on either
    // side, and the only way to find it was to reproduce the fetch by hand.
    console.error(
      '[mcp] kali toolbox returned an unexpected body shape:',
      `${typeof body} ${JSON.stringify(body).slice(0, 200)}`
    )
    throw new McpToolError('The Kali toolbox could not be loaded.', 'agent_failed')
  }
  toolboxCache = body.toolbox
  return toolboxCache
}

/** Test seam: the cache is process-global by design. */
export function __resetToolboxCache(): void {
  toolboxCache = null
}

// --- exec ---------------------------------------------------------------------

/**
 * Comfortably past the agent's own KALI_EXEC_MAX_WAIT (60s) so the inline wait
 * is what ends the call, not this. A timeout here would leave the command
 * running with the caller holding no job id to poll or cancel it with.
 */
const EXEC_TIMEOUT_MS = 90_000
const POLL_TIMEOUT_MS = 30_000

/**
 * The agent's job statuses. `starting` comes with per-user sandboxes: the
 * caller's sandbox is starting and the command waits for it. A status not
 * listed here is passed on as the agent wrote it.
 */
export type KaliJobStatus =
  | typeof KALI_EXEC_STATUS_STARTING
  | 'running' | 'done' | 'failed' | 'cancelled' | 'interrupted' | 'unknown'

export interface KaliJob {
  jobId: string
  status: KaliJobStatus | (string & {})
  exitCode: number | null
  output: string
  nextCursor: number
  truncated?: boolean
  command?: string
  /** The agent's reason a finished job failed, e.g. the 300s sandbox cap. */
  failure?: string
  /** Why the job could not use its sandbox; `failure` then says it in words. */
  errorCode?: KaliExecErrorCode
  startedAt?: string | null
  endedAt?: string | null
}

function sandboxErrorCode(value: unknown): KaliExecErrorCode | undefined {
  return KALI_EXEC_ERROR_CODES.find(code => code === value)
}

/**
 * The words for a sandbox the job could not use. Only the governor's sentence
 * (`ram`, `hard`) is quoted, because it is written for the caller; a refusal
 * always reads as the contract's text, and the rest as fixed lines (errors.ts).
 */
function sandboxFailure(code: KaliExecErrorCode, upstream: unknown): string {
  const governor = typeof upstream === 'string' ? upstream.trim().slice(0, 300) : ''
  switch (code) {
    case 'ram': return governor || MODAL_RAM_BODY
    case 'hard': return governor || MODAL_HARD_BODY
    case 'sandbox_refused': return SANDBOX_REFUSED
    case 'sandbox_error': return 'The Kali sandbox could not start.'
    case 'sandbox_stopped': return 'The Kali sandbox stopped during the command.'
  }
}

/** The agent answers snake_case; the MCP surface speaks camelCase throughout. */
function toJob(raw: Record<string, unknown>): KaliJob {
  const errorCode = sandboxErrorCode(raw.error_code)
  return {
    jobId: String(raw.job_id ?? ''),
    status: String(raw.status ?? 'unknown'),
    exitCode: typeof raw.exit_code === 'number' ? raw.exit_code : null,
    output: typeof raw.output === 'string' ? raw.output : '',
    nextCursor: typeof raw.next_cursor === 'number' ? raw.next_cursor : 0,
    ...(raw.truncated ? { truncated: true } : {}),
    ...(typeof raw.command === 'string' ? { command: raw.command } : {}),
    // WHY a finished job failed. Dropping it left "exitCode 1" with no reason,
    // and the most common reason is the sandbox's 300s cap - which an agent
    // can only act on if it is told.
    ...(errorCode
      ? { errorCode, failure: sandboxFailure(errorCode, raw.error) }
      : typeof raw.error === 'string' && raw.error ? { failure: raw.error } : {}),
    startedAt: (raw.started_at as string) ?? null,
    endedAt: (raw.ended_at as string) ?? null,
  }
}

/**
 * Turn an agent failure into a caller-facing message.
 *
 * A 400 carries the admission refusal, which is written FOR the caller and says
 * what to change; it is the one upstream message quoted verbatim. Everything
 * else becomes a fixed line, per the errors.ts rule.
 */
async function execFailure(resp: Response): Promise<never> {
  let detail: Record<string, unknown> = {}
  try {
    detail = await resp.json()
  } catch {
    // Non-JSON body: nothing safe to quote.
  }
  const message = typeof detail.error === 'string' ? detail.error : ''

  // A sandbox the command could not use, answered as an error rather than as a
  // failed job. Only the message reaches the MCP caller, so it names the code.
  const code = sandboxErrorCode(detail.error_code)
  if (code && (resp.status < 500 || resp.status === 503)) {
    throw new McpToolError(`${sandboxFailure(code, message)} (errorCode: ${code})`, code)
  }

  if (resp.status === 400) {
    throw new McpToolError(message || 'That command was refused.', 'refused')
  }
  // 404 is deliberately NOT quoted: the agent says "no such command" for a
  // missing job and for another project's job alike, and that sameness is the
  // anti-enumeration property.
  if (resp.status === 404) throw new McpToolError('No such command.', 'not_found')
  if (resp.status === 429) {
    throw new McpToolError(
      message || 'The sandbox is busy. Retry shortly.',
      'sandbox_busy'
    )
  }
  if (resp.status === 503) {
    throw new McpToolError(message || 'The sandbox is unavailable.', 'sandbox_unavailable')
  }
  // Any OTHER 4xx: the agent is telling the caller something it can act on, and
  // the enumerated branches above cannot be the complete list forever. The
  // cancel endpoint already answers 409 with the reason a job could not be
  // stopped, and that reason was being replaced by a flat "could not be run" -
  // the same defect a sibling session found in graphClient.ts, where a refusal
  // the caller could have fixed was collapsed into five generic words.
  //
  // 5xx still degrades: those bodies are raw exception text (host paths, image
  // names), which errors.ts forbids returning.
  if (resp.status < 500 && message) {
    console.error(`[mcp] kali exec ${resp.status}:`, message.slice(0, 200))
    throw new McpToolError(message, 'agent_refused')
  }
  console.error(`[mcp] kali exec failed (${resp.status}):`, JSON.stringify(detail))
  throw new McpToolError('The command could not be run.', 'agent_failed')
}

async function agentJson(
  path: string,
  init: RequestInit,
  timeoutMs: number,
  what: string
): Promise<KaliJob> {
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}${path}`, {
      ...init,
      headers: internalKeyHeaders(
        init.body ? { 'Content-Type': 'application/json' } : {}
      ),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    console.error(`[mcp] kali ${what} transport error:`, err)
    // Never an empty result: a command whose outcome is unknown must not read
    // as a command that produced nothing.
    throw new McpToolError('The sandbox is unreachable.', 'agent_unreachable')
  }
  if (!resp.ok) await execFailure(resp)
  return toJob((await resp.json()) as Record<string, unknown>)
}

/**
 * `userId` is the person whose own sandbox runs the command: the token's owner,
 * never the project's owner, who is only the tenant whose folder it runs on.
 */
export async function kaliExec(
  projectId: string,
  command: string,
  waitSeconds: number | undefined,
  userId: string
): Promise<KaliJob> {
  return agentJson(
    '/kali/exec',
    {
      method: 'POST',
      body: JSON.stringify({
        project_id: projectId,
        user_id: userId,
        command,
        ...(waitSeconds === undefined ? {} : { wait_seconds: waitSeconds }),
      }),
    },
    EXEC_TIMEOUT_MS,
    'exec'
  )
}

/**
 * `userId` is the token's owner, as for `kaliExec`: the agent answers 404 for a job recorded for
 * another person, so a co-member of the project cannot read or cancel someone else's command.
 */
export async function kaliJobStatus(
  projectId: string,
  jobId: string,
  cursor: number,
  userId: string
): Promise<KaliJob> {
  const qs = new URLSearchParams({ project_id: projectId, cursor: String(cursor), user_id: userId })
  return agentJson(
    `/kali/exec/${encodeURIComponent(jobId)}?${qs}`,
    { method: 'GET' },
    POLL_TIMEOUT_MS,
    'poll'
  )
}

export async function kaliJobCancel(projectId: string, jobId: string, userId: string): Promise<KaliJob> {
  const qs = new URLSearchParams({ project_id: projectId, user_id: userId })
  return agentJson(
    `/kali/exec/${encodeURIComponent(jobId)}/cancel?${qs}`,
    { method: 'POST' },
    POLL_TIMEOUT_MS,
    'cancel'
  )
}
