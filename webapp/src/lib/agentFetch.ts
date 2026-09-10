/**
 * Server-side fetch wrapper for all calls from a webapp API route to the agent.
 *
 * The agent-side twin of `lib/orchestrator.ts`. It exists for three reasons,
 * the first of which is a real user-facing bug (issue #184):
 *
 * 1. ATTRIBUTION. A raw `fetch` to the agent that fails at the transport layer
 *    throws Node's opaque `TypeError: fetch failed`. Routes were re-serializing
 *    that with `String(error)` into their JSON body, so when the agent container
 *    is down the LLM-provider form renders "TypeError: fetch failed" directly
 *    under the operator's Base URL field. The endpoint they just typed was never
 *    contacted (only the agent dials it), yet the message reads as if it were
 *    theirs. `describeAgentFailure` names the service that actually failed and
 *    says what to run.
 * 2. TIMEOUT. Same rationale as `orchestratorFetch`: without a default abort the
 *    route waits on a hung agent until the browser gives up.
 * 3. ONE base URL. Routes had drifted between `http://agent:8080` (correct on
 *    the compose network) and `http://localhost:8090` (the HOST-side published
 *    port - nothing listens there from inside the webapp container).
 *
 * Server-side only; never import into a client component.
 */
import { internalKeyHeaders } from '@/lib/agentAuth'

/**
 * Where the agent lives, resolved per call rather than at module load.
 *
 * The `NEXT_PUBLIC_AGENT_API_URL` rung is not decorative: ~15 agent-proxying
 * routes honour it, including the health route this helper replaced. Dropping it
 * would make a split deployment that sets only that variable report a healthy
 * agent as missing - a false outage produced by the outage detector itself.
 *
 * The last rung is the in-network SERVICE NAME. Never `localhost:8090`: that is
 * the host-side published port, and nothing listens on it inside the container.
 */
export function agentBaseUrl(): string {
  return (
    process.env.AGENT_API_URL ||
    process.env.NEXT_PUBLIC_AGENT_API_URL ||
    'http://agent:8080'
  )
}

const DEFAULT_AGENT_TIMEOUT_MS = 30_000

export interface AgentFailureContext {
  /** True when the abort came from the CALLER's signal (client disconnect),
   *  not from our timeout. Without it every abort blames the agent. */
  callerAborted?: boolean
}

/** Thrown when the agent could not be reached at all (DNS, refused, no route,
 *  timeout) - i.e. the request never got an HTTP response. An agent that
 *  answers with 4xx/5xx is NOT this: that comes back as a normal Response. */
export class AgentUnreachableError extends Error {
  readonly cause_: unknown

  constructor(cause: unknown, ctx: AgentFailureContext = {}) {
    super(describeAgentFailure(cause, ctx))
    this.name = 'AgentUnreachableError'
    this.cause_ = cause
  }
}

/** Pull the errno code out of a Node fetch failure. undici wraps the real
 *  syscall error in `.cause`, so the code is one level down. */
function errorCode(err: unknown): string | undefined {
  if (!err || typeof err !== 'object') return undefined
  const cause = (err as { cause?: unknown }).cause
  const nested = cause && typeof cause === 'object'
    ? (cause as NodeJS.ErrnoException).code
    : undefined
  return nested || (err as NodeJS.ErrnoException).code
}

function errorName(err: unknown): string | undefined {
  return err && typeof err === 'object' ? (err as Error).name : undefined
}

const CHECK_IT = 'Check it with "docker compose ps -a agent" and '
  + '"docker compose logs --tail=100 agent", then run "./redamon.sh up".'

/**
 * Turn a transport-level failure into a sentence naming the RIGHT service.
 * Exported for tests and for callers that catch a bare fetch rejection.
 */
export function describeAgentFailure(
  err: unknown,
  ctx: AgentFailureContext = {},
): string {
  const where = `the RedAmon agent service at ${agentBaseUrl()}`
  const notYourEndpoint =
    'The request never left RedAmon, so this is not a problem with the endpoint you configured.'

  switch (errorCode(err)) {
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return `Cannot reach ${where}: the hostname does not resolve, which means the `
        + `agent container is not running. ${CHECK_IT} ${notYourEndpoint}`
    case 'ECONNREFUSED':
      return `Cannot reach ${where}: connection refused. The agent container exists but is `
        + `not serving yet - wait for it to become healthy and retry. ${notYourEndpoint}`
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      return `Cannot reach ${where}: no route to host. The webapp and agent containers are `
        + `not on the same Docker network. ${notYourEndpoint}`
    case 'ECONNRESET':
    case 'EPIPE':
      return `Lost the connection to ${where} mid-request. The agent likely restarted or was `
        + `killed (out of memory). ${CHECK_IT}`
    case 'ETIMEDOUT':
      return `${where} did not respond in time. ${CHECK_IT}`
    default:
      if (errorName(err) === 'TimeoutError' || errorName(err) === 'AbortError') {
        // An abort proves nothing about the agent when the CALLER pulled the
        // plug (a closed tab aborting request.signal). Blaming the agent there
        // sends whoever reads the log to inspect a healthy container.
        return ctx.callerAborted
          ? `The request to ${where} was cancelled before it completed (the client `
            + 'disconnected). The agent itself was not necessarily at fault.'
          : `${where} did not respond in time. ${CHECK_IT}`
      }
      return `Cannot reach ${where}: ${err instanceof Error ? err.message : String(err)}`
  }
}

/**
 * Flatten any valid `RequestInit['headers']` to a plain object.
 *
 * A `Headers` instance has no own enumerable properties, so spreading one
 * yields `{}` and every caller header - `Content-Type` included - disappears
 * silently; the agent then rejects the untyped body with a 422 that reads like
 * a schema bug. An array of pairs spreads into `{0: [...], 1: [...]}`, which is
 * just as wrong and just as quiet.
 */
function toHeaderRecord(headers: HeadersInit | undefined): Record<string, string> {
  if (!headers) return {}
  if (headers instanceof Headers) return Object.fromEntries(headers.entries())
  if (Array.isArray(headers)) return Object.fromEntries(headers)
  return { ...headers }
}

export interface AgentFetchOptions {
  /** Abort after this many ms. Default 30s; <= 0 disables. Ignored when the
   *  caller supplies its own `init.signal` (e.g. a streaming route). */
  timeoutMs?: number
}

/**
 * Call the agent. `path` is agent-relative ("/llm-provider/test").
 *
 * Injects the internal API key (D3) and a default timeout, and converts every
 * transport failure into `AgentUnreachableError`. An HTTP error status is NOT
 * converted - callers keep their existing `resp.status` handling.
 */
export async function agentFetch(
  path: string,
  init: RequestInit = {},
  opts: AgentFetchOptions = {},
): Promise<Response> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_AGENT_TIMEOUT_MS
  // An explicit caller signal (a streaming route passing request.signal) always
  // wins, so a long-lived stream is never force-aborted by the default timeout.
  const callerSignal = init.signal ?? undefined
  const signal =
    callerSignal ?? (timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined)

  try {
    return await fetch(`${agentBaseUrl()}${path}`, {
      ...init,
      signal,
      // internalKeyHeaders LAST so a caller can never override or strip the key.
      headers: internalKeyHeaders(toHeaderRecord(init.headers)),
    })
  } catch (err) {
    throw new AgentUnreachableError(err, { callerAborted: !!callerSignal?.aborted })
  }
}
