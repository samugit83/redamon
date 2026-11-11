/**
 * Normalize an orchestrator start-endpoint error body into a SAFE shape:
 * `{ error: string, limit?: object }`.
 *
 * Why this exists: the memory-governor rejects a scan start with a STRUCTURED
 * FastAPI detail object, e.g.
 *   { detail: { admitted, limitType, resource, current, ceiling, settingName, detail } }
 * If a route forwards `errorData.detail` straight through as `error`, the value
 * is an OBJECT. Any component that renders it (a toast, an inline message)
 * throws React's "Objects are not valid as a React child", which surfaces as the
 * generic "Application error: a client-side exception" and takes the page down.
 *
 * This helper guarantees `error` is ALWAYS a string (never an object), and puts
 * a governor refusal's payload in `limit` for the tailored limit modal; no other
 * part of the body is passed on. Every start route must run its error body
 * through here so the class of bug can't recur.
 */

export interface OrchestratorLimit {
  limitType?: 'hard' | 'ram'
  resource?: string
  current?: number
  ceiling?: number
  settingName?: string | null
  detail?: string
}

export interface NormalizedStartError {
  error: string
  limit?: OrchestratorLimit
  /**
   * The orchestrator's own reason code, when its detail names one:
   * `spawn_failed` (the container could not be created) or `not_configured`.
   * The queue reads both as permanent (scanStartOutcome.ts).
   */
  code?: string
}

export function normalizeOrchestratorStartError(
  errorData: unknown,
  fallback: string,
): NormalizedStartError {
  const detail =
    errorData && typeof errorData === 'object'
      ? (errorData as { detail?: unknown }).detail
      : undefined

  if (detail && typeof detail === 'object') {
    const d = detail as OrchestratorLimit
    if (d.limitType) {
      const msg =
        d.limitType === 'hard'
          ? `${d.detail || 'Configured limit reached'}. This is a configured limit, not a memory issue${
              d.settingName ? `. Increase ${d.settingName} and restart` : ''
            }.`
          : `${
              d.detail || 'Not enough memory to start this scan now'
            }. This is a RAM limit; retry once memory frees (finish or stop other running scans, or lower parallelism).`
      return { error: msg, limit: d }
    }
    // Unknown object shape: prefer its own `detail` string, else the fallback.
    // Critically, NEVER return the object itself, as `error` or as `limit`: a
    // FastAPI 422 is an array whose items echo the request in `input`, the scan's
    // job credential included, and this result goes to the browser.
    const code = (detail as { code?: unknown }).code
    return {
      error: (typeof d.detail === 'string' ? d.detail : null) || fallback,
      ...(typeof code === 'string' ? { code } : {}),
    }
  }

  return { error: (typeof detail === 'string' ? detail : null) || fallback }
}
