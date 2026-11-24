/**
 * One-shot reads a page cannot work without (the session, the saved project) are tried again when
 * they get no answer at all. Chromium aborts every request in flight with net::ERR_NETWORK_CHANGED
 * when a host address appears or goes away, which on a Docker host a container on a bridge network
 * starting or stopping does; read once, such a page stayed on "No User" / "No Project" until a
 * reload. An answer, whatever its status, is never tried again: a refusal or an outage is the
 * server's to report. Neither is a read its owner gave up.
 */
import type { ApiError } from './apiError'

/** The waits before each new try, in ms: about 7.5 s in all, then the failure stands. */
export const NO_ANSWER_RETRY_MS: readonly number[] = [500, 1000, 2000, 4000]

export interface RetryOptions {
  /** Asked before each new try: false once the read's owner gave it up (superseded, unmounted). */
  keepTrying?: () => boolean
}

export interface RetriedRead<T> {
  res: Response
  /** The parsed JSON of an OK answer; undefined for any other status, whose body is left unread. */
  body: T | undefined
}

/**
 * `fetch` plus, for an OK answer, its JSON body, tried again after each wait of NO_ANSWER_RETRY_MS
 * while no answer arrives: the request or the OK body's read throws (a network error, an abort, a
 * timeout). A body that is not JSON is an answer and rejects at once with its SyntaxError. The
 * caller's own abort (`init.signal`) and `keepTrying() === false` stop the tries. Rejects with the
 * last failure once the waits are spent.
 */
export async function readRetryingNoAnswer<T = unknown>(
  input: RequestInfo | URL,
  init?: RequestInit,
  opts: RetryOptions = {},
): Promise<RetriedRead<T>> {
  const keepTrying = () => !init?.signal?.aborted && (opts.keepTrying?.() ?? true)
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(input, init)
      if (!res.ok) return { res, body: undefined }
      return { res, body: await res.json() as T }
    } catch (err) {
      if (err instanceof SyntaxError) throw err
      if (attempt >= NO_ANSWER_RETRY_MS.length || !keepTrying()) throw err
      await new Promise(resolve => setTimeout(resolve, NO_ANSWER_RETRY_MS[attempt]))
      if (!keepTrying()) throw err
    }
  }
}

const NO_ANSWER_CODES = new Set(['network_error', 'aborted', 'timeout'])

/** A failure `toApiError` built from a request that got no answer, as opposed to any answer. */
export function isNoAnswer(err: ApiError | null | undefined): boolean {
  return !!err && err.status === 0 && NO_ANSWER_CODES.has(err.code ?? '')
}
