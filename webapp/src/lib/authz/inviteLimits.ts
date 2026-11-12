/**
 * The invite routes' own limiter (step 2.9, DV-05). `loginThrottle` keys on the client address
 * only when that address is trusted, so on a local install it limits nobody by address; these
 * limits hold whatever the IP trust:
 *   - a ceiling on link lookups (a lookup is a database read anyone can cause by opening
 *     `/invite/<token>`), sliding over one minute;
 *   - a count of failed accepts per link; the route cancels the link at the limit.
 *
 * In-process, so per copy: with several copies the ceiling is per copy (accepted, as the other
 * in-memory limits; master §9.6). Time comes from the authorization clock.
 */
import { now } from './clock'

export const LOOKUPS_PER_MINUTE = 30
export const FAILED_ACCEPT_LIMIT = 5

const WINDOW_MS = 60_000
/** Links with a failed accept remembered at once; the oldest is forgotten first. */
const MAX_TRACKED_LINKS = 10_000

let lookups: number[] = []
const failedAccepts = new Map<string, number>()

/** Counts one lookup, or refuses it with the seconds until one is allowed again (a refusal is not counted). */
export function takeLookup(): { ok: true } | { ok: false; retryAfterSeconds: number } {
  const t = now().getTime()
  lookups = lookups.filter((at) => t - at < WINDOW_MS)
  if (lookups.length >= LOOKUPS_PER_MINUTE) {
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((lookups[0] + WINDOW_MS - t) / 1000)) }
  }
  lookups.push(t)
  return { ok: true }
}

/** One more failed accept of the link `key` (its token hash); returns how many it has now. */
export function recordFailedAccept(key: string): number {
  const count = (failedAccepts.get(key) ?? 0) + 1
  failedAccepts.delete(key)
  failedAccepts.set(key, count)
  if (failedAccepts.size > MAX_TRACKED_LINKS) {
    const oldest = failedAccepts.keys().next().value
    if (oldest !== undefined) failedAccepts.delete(oldest)
  }
  return count
}

export function forgetFailedAccepts(key: string): void {
  failedAccepts.delete(key)
}

export function resetInviteLimitsForTests(): void {
  lookups = []
  failedAccepts.clear()
}
