/**
 * The invite routes' own limiter (step 2.9, DV-05). `loginThrottle` keys on the client address
 * only when that address is trusted, so on a local install it limits nobody by address; these
 * limits hold whatever the IP trust:
 *   - a ceiling on link lookups (a lookup is a database read anyone can cause by opening
 *     `/invite/<token>`), sliding over one minute;
 *   - a count of failed accepts per link; the route cancels the link at the limit.
 *
 * The share routes' recipient lookups (step 4.4, DV-05) slide over the same minute, counted per
 * person: a lookup tells whether an email has an account (D-24 confirm mode).
 *
 * In-process, so per copy: with several copies the ceiling is per copy (accepted, as the other
 * in-memory limits; master §9.6). Time comes from the authorization clock.
 */
import { now } from './clock'

export const LOOKUPS_PER_MINUTE = 30
export const FAILED_ACCEPT_LIMIT = 5
export const SHARE_LOOKUPS_PER_MINUTE = 20

const WINDOW_MS = 60_000
/** Links with a failed accept remembered at once; the oldest is forgotten first. */
const MAX_TRACKED_LINKS = 10_000
/** People whose share lookups are remembered at once; the least recent is forgotten first. */
const MAX_TRACKED_ACTORS = 10_000

type Taken = { ok: true } | { ok: false; retryAfterSeconds: number }

let lookups: number[] = []
const failedAccepts = new Map<string, number>()
const shareLookups = new Map<string, number[]>()

/** One more use of a sliding one-minute window: the window kept, and the answer (a refusal is not counted). */
function slide(window: readonly number[], limit: number): { window: number[]; taken: Taken } {
  const t = now().getTime()
  const recent = window.filter((at) => t - at < WINDOW_MS)
  if (recent.length >= limit) {
    return { window: recent, taken: { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((recent[0] + WINDOW_MS - t) / 1000)) } }
  }
  recent.push(t)
  return { window: recent, taken: { ok: true } }
}

/** Counts one lookup, or refuses it with the seconds until one is allowed again (a refusal is not counted). */
export function takeLookup(): Taken {
  const { window, taken } = slide(lookups, LOOKUPS_PER_MINUTE)
  lookups = window
  return taken
}

/** takeLookup for one person's share recipient lookups (`actorId`, the person signed in). */
export function takeShareLookup(actorId: string): Taken {
  const { window, taken } = slide(shareLookups.get(actorId) ?? [], SHARE_LOOKUPS_PER_MINUTE)
  shareLookups.delete(actorId)
  shareLookups.set(actorId, window)
  if (shareLookups.size > MAX_TRACKED_ACTORS) {
    const oldest = shareLookups.keys().next().value
    if (oldest !== undefined) shareLookups.delete(oldest)
  }
  return taken
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
  shareLookups.clear()
}
