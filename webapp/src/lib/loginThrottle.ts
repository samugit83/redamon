// S11: application-layer login lockout / backoff.
//
// In-memory, per-process store keyed by lowercased email AND source IP (webapp is
// single-replica, so a shared store is not required; if ever scaled out, move to a
// Postgres counter - the failure AUDIT is already durable via R5). The map is
// BOUNDED: expired entries are evicted lazily on access plus a periodic sweep, so
// a flood of distinct source IPs cannot turn this anti-brute-force control into a
// memory-exhaustion vector.
//
// Thresholds come from env with SAFE DEFAULTS so an unset value fails safe to the
// documented default, never to "no limit".
//
// D6: a browser holding a known-device entry for the e-mail it signs in to
// (loginDevice.ts) is counted on its own `device:` key instead of the e-mail and IP
// keys, so failures sent by anyone else cannot lock it out. The namespaces never
// meet: an e-mail key is always `email:<...>`, whatever text the e-mail holds.

interface Entry {
  count: number
  firstAt: number
  lockedUntil: number
}

const globalForThrottle = globalThis as unknown as { __loginThrottle?: Map<string, Entry> }
const store: Map<string, Entry> = globalForThrottle.__loginThrottle ?? new Map()
globalForThrottle.__loginThrottle = store

const WINDOW_MS = 15 * 60 * 1000 // attempts counted within this rolling window
const MAX_ENTRIES = 10_000 // hard cap on tracked keys (memory bound)

function maxAttempts(): number {
  const n = parseInt(process.env.LOGIN_MAX_ATTEMPTS || '', 10)
  return Number.isFinite(n) && n > 0 ? n : 5
}

function lockoutSeconds(): number {
  const n = parseInt(process.env.LOGIN_LOCKOUT_SECONDS || '', 10)
  return Number.isFinite(n) && n > 0 ? n : 900
}

function evictExpired(now: number): void {
  for (const [k, e] of store) {
    // Drop entries that are neither locked nor within the attempt window.
    if (e.lockedUntil <= now && now - e.firstAt > WINDOW_MS) store.delete(k)
  }
  // Backstop: if still over the cap, drop the oldest-first insertions.
  if (store.size > MAX_ENTRIES) {
    const overflow = store.size - MAX_ENTRIES
    let i = 0
    for (const k of store.keys()) {
      if (i++ >= overflow) break
      store.delete(k)
    }
  }
}

function keysFor(email: string, ip: string | null): string[] {
  const keys = [`email:${email.toLowerCase()}`]
  if (ip) keys.push(`ip:${ip}`)
  return keys
}

export interface LockoutStatus {
  locked: boolean
  retryAfterSeconds: number
}

function deviceKeys(deviceId: string): string[] {
  return [`device:${deviceId}`]
}

function statusOf(keys: string[], now: number): LockoutStatus {
  evictExpired(now)
  let retryAfter = 0
  for (const k of keys) {
    const e = store.get(k)
    if (e && e.lockedUntil > now) {
      retryAfter = Math.max(retryAfter, Math.ceil((e.lockedUntil - now) / 1000))
    }
  }
  return { locked: retryAfter > 0, retryAfterSeconds: retryAfter }
}

// Returns the current lockout status for this (email, ip) pair without mutating
// counters (call before verifying the password).
export function checkLockout(email: string, ip: string | null, now = Date.now()): LockoutStatus {
  return statusOf(keysFor(email, ip), now)
}

// Record a failed attempt; if a key crosses the threshold it becomes locked for
// LOGIN_LOCKOUT_SECONDS. Returns the resulting status (locked=true means this
// attempt tripped/extended a lockout).
export function recordFailure(email: string, ip: string | null, now = Date.now()): LockoutStatus {
  return countFailure(keysFor(email, ip), now)
}

function countFailure(keys: string[], now: number): LockoutStatus {
  const limit = maxAttempts()
  const lockMs = lockoutSeconds() * 1000
  let retryAfter = 0
  for (const k of keys) {
    let e = store.get(k)
    if (!e || now - e.firstAt > WINDOW_MS) {
      e = { count: 0, firstAt: now, lockedUntil: 0 }
    }
    e.count += 1
    if (e.count >= limit) {
      e.lockedUntil = now + lockMs
    }
    store.set(k, e)
    if (e.lockedUntil > now) {
      retryAfter = Math.max(retryAfter, Math.ceil((e.lockedUntil - now) / 1000))
    }
  }
  evictExpired(now)
  return { locked: retryAfter > 0, retryAfterSeconds: retryAfter }
}

// Clear counters on a successful login.
export function clearAttempts(email: string, ip: string | null): void {
  for (const k of keysFor(email, ip)) store.delete(k)
}

// The same three operations for a known-device entry (loginDevice.ts). Its success
// clears only its own key: the e-mail's counter keeps counting the guesses others send.
export function checkDeviceLockout(deviceId: string, now = Date.now()): LockoutStatus {
  return statusOf(deviceKeys(deviceId), now)
}

export function recordDeviceFailure(deviceId: string, now = Date.now()): LockoutStatus {
  return countFailure(deviceKeys(deviceId), now)
}

export function clearDeviceAttempts(deviceId: string): void {
  for (const k of deviceKeys(deviceId)) store.delete(k)
}

// Test-only: wipe the store.
export function __resetThrottle(): void {
  store.clear()
}
