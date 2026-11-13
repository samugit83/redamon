/**
 * The browser's memory of whom an admin chose to act as. ProjectProvider re-posts it at the next page
 * load while the permissions switch is off; with it on the server holds the impersonation and nothing
 * is restored (step 3.14, IM-02).
 *
 * The key belongs to the browser, not to an account. With the identity switch on a pick is saved
 * bound to the admin who made it, and only that admin's pick is restored: anything else is dropped the
 * first time it is read, whether a bare id (what the switches-off code saves, the projects page's
 * first-user default and a member's own id included) or another account's pick. Re-posting it would
 * start an act-as nobody asked for, audited in the name of whoever signed in next (review of step
 * 3.16c). Sign-out forgets it too (AuthProvider). With the switches off the key holds a bare id and
 * is restored for whoever signs in, as before RBAC (DV-30).
 *
 * The value is never trusted for authorization: the act-as route decides on every post.
 */
export const ACT_AS_PICK_KEY = 'redamon-current-user'

interface BoundPick {
  by: string
  target: string
}

function readBound(saved: string): BoundPick | null {
  try {
    const value: unknown = JSON.parse(saved)
    if (value && typeof value === 'object') {
      const { by, target } = value as Record<string, unknown>
      if (typeof by === 'string' && by && typeof target === 'string' && target) return { by, target }
    }
  } catch {
    // A bare account id.
  }
  return null
}

/** Saves `target` as whom `by` chose to act as. */
export function rememberActAsPick(target: string, by: string | null | undefined, identityOn: boolean): void {
  if (!identityOn) localStorage.setItem(ACT_AS_PICK_KEY, target)
  else if (by) localStorage.setItem(ACT_AS_PICK_KEY, JSON.stringify({ by, target } satisfies BoundPick))
  else forgetActAsPick()
}

/**
 * Whom `signedIn` chose to act as and may be re-posted now, or null; a value that may not be is
 * removed. Switches off: a bare id as before, and a bound pick (saved while identity was on) only for
 * the account that made it.
 */
export function recallActAsPick(signedIn: string, identityOn: boolean): string | null {
  const saved = localStorage.getItem(ACT_AS_PICK_KEY)
  if (!saved) return null
  const pick = readBound(saved)
  if (!pick && !identityOn) return saved === signedIn ? null : saved
  if (pick && pick.by === signedIn && pick.target !== signedIn) return pick.target
  forgetActAsPick()
  return null
}

export function forgetActAsPick(): void {
  localStorage.removeItem(ACT_AS_PICK_KEY)
}
