'use client'

import { useEffect, useState } from 'react'
import type { PasswordPolicy } from '@/lib/authz/passwordPolicy'

export interface PasswordPolicyView extends PasswordPolicy {
  /** The sentence shown beside a password field. */
  description: string
}

/**
 * The password policy in force (GET /api/auth/password-policy), or null while it loads and
 * when there is none. `identityOn` is the identity switch as /api/auth/me reports it (`flags`):
 * off, the route answers 404, which the browser logs as an error on every page load, so it is not
 * asked and the forms keep Phase 1's floor with no policy text. The server applies the policy
 * whatever this says.
 */
export function usePasswordPolicy(identityOn: boolean): PasswordPolicyView | null {
  const [policy, setPolicy] = useState<PasswordPolicyView | null>(null)
  useEffect(() => {
    if (!identityOn) {
      setPolicy(null)
      return
    }
    let live = true
    fetch('/api/auth/password-policy')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!live || !data || typeof data.minLength !== 'number') return
        setPolicy({ minLength: data.minLength, rules: data.rules === true, description: String(data.description ?? '') })
      })
      .catch(() => {})
    return () => { live = false }
  }, [identityOn])
  return policy
}
