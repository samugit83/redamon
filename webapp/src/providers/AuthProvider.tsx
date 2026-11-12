'use client'

import { useContext, useState, useEffect, useCallback, useMemo, useRef, ReactNode } from 'react'
import { type ApiError, readApiError, toApiError } from '@/lib/apiError'
import type { PermissionId } from '@/lib/authz/permissions'
import type { RbacFlags } from '@/lib/authz/flags'
import { AuthContext } from './authContext'

/** The instance's Root as the header's Root banner shows it (identity switch on). */
export interface RootNotice {
  email: string
  /** Confirmed by the install, the host or a transfer; an automatic choice is not. */
  confirmed: boolean
  /** When an unconfirmed Root was chosen (ISO), null when unknown or confirmed. */
  chosenAt: string | null
}

/** What the header's admin banners show; /api/auth/me sends it to admins only. */
export interface AdminNotices {
  compat: boolean
  /** Null when the count could not be read: no review banner then. */
  legacyGrantsPending: number | null
  /** Present (true) only while RBAC_IDENTITY_ENABLED is on: disable and sign-out are offered. */
  identity?: true
  /** Identity switch on: the Root, null when the instance has none; absent when off or unread. */
  root?: RootNotice | null
}

export interface AuthUser {
  id: string
  name: string
  email: string
  role: 'admin' | 'standard'
  /** Identity switch on: root, admin or member; absent when off. */
  accountType?: 'root' | 'admin' | 'member'
  /**
   * What the person may use now, in registry order (step 3.12): under act-as what the admin may use
   * while acting. Null when the server could not resolve it; absent in the login answer.
   */
  capabilities?: PermissionId[] | null
  /** The RBAC switch states (every account). */
  flags?: RbacFlags
  rbac?: AdminNotices
}

export interface AuthContextValue {
  user: AuthUser | null
  isLoading: boolean
  /** `user.capabilities` as a set; empty until read, and when the server could not resolve it. */
  capabilities: ReadonlySet<PermissionId>
  flags: Readonly<RbacFlags> | null
  /**
   * Why the session could not be read when the cause was not "signed out": a
   * 5xx (database down) or no answer. Null for a 401, which is a plain sign-out.
   */
  sessionError: ApiError | null
  login: (email: string, password: string) => Promise<{ error?: string }>
  logout: () => Promise<void>
  /**
   * Reads /api/auth/me again, after a change of what the person may use: an act-as switch changes
   * the capabilities. A failed read keeps what was shown.
   */
  refresh: () => Promise<void>
}

/** Pages a signed-out browser may stay on: the middleware's public pages (`/invite`: step 2.9). */
const SIGNED_OUT_PAGES = ['/login', '/invite']

function onSignedOutPage(pathname: string): boolean {
  return SIGNED_OUT_PAGES.some(p => pathname === p || pathname.startsWith(p + '/'))
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [sessionError, setSessionError] = useState<ApiError | null>(null)
  const hydrated = useRef(false)

  // Hydrate session once on mount
  useEffect(() => {
    if (hydrated.current) return
    hydrated.current = true

    fetch('/api/auth/me')
      .then(async res => {
        if (res.ok) return res.json()
        if (res.status >= 500) setSessionError(await readApiError(res, 'Could not read your session'))
        // The middleware checks only the cookie's signature, so a revoked, disabled or
        // deleted account still loads pages while every API answers 401: go to sign-in
        // rather than leave a signed-in shell that can do nothing. Only a session the identity
        // switch ended says so; a bare 401 (switch off) leaves the page as before the switch.
        if (res.status === 401 && !onSignedOutPage(window.location.pathname)) {
          const body = await res.json().catch(() => null)
          if (body?.code === 'session_ended') window.location.replace('/login')
        }
        return null
      })
      .then(data => {
        if (data?.id) setUser(data)
      })
      .catch(err => setSessionError(toApiError(err, 'Could not read your session')))
      .finally(() => setIsLoading(false))
  }, [])

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/me', { cache: 'no-store' })
      if (!res.ok) return
      const data = await res.json()
      if (data?.id) setUser(data)
    } catch {
      // The next page load reads the session again; what is shown stays until then.
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })

    if (!res.ok) {
      return { error: (await readApiError(res, 'Login failed')).message }
    }

    const data = await res.json()
    setUser(data)
    // The login answer carries the account, not what it may use.
    await refresh()
    return {}
  }, [refresh])

  const logout = useCallback(async () => {
    await fetch('/api/auth/logout', { method: 'POST' })
    setUser(null)
    window.location.href = '/login'
  }, [])

  const capabilities = useMemo(() => new Set<PermissionId>(user?.capabilities ?? []), [user])

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        capabilities,
        flags: user?.flags ?? null,
        sessionError,
        login,
        logout,
        refresh,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

/** The auth context, or null outside an AuthProvider (a component also rendered alone). */
export function useOptionalAuth(): AuthContextValue | null {
  return useContext(AuthContext)
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}
