'use client'

import { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react'
import { type ApiError, readApiError, toApiError } from '@/lib/apiError'

/** What the header's admin banners show; /api/auth/me sends it to admins only. */
export interface AdminNotices {
  compat: boolean
  /** Null when the count could not be read: no review banner then. */
  legacyGrantsPending: number | null
}

export interface AuthUser {
  id: string
  name: string
  email: string
  role: 'admin' | 'standard'
  rbac?: AdminNotices
}

interface AuthContextValue {
  user: AuthUser | null
  isLoading: boolean
  isAdmin: boolean
  /**
   * Why the session could not be read when the cause was not "signed out": a
   * 5xx (database down) or no answer. Null for a 401, which is a plain sign-out.
   */
  sessionError: ApiError | null
  login: (email: string, password: string) => Promise<{ error?: string }>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

/** Pages a signed-out browser may stay on: the middleware's public pages. */
const SIGNED_OUT_PAGES = ['/login']

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
        // rather than leave a signed-in shell that can do nothing.
        if (res.status === 401 && !onSignedOutPage(window.location.pathname)) window.location.replace('/login')
        return null
      })
      .then(data => {
        if (data?.id) setUser(data)
      })
      .catch(err => setSessionError(toApiError(err, 'Could not read your session')))
      .finally(() => setIsLoading(false))
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
    return {}
  }, [])

  const logout = useCallback(async () => {
    await fetch('/api/auth/logout', { method: 'POST' })
    setUser(null)
    window.location.href = '/login'
  }, [])

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAdmin: user?.role === 'admin',
        sessionError,
        login,
        logout,
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
