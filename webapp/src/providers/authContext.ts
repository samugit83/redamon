'use client'

import { createContext } from 'react'
import type { AuthContextValue } from './AuthProvider'

/**
 * The AuthProvider's context, in a module of its own: the permission hooks (hooks/useCan.ts) read
 * it without importing the provider, so a component rendered with no provider above it (or under a
 * test that replaces the provider module) reads "nobody signed in" and shows nothing gated.
 */
export const AuthContext = createContext<AuthContextValue | null>(null)
