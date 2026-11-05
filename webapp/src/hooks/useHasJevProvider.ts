'use client'

import { createContext, createElement, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { isJevProvider } from '@/lib/llmProviderKinds'
import { readApiError, toApiError } from '@/lib/apiError'

export type JevProviderStatus = 'loading' | 'yes' | 'no' | 'error'

/** Masked account configuration; credential presence does not prove live Jev access. */
export interface JevProviderRow {
  id: string
  name: string
  providerType: string
  apiKey: string
  modelIdentifier: string
}

interface JevSelectionState {
  status: JevProviderStatus
  lookupStatus: 'loading' | 'ready' | 'error' | 'limited'
  provider: JevProviderRow | null
  providers: JevProviderRow[]
  selectedProviderId: string | null
  ownerUserId: string | null
  error: string | null
  refresh: () => void
}

const CHANGED_EVENT = 'redamon:jev-provider-changed'
const JevSelectionContext = createContext<JevSelectionState | null>(null)

/**
 * Tell the mounted Jev lookup that a configuration was added, replaced or removed.
 *
 * The project form's Target panel can add one inline, and Settings can delete one;
 * without this, every engine switch on the page would keep reading the old list
 * until the page reloads.
 */
export function notifyJevProviderChanged(): void {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(CHANGED_EVENT))
}

/**
 * The project owner's Jev configurations and the project's (possibly unsaved)
 * selection, looked up once for every Jev control in the form.
 *
 * A failed lookup is 'error', never 'no': telling a user "nothing is selected" when
 * the lookup actually failed would push them to re-add a configuration they already
 * have. Don't copy ShodanSection's hook, which reports a failed fetch as "no key".
 *
 * This is a convenience signal for the form only; the server
 * (validateJevEngineChange) is the authority on whether a switch-on is allowed.
 */
export function JevSelectionProvider({
  ownerUserId, selectedProviderId, ownerUnavailable = false, children,
}: {
  ownerUserId: string | null
  selectedProviderId: string | null
  ownerUnavailable?: boolean
  children: ReactNode
}) {
  const [lookup, setLookup] = useState<{
    ownerUserId: string | null
    nonce: number
    status: 'loading' | 'ready' | 'error'
    providers: JevProviderRow[]
    error: string | null
  }>({ ownerUserId: null, nonce: 0, status: 'loading', providers: [], error: null })
  const [nonce, setNonce] = useState(0)
  const refresh = useCallback(() => setNonce(n => n + 1), [])

  useEffect(() => {
    window.addEventListener(CHANGED_EVENT, refresh)
    return () => window.removeEventListener(CHANGED_EVENT, refresh)
  }, [refresh])

  useEffect(() => {
    if (!ownerUserId) return
    let cancelled = false
    ;(async () => {
      try {
        const response = await fetch(`/api/users/${ownerUserId}/llm-providers`)
        if (!response.ok) throw await readApiError(response, 'Could not load the project owner’s Jev configurations')
        const rows: unknown = await response.json()
        // A 200 that is not a list (an error payload, a proxy page) tells us nothing
        // about the account, so it is a failed lookup, not "no configurations".
        if (!Array.isArray(rows)) throw new Error('Invalid Jev configuration lookup response')
        const providers = rows.filter((row): row is JevProviderRow =>
          row !== null && typeof row === 'object' && typeof row.id === 'string' &&
          typeof row.providerType === 'string' &&
          typeof row.name === 'string' && typeof row.apiKey === 'string' && typeof row.modelIdentifier === 'string' &&
          isJevProvider(row))
        if (!cancelled) setLookup({ ownerUserId, nonce, status: 'ready', providers, error: null })
      } catch (error) {
        if (!cancelled) setLookup({ ownerUserId, nonce, status: 'error', providers: [],
          error: toApiError(error, 'Could not load Jev configurations').message })
      }
    })()
    return () => { cancelled = true }
  }, [ownerUserId, nonce])

  // Never show a previous owner's configurations, even for the render before an effect runs.
  const lookupStatus = ownerUnavailable ? 'limited'
    : !ownerUserId || lookup.ownerUserId !== ownerUserId || lookup.nonce !== nonce ? 'loading'
    : lookup.status
  const providers = lookupStatus === 'ready' ? lookup.providers : []
  const provider = providers.find(row =>
    row.id === selectedProviderId && typeof row.apiKey === 'string' && row.apiKey.trim()) ?? null
  const status: JevProviderStatus = lookupStatus === 'loading' ? 'loading'
    : lookupStatus === 'error' || lookupStatus === 'limited' ? 'error'
    : provider ? 'yes' : 'no'

  return createElement(JevSelectionContext.Provider, { value: {
    status, lookupStatus, provider, providers, selectedProviderId, ownerUserId,
    error: lookupStatus === 'error' ? lookup.error : null, refresh,
  } }, children)
}

/** No implicit acting-user/first-row fallback outside a project selection scope. */
export function useJevProvider(): JevSelectionState {
  return useContext(JevSelectionContext) ?? {
    status: 'error', lookupStatus: 'limited', provider: null, providers: [],
    selectedProviderId: null, ownerUserId: null, error: null, refresh: () => {},
  }
}

export function useHasJevProvider(): JevProviderStatus {
  return useJevProvider().status
}
