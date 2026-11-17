'use client'

import { useEffect, useState } from 'react'
import { fetchSavedFeatureModels, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { toApiError } from '@/lib/apiError'
import tc from './tradecraft.module.css'

export const LIBRARIAN_FEATURE = 'tradecraft_librarian' as const
export const NO_LIBRARIAN_TEXT = 'No librarian model: the agent can only use plain search on your resources'

export type LibrarianModelState =
  | { kind: 'loading' }
  | { kind: 'error'; text: string }
  | { kind: 'ready'; model: string }

/**
 * The account's "Tradecraft librarian" model (Q10 "One value, shown in three places"): the
 * Models-by-feature value, read again whenever the gate saves one.
 */
export function useLibrarianModel(userId: string): { state: LibrarianModelState; choose: () => void } {
  const gate = useFeatureModelGate()
  const [state, setState] = useState<LibrarianModelState>({ kind: 'loading' })
  useEffect(() => {
    let live = true
    fetchSavedFeatureModels(userId)
      .then(map => { if (live) setState({ kind: 'ready', model: map[LIBRARIAN_FEATURE] ?? '' }) })
      .catch(e => { if (live) setState({ kind: 'error', text: toApiError(e, "Couldn't read your librarian model").message }) })
    return () => { live = false }
  }, [userId, gate.savedVersion])
  return { state, choose: () => void gate.ensureFeatureModel(LIBRARIAN_FEATURE, { force: true }) }
}

/** "Librarian model: <name> (change)", the line above the resource list and in Configure search. */
export function LibrarianModelLine({ state, onChoose }: { state: LibrarianModelState; onChoose: () => void }) {
  const shown = state.kind === 'loading' ? '…' : state.kind === 'error' ? 'unknown' : state.model || 'not set'
  return (
    <div className={tc.hint} data-testid="librarian-model-line" title={state.kind === 'error' ? state.text : undefined}>
      Librarian model: <strong>{shown}</strong>{' '}
      <button type="button" className={tc.linkButton} onClick={onChoose}>
        ({state.kind === 'ready' && state.model ? 'change' : 'choose'})
      </button>
    </div>
  )
}

/** Q10: Settings → Tradecraft with resources but no librarian model (after the upgrade, or its provider was deleted). */
export function NoLibrarianBanner({ onChoose }: { onChoose: () => void }) {
  return (
    <div className={`${tc.switchBar} ${tc.badgeWarn}`} role="alert" data-testid="no-librarian-banner">
      <span>{NO_LIBRARIAN_TEXT}</span>
      <button type="button" className="secondaryButton" onClick={onChoose}>Choose a model</button>
    </div>
  )
}
