'use client'

import { useEffect, useState } from 'react'
import { fetchModelOptions, fetchSavedFeatureModels, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { toApiError } from '@/lib/apiError'
import { modelAllowedForFeature } from '@/lib/llmFeatures'
import tc from './tradecraft.module.css'

export const LIBRARIAN_FEATURE = 'tradecraft_librarian' as const
/** Q10: the gate and the banner offer the section picker's model first, as a suggestion the person confirms. */
export const LIBRARIAN_SUGGESTION = { suggestFrom: 'tradecraft_section_picker', suggestedFrom: 'your Tradecraft section picker model' } as const

/** The gate for an Add or an Enabled turned on (`tradecraftClient.create` / `update`). */
export function useLibrarianGate(): (doFetch: () => Promise<Response>) => Promise<Response> {
  const gate = useFeatureModelGate()
  return doFetch => gate.fetchWithFeatureModel(LIBRARIAN_FEATURE, doFetch, {}, LIBRARIAN_SUGGESTION)
}

export const NO_LIBRARIAN_TEXT = 'No librarian model: the agent can only use plain search on your resources'

export type LibrarianModelState =
  | { kind: 'loading' }
  | { kind: 'error'; text: string }
  /** `usable`: the saved model is among the account's models (false when its provider was deleted); null when unknown. */
  | { kind: 'ready'; model: string; usable?: boolean | null }

/** No usable librarian model: none saved, or a saved one whose provider is gone (Q10). */
export function librarianMissing(state: LibrarianModelState): boolean {
  return state.kind === 'ready' && (!state.model || state.usable === false)
}

/**
 * The account's "Tradecraft librarian" model (Q10 "One value, shown in three places"): the
 * Models-by-feature value, read again whenever the gate saves one. With `checkUsable`, a saved
 * model is also looked up among the account's models, as the gate lists them: deleting its
 * provider leaves the id saved, and Q10 names that case for the banner. The listing asks the
 * providers, so the tab asks for it only where the answer shows something (resources, and
 * Librarian use "Agent decides"); a listing that fails leaves `usable` unknown, never missing.
 */
export function useLibrarianModel(userId: string, { checkUsable = false }: { checkUsable?: boolean } = {}): { state: LibrarianModelState; choose: () => void } {
  const gate = useFeatureModelGate()
  const [state, setState] = useState<LibrarianModelState>({ kind: 'loading' })
  useEffect(() => {
    let live = true
    fetchSavedFeatureModels(userId)
      .then(async map => {
        const model = map[LIBRARIAN_FEATURE] ?? ''
        if (!live) return
        setState({ kind: 'ready', model, usable: null })
        if (!model || !checkUsable) return
        let usable: boolean | null = null
        try {
          const groups = await fetchModelOptions(userId)
          usable = modelAllowedForFeature(LIBRARIAN_FEATURE, model) && Object.values(groups).some(list => list.some(m => m.id === model))
        } catch {
          usable = null
        }
        if (live) setState({ kind: 'ready', model, usable })
      })
      .catch(e => { if (live) setState({ kind: 'error', text: toApiError(e, "Couldn't read your librarian model").message }) })
    return () => { live = false }
  }, [userId, gate.savedVersion, checkUsable])
  return { state, choose: () => void gate.ensureFeatureModel(LIBRARIAN_FEATURE, { force: true, ...LIBRARIAN_SUGGESTION }) }
}

/** "Librarian model: <name> (change)", the line above the resource list and in Configure search. */
export function LibrarianModelLine({ state, onChoose }: { state: LibrarianModelState; onChoose: () => void }) {
  const shown = state.kind === 'loading' ? '…' : state.kind === 'error' ? 'unknown'
    : !state.model ? 'not set' : state.usable === false ? `${state.model} (not available: its provider is gone)` : state.model
  return (
    <div className={tc.hint} data-testid="librarian-model-line" title={state.kind === 'error' ? state.text : undefined}>
      Librarian model: <strong>{shown}</strong>{' '}
      <button type="button" className={tc.linkButton} onClick={onChoose}>
        ({state.kind === 'ready' && state.model && state.usable !== false ? 'change' : 'choose'})
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
