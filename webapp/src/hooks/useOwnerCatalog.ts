'use client'

import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import type { OwnerCatalog } from '@/lib/ownerCatalog'
import { errorMessage, fetchJson } from '@/lib/apiError'
import { fetchModelOptions, MODELS_LOAD_FAILED, type ModelsByProvider } from '@/components/shared/modelOptions'

export const OWNER_CATALOG_FAILED = "Could not load the project owner's catalog"

export type OwnerCatalogStatus = 'loading' | 'ready' | 'error'

/**
 * The project owner's catalogs as a collaborator's project form shows them (step 5.7, SH-26): the
 * owner's providers, Jev configurations, skills, tradecraft resources, MCP servers and which keys
 * are set, by name and presence (GET /api/projects/[id]/owner-catalog), and at Manage the models of
 * the owner's providers. Provided around the form of a project the person does not own; absent for
 * the owner's form and with RBAC_SHARING_ENABLED off, where every control reads the person's own
 * account as before (DV-30).
 */
export interface OwnerCatalogSource {
  catalog: OwnerCatalog | null
  status: OwnerCatalogStatus
  error: string | null
  /** The owner's models, read only at Manage; 'off' below it. */
  models: ModelsByProvider | null
  modelsStatus: 'off' | OwnerCatalogStatus
  modelsError: string | null
  /** Why this access may not pick from the catalog (below Manage), or null. */
  pickRefusal: string | null
  retry: () => void
}

export const OwnerCatalogContext = createContext<OwnerCatalogSource | null>(null)

/** The owner's catalogs inside a collaborator's project form; null anywhere else. */
export function useOwnerCatalogSource(): OwnerCatalogSource | null {
  return useContext(OwnerCatalogContext)
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

function isCatalog(v: unknown): v is OwnerCatalog {
  return isRecord(v) && isRecord(v.keys)
    && ['providers', 'jevProviders', 'attackSkills', 'tradecraftResources', 'mcpServers'].every(k => Array.isArray(v[k]))
}

/**
 * Reads the owner's catalogs once per form while `enabled` (a project the person does not own),
 * and the owner's models too when `models` (Manage). Returns null while not enabled.
 */
export function useOwnerCatalog(
  projectId: string | null | undefined,
  { enabled, models, pickRefusal }: { enabled: boolean; models: boolean; pickRefusal: string | null },
): OwnerCatalogSource | null {
  const [nonce, setNonce] = useState(0)
  const retry = useCallback(() => setNonce(n => n + 1), [])
  const [state, setState] = useState<{ key: string; status: OwnerCatalogStatus; catalog: OwnerCatalog | null; error: string | null }>(
    { key: '', status: 'loading', catalog: null, error: null })
  const [modelState, setModelState] = useState<{ key: string; status: OwnerCatalogStatus; models: ModelsByProvider | null; error: string | null }>(
    { key: '', status: 'loading', models: null, error: null })
  const key = `${projectId ?? ''}:${nonce}`
  const on = enabled && !!projectId

  useEffect(() => {
    if (!on || !projectId) return
    let live = true
    fetchJson<unknown>(`/api/projects/${encodeURIComponent(projectId)}/owner-catalog`, undefined, OWNER_CATALOG_FAILED)
      .then(body => {
        if (!live) return
        if (!isCatalog(body)) throw new Error(`${OWNER_CATALOG_FAILED} (invalid_response)`)
        setState({ key, status: 'ready', catalog: body, error: null })
      })
      .catch(err => { if (live) setState({ key, status: 'error', catalog: null, error: errorMessage(err, OWNER_CATALOG_FAILED) }) })
    return () => { live = false }
  }, [on, projectId, key])

  useEffect(() => {
    if (!on || !models || !projectId) return
    let live = true
    fetchModelOptions(null, { projectId })
      .then(m => { if (live) setModelState({ key, status: 'ready', models: m, error: null }) })
      .catch(err => { if (live) setModelState({ key, status: 'error', models: null, error: errorMessage(err, MODELS_LOAD_FAILED) }) })
    return () => { live = false }
  }, [on, models, projectId, key])

  if (!on) return null
  // A previous project's (or attempt's) answer is never shown, even for the render before the effect.
  const current = state.key === key ? state : { status: 'loading' as const, catalog: null, error: null }
  const currentModels = modelState.key === key ? modelState : { status: 'loading' as const, models: null, error: null }
  return {
    catalog: current.catalog,
    status: current.status,
    error: current.error,
    models: models ? currentModels.models : null,
    modelsStatus: models ? currentModels.status : 'off',
    modelsError: models ? currentModels.error : null,
    pickRefusal,
    retry,
  }
}

/**
 * The owner's key presence for the sections that read the person's own settings to warn about a
 * missing key: undefined outside a collaborator's form (read your own, as before), null while the
 * catalog loads or failed, else `{<settings column>: true}` for every key the owner has set.
 */
export function useOwnerKeys(): Record<string, boolean> | null | undefined {
  const source = useOwnerCatalogSource()
  if (!source) return undefined
  return source.catalog?.keys ?? null
}

/**
 * The settings a missing-key warning reads: the owner's presence flags in a collaborator's form,
 * else the person's own GET /api/users/[id]/settings (null when it fails). Null `ownerKeys` (the
 * catalog loading or failed) answers null: the warning keeps its "not known yet" state.
 */
export async function readKeySettings(
  userId: string,
  ownerKeys: Record<string, boolean> | null | undefined,
): Promise<Record<string, unknown> | null> {
  if (ownerKeys !== undefined) return ownerKeys
  const res = await fetch(`/api/users/${userId}/settings`)
  return res.ok ? res.json() : null
}
