'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { RotateCw, X } from 'lucide-react'
import { useToast } from '@/components/ui'
import { ModelPicker } from '@/components/shared/ModelPicker'
import {
  fetchModelOptions,
  fetchSavedFeatureModels,
  saveFeatureModel,
  type GateFeatureId,
  type ModelsByProvider,
} from '@/components/shared/FeatureModelGate'
import { getDisplayName } from '@/app/graph/components/AIAssistantDrawer/modelUtils'
import { ApiError, fetchJson, formatApiError, toApiError } from '@/lib/apiError'
import { LLM_FEATURES, isPluginFeatureId, modelAllowedForFeature, type PluginFeatureId } from '@/lib/llmFeatures'
import { isLoopModel } from '@/lib/agentInTheLoop'
import styles from './FeatureModelsSection.module.css'

interface FeatureModelsSectionProps {
  userId: string | null
  providersCount: number
  providersLoading: boolean
}

type LoadState = 'loading' | 'ready' | 'error'
type TileStatus = 'set' | 'unset' | 'removed'

/** A plugin the user can choose a model for (GET /api/plugins/llm-features). */
interface PluginFeature {
  featureId: PluginFeatureId
  label: string
  description: string
}

const PLUGINS_FAILED = 'Plugin items could not be loaded'

// A failed list means no plugin tile and a one-line notice; the core features never wait
// on it.
async function fetchPluginFeatures(): Promise<{ features: PluginFeature[]; error: ApiError | null }> {
  try {
    const data = await fetchJson<unknown>('/api/plugins/llm-features', { cache: 'no-store' }, PLUGINS_FAILED)
    if (!Array.isArray(data)) return { features: [], error: null }
    const features = data.filter(
      (f): f is PluginFeature =>
        !!f && isPluginFeatureId(f.featureId) && typeof f.label === 'string' && typeof f.description === 'string',
    )
    return { features, error: null }
  } catch (err) {
    return { features: [], error: toApiError(err, PLUGINS_FAILED) }
  }
}

interface TileFeature {
  id: GateFeatureId
  label: string
  description: string
  hint?: string
  alsoEditedIn?: string[]
  /** Model ids this feature may use; a plugin feature may use any. */
  allowed?: (modelId: string) => boolean
  plugin?: boolean
}

const STATUS_LABEL: Record<TileStatus, string> = {
  set: 'Set',
  unset: 'Not set',
  removed: 'Provider removed',
}

/**
 * Global Settings → LLM Providers → "Models by feature": one tile per AI
 * feature, each saving that feature's model for the user, then one per plugin
 * that may call a model (badged "plugin"). The whole grid shares ONE
 * /api/models call, handed to every picker.
 */
export function FeatureModelsSection({ userId, providersCount, providersLoading }: FeatureModelsSectionProps) {
  const toast = useToast()
  const [saved, setSaved] = useState<Record<string, string>>({})
  const [savedState, setSavedState] = useState<LoadState>('loading')
  const [savedError, setSavedError] = useState<ApiError | null>(null)
  const [models, setModels] = useState<ModelsByProvider>({})
  const [modelsState, setModelsState] = useState<LoadState>('loading')
  const [modelsError, setModelsError] = useState<ApiError | null>(null)
  const [savingId, setSavingId] = useState<string | null>(null)
  const [plugins, setPlugins] = useState<PluginFeature[]>([])
  const [pluginsError, setPluginsError] = useState<ApiError | null>(null)
  const [pluginsGeneration, setPluginsGeneration] = useState(0)
  const noProviders = !providersLoading && providersCount === 0

  useEffect(() => {
    if (!userId) return
    let live = true
    void fetchPluginFeatures().then(({ features, error }) => {
      if (!live) return
      setPlugins(features)
      setPluginsError(error)
    })
    return () => { live = false }
  }, [userId, pluginsGeneration])

  useEffect(() => {
    if (!userId) return
    let live = true
    fetchSavedFeatureModels(userId)
      .then(map => { if (live) { setSaved(map); setSavedState('ready') } })
      .catch(err => {
        if (!live) return
        setSavedError(toApiError(err, 'Could not read your settings'))
        setSavedState('error')
      })
    return () => { live = false }
  }, [userId])

  const loadModels = useCallback(async () => {
    if (!userId) return
    setModelsState('loading')
    try {
      setModels(await fetchModelOptions(userId))
      setModelsState('ready')
    } catch (err) {
      setModelsError(toApiError(err, 'Failed to load models'))
      setModelsState('error')
    }
  }, [userId])

  // Refetched when the provider count changes: a new provider brings new models.
  useEffect(() => {
    if (providersLoading || providersCount === 0) return
    void loadModels()
  }, [loadModels, providersLoading, providersCount])

  const modelIds = useMemo(
    () => new Set(Object.values(models).flatMap(list => list.map(m => m.id))),
    [models],
  )

  const statusOf = (model: string): TileStatus => {
    if (!model) return 'unset'
    if (modelsState === 'ready' && !modelIds.has(model)) return 'removed'
    return 'set'
  }

  const save = async (feature: TileFeature, model: string) => {
    if (!userId || savingId) return
    if (model === (saved[feature.id] ?? '')) return
    setSavingId(feature.id)
    try {
      const merged = await saveFeatureModel(userId, feature.id, model)
      setSaved(merged)
      toast.success(model
        ? `${feature.label} now uses ${getDisplayName(model, models)}`
        : `${feature.label} has no model now`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Could not save the ${feature.label} model`)
    } finally {
      setSavingId(null)
    }
  }

  const loading = !noProviders && (providersLoading || savedState === 'loading' || modelsState === 'loading')

  const tiles: TileFeature[] = [
    ...LLM_FEATURES.map(f => ({ ...f, allowed: (id: string) => modelAllowedForFeature(f.id, id) })),
    ...plugins.map(p => ({
      id: p.featureId, label: p.label, description: p.description, plugin: true,
      allowed: (id: string) => !isLoopModel(id),
    })),
  ]

  return (
    <section className={styles.section} aria-labelledby="feature-models-title">
      <h3 id="feature-models-title" className={styles.title}>Models by feature</h3>
      <p className={styles.intro}>
        Each feature below uses its own model, in all your projects. A feature with no model asks
        for one the first time you use it.
      </p>

      {noProviders ? (
        <div className={styles.empty}>Add an LLM provider above to choose models for these features</div>
      ) : loading ? (
        <div className={styles.grid} aria-busy="true" aria-label="Loading models by feature">
          {LLM_FEATURES.map(f => (
            <div key={f.id} className={`${styles.tile} ${styles.tileSkeleton}`} data-testid="feature-model-skeleton">
              <span className={`${styles.skel} ${styles.skelTitle}`} />
              <span className={`${styles.skel} ${styles.skelLine}`} />
              <span className={`${styles.skel} ${styles.skelPicker}`} />
              <span className={`${styles.skel} ${styles.skelLine}`} />
            </div>
          ))}
        </div>
      ) : (
        <>
          {savedState === 'error' && (
            <div className={styles.notice} role="alert">
              {savedError ? formatApiError({ ...savedError, reason: "Couldn't read your saved models" }) : "Couldn't read your saved models"}.
              {' '}Reload the page to try again.
            </div>
          )}
          {modelsState === 'error' && modelsError && (
            <div className={styles.notice} role="alert">
              {formatApiError({ ...modelsError, reason: "Couldn't load your models" })}. Retry on any feature below.
            </div>
          )}
          <div className={styles.grid}>
            {tiles.map(feature => {
              const model = saved[feature.id] ?? ''
              const status = statusOf(model)
              // Every tile waits while one saves: `save` takes one at a time,
              // and a pick made meanwhile would snap back, unsaved and unsaid.
              const busy = savingId !== null
              return (
                <div key={feature.id} className={styles.tile} data-feature={feature.id}>
                  <div className={styles.tileHead}>
                    <span className={styles.tileName}>
                      <span className={styles.tileLabel}>{feature.label}</span>
                      {feature.plugin && (
                        <span className={styles.pluginBadge} title="A RedAmon plugin, not a built-in feature">plugin</span>
                      )}
                    </span>
                    <span className={`${styles.chip} ${styles[`chip_${status}`]}`}>{STATUS_LABEL[status]}</span>
                  </div>
                  <p className={styles.tileDesc}>{feature.description}</p>

                  {modelsState === 'error' ? (
                    <div className={styles.readOnly}>
                      <span className={styles.readOnlyValue} title={model || undefined}>{model || 'Not set'}</span>
                      <button type="button" className="textButton" onClick={() => void loadModels()}>
                        <RotateCw size={11} /> Retry
                      </button>
                    </div>
                  ) : (
                    <div className={styles.pickerRow}>
                      <div className={styles.picker}>
                        <ModelPicker
                          userId={userId}
                          value={model}
                          onChange={id => void save(feature, id)}
                          models={models}
                          hideManualFallback
                          filter={feature.allowed}
                          disabled={busy || savedState !== 'ready'}
                          emptyLabel="Choose a model"
                        />
                      </div>
                      {model && (
                        <button
                          type="button"
                          className={`iconButton ${styles.clear}`}
                          onClick={() => void save(feature, '')}
                          disabled={busy}
                          title={`Clear the ${feature.label} model`}
                          aria-label={`Clear the ${feature.label} model`}
                        >
                          <X size={12} />
                        </button>
                      )}
                    </div>
                  )}

                  {feature.hint && <p className={styles.tileHint}>{feature.hint}</p>}
                  {feature.alsoEditedIn && feature.alsoEditedIn.length > 0 && (
                    <p className={styles.tileAlso}>Also in: {feature.alsoEditedIn.join(', ')}</p>
                  )}
                </div>
              )
            })}
          </div>
          {pluginsError && (
            <div className={styles.notice} role="alert">
              {formatApiError({ ...pluginsError, reason: PLUGINS_FAILED })} ·{' '}
              <button type="button" className="textButton" onClick={() => setPluginsGeneration(g => g + 1)}>
                <RotateCw size={11} /> Retry
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}
