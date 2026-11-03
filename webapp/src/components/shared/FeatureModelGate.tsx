'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { ExternalLink, Loader2, RotateCw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { useProject } from '@/providers/ProjectProvider'
import { fetchJson, formatApiError, toApiError } from '@/lib/apiError'
import { fetchModelOptions, type ModelsByProvider } from './modelOptions'
import {
  GATE_CODES,
  featureModelMessage,
  getLlmFeature,
  isPluginFeatureId,
  modelAllowedForFeature,
  readFeatureModelCode,
  type FeatureId,
  type PluginFeatureId,
} from '@/lib/llmFeatures'
import { isLoopModel } from '@/lib/agentInTheLoop'
import styles from './FeatureModelGate.module.css'

/** A core feature, or a plugin's own entry (`plugin:<id>`, TD-10). */
export type GateFeatureId = FeatureId | PluginFeatureId

/** What the caller knows about a plugin feature: the gate cannot look a plugin up. */
export interface PluginFeatureText {
  label?: string
  description?: string
}

interface FeatureText {
  label: string
  description: string
  hint: string
}

/**
 * The words the gate shows. getLlmFeature knows only core features and throws for any
 * other id, so a plugin feature's label comes from the caller (its manifest's name).
 */
function featureText(featureId: GateFeatureId, plugin: PluginFeatureText = {}): FeatureText {
  if (!isPluginFeatureId(featureId)) return getLlmFeature(featureId)
  return {
    label: plugin.label || 'this plugin',
    description: plugin.description || 'The model this plugin runs on, in all your projects.',
    hint: '',
  }
}

// Plugin features have no excluded models of their own; Agent in the Loop is
// excluded everywhere, because it answers only inside a chat run.
const allowedFor = (featureId: GateFeatureId) => (id: string) =>
  isPluginFeatureId(featureId) ? !isLoopModel(id) : modelAllowedForFeature(featureId, id)

// ---------------------------------------------------------------------------
// Client calls shared by the gate and the Models by feature section
// ---------------------------------------------------------------------------

export { fetchModelOptions, type ModelsByProvider }

function stringMap(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  return Object.fromEntries(
    Object.entries(raw as Record<string, unknown>).filter((e): e is [string, string] => typeof e[1] === 'string'),
  )
}

/** Throws an ApiError whose message carries the code and HTTP status of the failed read. */
export async function fetchSavedFeatureModels(userId: string): Promise<Record<string, string>> {
  const data = await fetchJson<{ featureModels?: unknown } | null>(
    `/api/users/${encodeURIComponent(userId)}/settings`, undefined, 'Could not read your settings')
  return stringMap(data?.featureModels)
}

/** Save one feature's model ('' clears it). Resolves with the whole saved map. */
export async function saveFeatureModel(
  userId: string,
  featureId: GateFeatureId,
  model: string,
): Promise<Record<string, string>> {
  const res = await fetch(`/api/users/${encodeURIComponent(userId)}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ featureModels: { [featureId]: model } }),
  })
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    throw new Error(typeof body?.error === 'string' ? body.error : `Could not save the model (${res.status})`)
  }
  return stringMap(body?.featureModels)
}

export function countModels(models: ModelsByProvider, keep?: (id: string) => boolean): number {
  let n = 0
  for (const list of Object.values(models)) {
    for (const m of list) if (!keep || keep(m.id)) n++
  }
  return n
}

export const SETTINGS_PROVIDERS_URL = '/settings?tab=providers'

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

export interface FeatureModelGateProps {
  featureId: GateFeatureId
  /** For a plugin feature: its name and description (a core feature has its own). */
  label?: string
  description?: string
  userId: string | null
  /** Shown above the picker, e.g. why the saved model could not be used. */
  message?: string
  /** Render the body alone, for embedding in another dialog. */
  inline?: boolean
  confirmLabel?: string
  onSaved: (model: string) => void
  onCancel: () => void
}

type LoadState = 'loading' | 'ready' | 'error'

/**
 * Asks for the model a feature runs on and saves it to the user's settings.
 * Only the models this feature may use are listed, and there is no free-text
 * fallback: a typed id could name a provider the user does not have.
 */
export function FeatureModelGate({
  featureId,
  label,
  description,
  userId,
  message,
  inline = false,
  confirmLabel = 'Save and continue',
  onSaved,
  onCancel,
}: FeatureModelGateProps) {
  const feature = featureText(featureId, { label, description })
  const [models, setModels] = useState<ModelsByProvider>({})
  const [loadState, setLoadState] = useState<LoadState>('loading')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [picked, setPicked] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const allowed = useMemo(() => allowedFor(featureId), [featureId])

  const load = useCallback(async () => {
    if (!userId) {
      setLoadError(null)
      setLoadState('error')
      return
    }
    setLoadState('loading')
    try {
      setModels(await fetchModelOptions(userId))
      setLoadState('ready')
    } catch (err) {
      setLoadError(toApiError(err, 'Failed to load models').message)
      setLoadState('error')
    }
  }, [userId])

  useEffect(() => { void load() }, [load])

  const total = countModels(models)
  const usable = countModels(models, allowed)

  const save = async () => {
    if (!userId || !picked || saving) return
    setSaving(true)
    setSaveError(null)
    try {
      await saveFeatureModel(userId, featureId, picked)
      onSaved(picked)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Could not save the model')
    } finally {
      setSaving(false)
    }
  }

  const providerActions = (
    <div className={styles.inlineActions}>
      <button
        type="button"
        className="secondaryButton"
        onClick={() => window.open(SETTINGS_PROVIDERS_URL, '_blank', 'noopener')}
      >
        <ExternalLink size={12} /> Add provider
      </button>
      <button type="button" className="secondaryButton" onClick={() => void load()}>
        <RotateCw size={12} /> Check again
      </button>
    </div>
  )

  const body = (
    <div className={styles.body}>
      <div>
        {inline && <div className={styles.featureName}>{feature.label}</div>}
        <p className={styles.featureDescription}>{feature.description}</p>
      </div>

      {message && <div className={styles.message} role="alert">{message}</div>}

      {loadState === 'loading' && (
        <div className={styles.status}><Loader2 size={14} className={styles.spin} /> Loading your models...</div>
      )}

      {loadState === 'error' && (
        <div className={styles.emptyBox}>
          <span>Couldn&apos;t load your models.</span>
          {loadError && <span role="alert">{loadError}</span>}
          <div className={styles.inlineActions}>
            <button type="button" className="secondaryButton" onClick={() => void load()}>
              <RotateCw size={12} /> Check again
            </button>
          </div>
        </div>
      )}

      {loadState === 'ready' && total === 0 && (
        <div className={styles.emptyBox}>
          <span className={styles.emptyTitle}>You have no LLM provider yet</span>
          <span>Add one in Global Settings, then check again.</span>
          {providerActions}
        </div>
      )}

      {loadState === 'ready' && total > 0 && usable === 0 && (
        <div className={styles.emptyBox}>
          <span className={styles.emptyTitle}>None of your models can run {feature.label}</span>
          {feature.hint && <span>{feature.hint}</span>}
          {providerActions}
        </div>
      )}

      {loadState === 'ready' && usable > 0 && (
        <div className={styles.pickerField}>
          <ModelPicker
            userId={userId}
            value={picked}
            onChange={setPicked}
            models={models}
            hideManualFallback
            filter={allowed}
            disabled={saving}
            emptyLabel="Choose a model"
          />
          {feature.hint && <span className={styles.hint}>{feature.hint}</span>}
        </div>
      )}

      {saveError && <div className={styles.error} role="alert">{saveError}</div>}

      <p className={styles.note}>
        Saved for your account; also in Global Settings → LLM Providers → Models by feature
      </p>
    </div>
  )

  const buttons = (
    <>
      <button type="button" className="secondaryButton" onClick={onCancel} disabled={saving}>
        Cancel
      </button>
      <button
        type="button"
        className="primaryButton"
        onClick={() => void save()}
        disabled={!picked || saving}
      >
        {saving && <Loader2 size={12} className={styles.spin} />}
        {confirmLabel}
      </button>
    </>
  )

  if (inline) {
    return (
      <div className={styles.inline}>
        {body}
        <div className={styles.inlineFooter}>{buttons}</div>
      </div>
    )
  }

  return (
    <Modal
      isOpen
      onClose={saving ? () => {} : onCancel}
      title={`Choose a model for ${feature.label}`}
      className={styles.dialog}
      footer={buttons}
    >
      {body}
    </Modal>
  )
}

// ---------------------------------------------------------------------------
// Provider + hook
// ---------------------------------------------------------------------------

export interface EnsureFeatureModelOptions extends PluginFeatureText {
  /** Open the gate even when a model is saved (the saved one failed, or the user asked to change it). */
  force?: boolean
  message?: string
}

export interface FeatureModelGateApi {
  /**
   * The model to run `featureId` on: the saved one, else the one the user
   * picks in the gate. null when the user cancels.
   */
  ensureFeatureModel: (featureId: GateFeatureId, opts?: EnsureFeatureModelOptions) => Promise<string | null>
  /**
   * Run a request that may answer model_required / model_unavailable. On
   * either, the gate opens and, once a model is picked, the request runs ONE
   * more time. Any other answer, including every agent_* and
   * providers_unreachable code, comes back untouched: another model would not
   * fix those, so the caller shows featureModelMessage(code) instead.
   */
  fetchWithFeatureModel: (
    featureId: GateFeatureId,
    doFetch: () => Promise<Response>,
    plugin?: PluginFeatureText,
  ) => Promise<Response>
  /** Whose models the gate reads and saves; null outside the provider. */
  userId: string | null
  /** Bumped whenever the gate saves a model, so lines showing one can refetch. */
  savedVersion: number
}

// Without a provider mounted the hook degrades to "no gate": the request runs
// as is and ensureFeatureModel answers null, so a component rendered on its
// own (in a test, say) behaves exactly as it did before the gate existed.
const NO_GATE: FeatureModelGateApi = {
  ensureFeatureModel: async () => null,
  fetchWithFeatureModel: (_featureId, doFetch) => doFetch(),
  userId: null,
  savedVersion: 0,
}

const FeatureModelGateContext = createContext<FeatureModelGateApi>(NO_GATE)

export function useFeatureModelGate(): FeatureModelGateApi {
  return useContext(FeatureModelGateContext)
}

interface PendingGate {
  id: number
  featureId: GateFeatureId
  plugin: PluginFeatureText
  message?: string
  resolve: (model: string | null) => void
}

export function FeatureModelGateProvider({ children }: { children: ReactNode }) {
  const { userId } = useProject()
  const [open, setOpen] = useState<PendingGate | null>(null)
  const [savedVersion, setSavedVersion] = useState(0)
  // The promise of the gate on screen. A second request settles the first
  // with null (cancelled) rather than leaving its caller waiting forever.
  const pendingRef = useRef<PendingGate | null>(null)
  const seqRef = useRef(0)

  const openGate = useCallback((featureId: GateFeatureId, message: string | undefined, plugin: PluginFeatureText) => {
    return new Promise<string | null>(resolve => {
      pendingRef.current?.resolve(null)
      const next: PendingGate = { id: ++seqRef.current, featureId, plugin, message, resolve }
      pendingRef.current = next
      setOpen(next)
    })
  }, [])

  // Settles the gate `id` only. A gate replaced while it was saving still
  // finishes its save, and its answer belongs to a request already settled
  // with null, never to the gate on screen now (another feature's, maybe).
  const settle = useCallback((id: number, model: string | null) => {
    if (model) setSavedVersion(v => v + 1)
    const pending = pendingRef.current
    if (!pending || pending.id !== id) return
    pendingRef.current = null
    setOpen(null)
    pending.resolve(model)
  }, [])

  const ensureFeatureModel = useCallback(async (featureId: GateFeatureId, opts: EnsureFeatureModelOptions = {}) => {
    if (!userId) return null
    let message = opts.message
    if (!opts.force) {
      try {
        const saved = (await fetchSavedFeatureModels(userId))[featureId]
        if (saved) return saved
      } catch (err) {
        // Unreadable settings: asking is better than blocking the action, but the gate
        // says why it asks, or it reads as if no model had ever been saved.
        const read = toApiError(err, 'Could not read your settings')
        message ??= `${formatApiError({ ...read, reason: "Couldn't read your saved model" })}. Choose one to continue.`
      }
    }
    return openGate(featureId, message, { label: opts.label, description: opts.description })
  }, [userId, openGate])

  const fetchWithFeatureModel = useCallback(async (
    featureId: GateFeatureId,
    doFetch: () => Promise<Response>,
    plugin: PluginFeatureText = {},
  ) => {
    const res = await doFetch()
    if (res.ok) return res
    const body: unknown = await res.clone().json().catch(() => null)
    const code = readFeatureModelCode(body)
    if (!code || !GATE_CODES.includes(code)) return res
    const failedModel = (body as { model?: unknown }).model
    const model = await ensureFeatureModel(featureId, {
      ...plugin,
      force: true,
      message: code === 'model_unavailable'
        ? featureModelMessage('model_unavailable', typeof failedModel === 'string' ? failedModel : undefined)
        : undefined,
    })
    return model ? doFetch() : res
  }, [ensureFeatureModel])

  const api = useMemo(
    () => ({ ensureFeatureModel, fetchWithFeatureModel, userId, savedVersion }),
    [ensureFeatureModel, fetchWithFeatureModel, userId, savedVersion],
  )

  return (
    <FeatureModelGateContext.Provider value={api}>
      {children}
      {open && (
        <FeatureModelGate
          key={open.id}
          featureId={open.featureId}
          label={open.plugin.label}
          description={open.plugin.description}
          userId={userId}
          message={open.message}
          onSaved={model => settle(open.id, model)}
          onCancel={() => settle(open.id, null)}
        />
      )}
    </FeatureModelGateContext.Provider>
  )
}

// ---------------------------------------------------------------------------
// "Model: X · Change", shown next to the button that runs a feature
// ---------------------------------------------------------------------------

type LineState = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; model: string }

/**
 * The saved model of a feature, with a link that reopens the gate to change
 * it. Renders nothing outside the provider, so a component tested on its own
 * makes no settings request.
 */
export function FeatureModelLine({
  featureId,
  featureLabel,
  label = 'Model',
  className,
}: {
  featureId: GateFeatureId
  /** A plugin feature's name; a core feature has its own. */
  featureLabel?: string
  label?: string
  className?: string
}) {
  const { userId, savedVersion, ensureFeatureModel } = useFeatureModelGate()
  const [state, setState] = useState<LineState>({ kind: 'loading' })

  useEffect(() => {
    if (!userId) return
    let live = true
    fetchSavedFeatureModels(userId)
      .then(map => { if (live) setState({ kind: 'ready', model: map[featureId] ?? '' }) })
      .catch(err => { if (live) setState({ kind: 'error', message: toApiError(err, 'Could not read your settings').message }) })
    return () => { live = false }
  }, [userId, featureId, savedVersion])

  if (!userId) return null

  const model = state.kind === 'ready' ? state.model : ''
  const shown = state.kind === 'loading' ? '...' : state.kind === 'error' ? 'unknown' : model || 'not set'

  return (
    <span className={`${styles.line} ${className ?? ''}`} data-feature-model={featureId}>
      <span>{label}:</span>
      <span className={styles.lineValue} title={state.kind === 'error' ? state.message : model || undefined}>{shown}</span>
      <span aria-hidden="true">·</span>
      <button
        type="button"
        className={styles.lineChange}
        onClick={() => void ensureFeatureModel(featureId, { force: true, label: featureLabel })}
        aria-label={`Change the ${featureText(featureId, { label: featureLabel }).label} model`}
      >
        {model ? 'Change' : 'Choose'}
      </button>
    </span>
  )
}
