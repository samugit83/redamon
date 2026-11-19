'use client'

import { useState, useEffect } from 'react'
import { Loader2, AlertTriangle, Sparkles, RotateCcw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useToast, WikiInfoButton } from '@/components/ui'
import { FeatureModelLine, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'
import { field, tool } from '@/lib/reconSettings/registry'
import formStyles from './ProjectForm.module.css'
import styles from './GeneratePresetModal.module.css'

interface GeneratePresetModalProps {
  isOpen: boolean
  onClose: () => void
  onSaved: () => void
  userId: string | null | undefined
}

// The registry names tools, not the feature toggles inside them, so a feature
// is read off its key; these words would otherwise come out as "Ai", "Mcp".
const ACRONYMS: Record<string, string> = {
  Ai: 'AI', Db: 'DB', Mcp: 'MCP', Ns: 'NS', Openapi: 'OpenAPI', Rag: 'RAG', Sdk: 'SDK', Txt: 'TXT', Yara: 'YARA',
}

const capitalize = (w: string) => w.charAt(0).toUpperCase() + w.slice(1)
const camelId = (id: string) => id.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())

/**
 * A readable name for a generated preset's `*Enabled` key, from the registry.
 *
 * A tool's own switch is the tool's title (`tlsxEnabled` -> "tlsx"); a feature
 * toggle inside a tool is the title and the rest of the key
 * (`nucleiTakeoversEnabled` -> "Nuclei: Takeovers"). A hand-kept map of names
 * missed every tool added after it.
 */
export function enabledKeyLabel(key: string): string {
  const bare = key.replace(/Enabled$/, '')
  const spec = field(key)
  const owner = spec ? tool(spec.tool) : undefined
  if (!spec || !owner) return bare
  const prefix = camelId(spec.tool)
  if ((spec.runtime_key != null && spec.runtime_key === owner.enabled_key) || bare === prefix) {
    return owner.title
  }
  const rest = bare.startsWith(prefix) ? bare.slice(prefix.length) : bare
  const words = rest.match(/[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])/g) ?? [rest]
  const feature = words
    .map((w, i) => ACRONYMS[capitalize(w)] ?? (i === 0 ? capitalize(w) : w.toLowerCase()))
    .join(' ')
  return `${owner.title}: ${feature}`
}

/** Summarise the generated parameters for the review step. */
function buildSummary(params: Record<string, unknown>) {
  const enabled: string[] = []
  const disabled: string[] = []
  const tuned: string[] = []

  for (const [key, value] of Object.entries(params)) {
    if (key.endsWith('Enabled') && typeof value === 'boolean') {
      const name = enabledKeyLabel(key)
      if (value) enabled.push(name)
      else disabled.push(name)
    } else if (!key.endsWith('Enabled')) {
      tuned.push(key)
    }
  }

  return { enabled, disabled, tunedCount: tuned.length }
}

export function GeneratePresetModal({
  isOpen,
  onClose,
  onSaved,
  userId,
}: GeneratePresetModalProps) {
  const toast = useToast()
  const { ensureFeatureModel, fetchWithFeatureModel } = useFeatureModelGate()

  // Step state
  const [step, setStep] = useState<'describe' | 'review'>('describe')
  const [prompt, setPrompt] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [errorDetails, setErrorDetails] = useState<string[]>([])
  const [generatedParams, setGeneratedParams] = useState<Record<string, unknown> | null>(null)

  // Save fields
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Reset on open
  useEffect(() => {
    if (isOpen) {
      setStep('describe')
      setPrompt('')
      setError(null)
      setErrorDetails([])
      setGeneratedParams(null)
      setName('')
      setDescription('')
    }
  }, [isOpen])

  const handleGenerate = async () => {
    if (!prompt.trim() || !userId) return

    setError(null)
    setErrorDetails([])
    // The route runs the user's saved "Recon preset generator" model and takes
    // none from the request; this only makes sure one is saved.
    if (!(await ensureFeatureModel('preset_generator'))) return
    setIsGenerating(true)

    try {
      const res = await fetchWithFeatureModel('preset_generator', () => fetch('/api/presets/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt.trim() }),
      }))

      if (!res.ok) {
        const err = await readApiError(res, 'Failed to generate preset')
        const code = readFeatureModelCode(err.body)
        // model_unavailable keeps the route's own text: for Bedrock it says why.
        setError(code && code !== 'model_unavailable' ? featureModelMessage(code) : err.message)
        if (err.details) setErrorDetails(err.details)
        return
      }

      const data = await res.json().catch(() => null)
      if (!data) throw new ApiError({ reason: 'Failed to generate preset', status: res.status, code: 'invalid_json' })
      setGeneratedParams(data.parameters)
      setDescription(prompt.trim())
      setStep('review')
    } catch (err) {
      setError(toApiError(err, 'Network error. Check your connection and try again.').message)
    } finally {
      setIsGenerating(false)
    }
  }

  const handleSave = async () => {
    if (!name.trim() || !userId || !generatedParams) return

    setIsSaving(true)
    try {
      const res = await fetch('/api/presets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: name.trim(),
          description: description.trim(),
          settings: generatedParams,
        }),
      })

      if (!res.ok) throw await readApiError(res, 'Failed to save preset')

      toast.success(`Preset "${name.trim()}" saved`, 'Preset Created')
      onSaved()
      onClose()
    } catch (err) {
      toast.error(toApiError(err, 'Failed to save preset').message)
    } finally {
      setIsSaving(false)
    }
  }

  const handleRegenerate = () => {
    setStep('describe')
    setGeneratedParams(null)
    setError(null)
    setErrorDetails([])
    setName('')
  }

  const summary = generatedParams ? buildSummary(generatedParams) : null

  // -- Describe step --
  if (step === 'describe') {
    return (
      <Modal
        isOpen={isOpen}
        onClose={onClose}
        title="Generate Recon Preset with AI"
        size="large"
        closeOnOverlayClick={false}
        closeOnEscape={false}
        headerActions={<WikiInfoButton target="ReconPreset" title="Open Recon Presets wiki page" />}
        footer={
          <>
            <button type="button" className="secondaryButton" onClick={onClose} disabled={isGenerating}>
              Cancel
            </button>
            <button
              type="button"
              className="primaryButton"
              onClick={handleGenerate}
              disabled={isGenerating || !prompt.trim()}
            >
              {isGenerating ? (
                <>
                  <Loader2 size={14} className={formStyles.spinner} />
                  Generating...
                </>
              ) : (
                <>
                  <Sparkles size={14} />
                  Generate
                </>
              )}
            </button>
          </>
        }
      >
        <div className={styles.promptArea}>
          <div className={styles.modelBadge}>
            <Sparkles size={12} />
            <FeatureModelLine featureId="preset_generator" />
          </div>

          <textarea
            className={`textarea ${styles.promptTextarea}`}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="Describe the reconnaissance strategy you want, e.g.:\n- Fast passive scan focused on subdomain discovery and OSINT, no active probing\n- Deep web app pentest with full crawling, directory fuzzing, and nuclei on all severities\n- Stealth mode: minimal noise, only passive tools, no port scanning"
            rows={5}
            autoFocus
            disabled={isGenerating}
          />

          {error && (
            <div className={styles.errorBanner}>
              <AlertTriangle size={14} />
              <div>
                {error}
                {errorDetails.length > 0 && (
                  <ul className={styles.errorDetails}>
                    {errorDetails.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      </Modal>
    )
  }

  // -- Review & Save step --
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Review Generated Preset"
      size="large"
      closeOnOverlayClick={false}
      closeOnEscape={false}
      headerActions={<WikiInfoButton target="ReconPreset" title="Open Recon Presets wiki page" />}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={handleRegenerate} disabled={isSaving}>
            <RotateCcw size={14} />
            Regenerate
          </button>
          <button
            type="button"
            className="primaryButton"
            onClick={handleSave}
            disabled={isSaving || !name.trim()}
          >
            {isSaving ? (
              <>
                <Loader2 size={14} className={formStyles.spinner} />
                Saving...
              </>
            ) : (
              'Save Preset'
            )}
          </button>
        </>
      }
    >
      <div className={styles.reviewArea}>
        {/* Summary */}
        {summary && (
          <div className={styles.summaryBox}>
            <h4>Generated Configuration</h4>
            {summary.enabled.length > 0 && (
              <div className={styles.summaryRow}>
                <span className={styles.summaryLabel}>Enabled:</span>
                <span className={styles.summaryValue}>
                  {summary.enabled.map((t) => (
                    <span key={t} className={styles.enabledTag}>{t}</span>
                  ))}
                </span>
              </div>
            )}
            {summary.disabled.length > 0 && (
              <div className={styles.summaryRow}>
                <span className={styles.summaryLabel}>Disabled:</span>
                <span className={styles.summaryValue}>
                  {summary.disabled.map((t) => (
                    <span key={t} className={styles.disabledTag}>{t}</span>
                  ))}
                </span>
              </div>
            )}
            {summary.tunedCount > 0 && (
              <div className={styles.summaryRow}>
                <span className={styles.summaryLabel}>Tuned:</span>
                <span className={styles.summaryValue}>{summary.tunedCount} numeric/array parameters adjusted</span>
              </div>
            )}
          </div>
        )}

        {/* Name & Description */}
        <div className={styles.formFields}>
          <div>
            <label className={`${formStyles.fieldLabel} ${formStyles.fieldLabelRequired}`}>
              Name
            </label>
            <input
              type="text"
              className="textInput"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Fast OSINT Scan"
              autoFocus
            />
          </div>
          <div>
            <label className={formStyles.fieldLabel}>
              Description
            </label>
            <textarea
              className="textarea"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              rows={3}
            />
          </div>
        </div>
      </div>
    </Modal>
  )
}
