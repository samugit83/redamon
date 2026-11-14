'use client'

/**
 * Upload a Rules of Engagement document and have it read into a review.
 *
 * The parse runs in the RoE store, not in this component, so switching tab or
 * page while the model reads a long document loses nothing: the review waits in
 * the store and a toast says when it is ready.
 */
import { useEffect, useRef, useState } from 'react'
import { Loader2, Upload } from 'lucide-react'
import { useToast } from '@/components/ui'
import { FeatureModelLine, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { ACCEPT_ATTRIBUTE, ALLOWED_EXTENSIONS_LABEL, MAX_FILE_SIZE } from '@/lib/roe/limits'
import { useProjectAccess } from '@/hooks/useRefusal'
import { readsOwnerCatalog } from '@/hooks/useProjectOwnerCatalog'
import { readRoeError } from './roeClient'
import { startRoeParse, useRoeEntry, useRoeMounted } from './roeParseStore'

export interface RoeUploadButtonProps {
  /** The store key: the project id, or 'create'. */
  storeKey: string
  /** An existing project: the parse is a replace review against its stored row. */
  projectId?: string | null
  hasDocument: boolean
  /** A project being created: the form's values, so the result is a diff. */
  currentForDiff?: () => Record<string, unknown>
  onFileSelected?: (file: File) => void
  className?: string
  showModelLine?: boolean
  /** Hide the format hint, for a toolbar. */
  compact?: boolean
}

// "Your model" would point a collaborator at a model only the owner can choose or change.
const OWNER_MODEL_ERRORS: Record<string, string> = {
  model_required: "The project's owner has not chosen an RoE parsing model; only the owner can choose one",
  model_unavailable: "The project owner's RoE parsing model could not be used",
}

function elapsed(since: number | null, now: number): string {
  if (!since) return '0:00'
  const s = Math.max(0, Math.floor((now - since) / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export function RoeUploadButton({
  storeKey, projectId, hasDocument, currentForDiff, onFileSelected, className, showModelLine = true, compact = false,
}: RoeUploadButtonProps) {
  useRoeMounted(storeKey)
  const entry = useRoeEntry(storeKey)
  const inputRef = useRef<HTMLInputElement>(null)
  const { ensureFeatureModel, fetchWithFeatureModel } = useFeatureModelGate()
  // An existing project the person does not own is parsed on its OWNER's model (step 5.6), by the
  // rule the reports page and the project form read the owner's catalog with; a project being
  // created is the caller's own.
  const access = useProjectAccess(projectId || null)
  const ownerModel = !!projectId && readsOwnerCatalog(access)
  const toast = useToast()
  const [now, setNow] = useState(() => Date.now())
  const [localError, setLocalError] = useState<string | null>(null)
  const parsing = entry.status === 'parsing'

  useEffect(() => {
    if (!parsing) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [parsing])

  const handleFile = async (file: File) => {
    setLocalError(null)
    if (file.size > MAX_FILE_SIZE) {
      setLocalError(`The file is larger than ${MAX_FILE_SIZE / 1024 / 1024} MB.`)
      return
    }
    // The route reads the "RoE parsing" model itself; on the person's own
    // project picking one here only makes sure there is one.
    if (!ownerModel && !(await ensureFeatureModel('roe_parse'))) return
    onFileSelected?.(file)
    const post = () => {
      const form = new FormData()
      form.append('file', file)
      if (projectId) form.append('projectId', projectId)
      // Narrowed to the fields a document could propose: the form also holds
      // stored credentials, and a value that does not need to travel should not.
      if (currentForDiff) form.append('current', JSON.stringify(currentForDiff()))
      return fetch('/api/roe/parse', { method: 'POST', body: form })
    }
    void startRoeParse(
      storeKey,
      file,
      ownerModel ? post : () => fetchWithFeatureModel('roe_parse', post),
      {
        readError: async res => {
          const err = await readRoeError(res)
          return (ownerModel && err.code && OWNER_MODEL_ERRORS[err.code]) || err.error
        },
        notifyUnmounted: outcome => toast.addToast({
          type: outcome === 'review' ? 'info' : 'error',
          title: outcome === 'review' ? 'RoE ready to review' : 'RoE parse failed',
          message: outcome === 'review'
            ? `${file.name} has been read. Open the RoE tab to review and confirm it.`
            : `${file.name} could not be read. Open the RoE tab for the reason.`,
          duration: 0,
          ...(projectId
            ? { action: { label: 'Review', onClick: () => { window.location.href = `/projects/${projectId}/settings?tab=roe` } } }
            : {}),
        }),
      },
    )
  }

  const error = localError ?? (entry.status === 'error' ? entry.error : null)
  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPT_ATTRIBUTE}
        style={{ display: 'none' }}
        data-testid={`roe-file-input-${storeKey}`}
        onChange={(e) => {
          const file = e.target.files?.[0]
          // Cleared so choosing the same file again, after a cancelled model
          // prompt or a failed parse, fires again.
          e.target.value = ''
          if (file) void handleFile(file)
        }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <button
          type="button"
          className="secondaryButton"
          onClick={() => inputRef.current?.click()}
          disabled={parsing || entry.status === 'review'}
          style={{ width: 'fit-content' }}
        >
          {parsing ? (
            <>
              <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
              Reading document… {elapsed(entry.startedAt, now)}
            </>
          ) : (
            <>
              <Upload size={14} />
              {hasDocument ? 'Replace RoE' : 'Upload RoE'}
            </>
          )}
        </button>
        {showModelLine && (ownerModel ? (
          <span
            data-feature-model="roe_parse"
            style={{ fontSize: 11, color: 'var(--form-ink-muted)' }}
            title="The document is read by the project owner's RoE parsing model, which only the owner changes, in their Global Settings"
          >
            Model: the project owner&apos;s
          </span>
        ) : <FeatureModelLine featureId="roe_parse" />)}
      </div>
      {parsing && (
        <span style={{ fontSize: 11, lineHeight: 1.5, color: 'var(--form-ink-muted)' }}>
          Large documents can take 2–4 minutes. You can switch tabs; the review waits for you.
        </span>
      )}
      {!parsing && !error && !compact && (
        <span style={{ fontSize: 11, lineHeight: 1.5, color: 'var(--form-ink-muted)' }}>
          {ALLOWED_EXTENSIONS_LABEL}, up to {MAX_FILE_SIZE / 1024 / 1024} MB.
        </span>
      )}
      {error && (
        <span role="alert" style={{ fontSize: 11, color: 'var(--form-danger)' }}>{error}</span>
      )}
    </div>
  )
}
