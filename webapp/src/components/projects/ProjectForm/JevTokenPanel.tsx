'use client'

import { useId, useState } from 'react'
import { AlertTriangle, ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { LlmProviderForm } from '@/components/settings/LlmProviderForm'
import { SiTypeSafe } from '@/components/icons/ProviderBrandIcons'
import { JEV_MODEL, JEV_OPENROUTER_MODEL } from '@/lib/llmProviderKinds'
import { notifyJevProviderChanged, useJevProvider, type JevProviderRow } from '@/hooks/useHasJevProvider'
import styles from './AiPipelinePanel.module.css'

const SETTINGS_URL = '/settings?tab=providers'

function label(provider: JevProviderRow): string {
  const backend = provider.providerType === 'jev_openrouter' ? 'OpenRouter' : 'TypeSafe'
  const model = provider.providerType === 'jev_openrouter' ? JEV_OPENROUTER_MODEL : JEV_MODEL
  return `${provider.name || backend} · ${backend} · ${model}`
}

function problemText(missing: boolean, selectedProviderId: string | null): string {
  if (missing) return 'The selected Jev configuration was deleted or is unavailable.'
  if (selectedProviderId) return 'The selected Jev configuration has no saved credential.'
  return 'No Jev provider is selected for this project.'
}

/**
 * The project's Jev provider, next to the AI Model picker in the Target AI panel.
 *
 * The selection belongs to the project; the configurations belong to the project
 * OWNER's account, because the agent resolves the key from the owner. Adding one
 * here is the same as adding it in Global Settings. Nothing is ever selected
 * implicitly: a project with no selection runs every Jev hook on its fallback.
 */
export function JevTokenPanel({ userId, onSelect }: {
  userId: string | null
  onSelect: (providerId: string | null) => void
}) {
  const {
    status, lookupStatus, provider, providers, selectedProviderId, ownerUserId, error, refresh,
  } = useJevProvider()
  const [adding, setAdding] = useState(false)
  const selectId = useId()
  const canManage = !!ownerUserId && ownerUserId === userId && lookupStatus === 'ready'
  const missing = !!selectedProviderId && !providers.some(row => row.id === selectedProviderId)

  return (
    <div className={styles.tokenPanel} data-testid="jev-token-panel">
      <div className={styles.tokenHead}>
        <span className={styles.tokenIcon} aria-hidden="true"><SiTypeSafe size={16} /></span>
        <label className={styles.tokenTitle} htmlFor={selectId}>Jev provider</label>
        {status === 'yes' && <span className={`${styles.chip} ${styles.chipOk}`}>Selected</span>}
        {status === 'no' && <span className={styles.chip}>{missing ? 'Unavailable' : 'Not selected'}</span>}
      </div>

      {lookupStatus === 'loading' && (
        <div className={styles.tokenNote}>
          <Loader2 size={12} className={styles.spin} /> Loading the project owner&apos;s Jev configurations…
        </div>
      )}
      {lookupStatus === 'limited' && (
        <div className={styles.tokenNote} role="alert">
          <AlertTriangle size={12} /> The project owner&apos;s Jev configurations are unavailable in this view.
          No account configuration will be selected automatically.
        </div>
      )}
      {lookupStatus === 'error' && (
        <div className={styles.tokenNote} role="alert">
          <AlertTriangle size={12} /> Couldn&apos;t load the project owner&apos;s Jev configurations. {error}
          <button type="button" className={styles.linkButton} onClick={refresh}>
            <RefreshCw size={11} /> Retry
          </button>
        </div>
      )}

      {lookupStatus === 'ready' && (
        <>
          <select
            id={selectId}
            className="selectInput"
            value={selectedProviderId ?? ''}
            onChange={event => onSelect(event.target.value || null)}
          >
            <option value="">Not configured — deterministic fallback</option>
            {missing && (
              <option value={selectedProviderId!} disabled>Selected configuration unavailable</option>
            )}
            {providers.map(row => (
              <option key={row.id} value={row.id} disabled={!row.apiKey?.trim()}>{label(row)}</option>
            ))}
          </select>
          {status === 'no' && (
            <p className={styles.tokenIntro} role="alert">
              {problemText(missing, selectedProviderId)}
              {' '}Jev hooks use deterministic fallbacks; scan start is not blocked. Select a configuration
              explicitly, including for existing projects.
            </p>
          )}
          {provider && (
            <p className={styles.tokenIntro} data-testid="jev-provider-selected">
              {label(provider)}. Shared by every Jev hook in this project. Saved credentials do not confirm
              live model access; failed calls use deterministic fallbacks.
            </p>
          )}
          {providers.length === 0 && (
            <p className={styles.tokenIntro}>The project owner has no Jev configurations.</p>
          )}
        </>
      )}

      {selectedProviderId && lookupStatus !== 'ready' && (
        <button type="button" className={styles.linkButton} onClick={() => onSelect(null)}>
          Clear Jev selection
        </button>
      )}

      {canManage && (
        <>
          <div className={styles.tokenNote}>
            <button type="button" className={styles.linkButton} onClick={() => setAdding(value => !value)}>
              {adding ? 'Close add form' : 'Add Jev configuration'}
            </button>
            <a className={styles.manageLink} href={SETTINGS_URL} target="_blank" rel="noopener noreferrer">
              Manage <ExternalLink size={11} />
            </a>
          </div>
          {adding && (
            <LlmProviderForm
              userId={ownerUserId!}
              lockedType="jev"
              embedded
              onSave={() => { setAdding(false); notifyJevProviderChanged() }}
              onCancel={() => setAdding(false)}
            />
          )}
        </>
      )}
    </div>
  )
}
