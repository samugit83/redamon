'use client'

import type { ReactNode } from 'react'
import { ExternalLink, Loader2, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { PROVIDER_TYPES, JEV_MODEL } from '@/lib/llmProviderPresets'
import { LlmProviderForm } from './LlmProviderForm'
import type { ProviderData } from './LlmProviderForm'
import settingsStyles from './Settings.module.css'
import styles from './JevProviderSection.module.css'

const JEV_TYPE = PROVIDER_TYPES.find(p => p.id === 'jev')!

interface JevProviderSectionProps {
  userId: string
  providers: ProviderData[]
  loading: boolean
  error: boolean
  errorText?: string
  onRetry: () => void
  formOpen: boolean
  editingProvider: ProviderData | null
  onOpenForm: (provider: ProviderData | null) => void
  onFormDone: (saved: boolean) => void
  onDelete: (providerId: string) => void
  onDirtyChange?: (dirty: boolean) => void
  usageChip?: (provider: ProviderData) => ReactNode
}

export function JevProviderSection({
  userId, providers, loading, error, errorText, onRetry, formOpen, editingProvider,
  onOpenForm, onFormDone, onDelete, onDirtyChange, usageChip,
}: JevProviderSectionProps) {
  let body: ReactNode
  if (loading) {
    body = <div className={settingsStyles.emptyState}><Loader2 size={16} className={settingsStyles.spin} /> Loading...</div>
  } else if (error) {
    body = <div className={styles.error} role="alert">
      <span>{errorText ?? "Couldn't load your providers"}.</span>
      <button type="button" className="secondaryButton" onClick={onRetry}><RefreshCw size={12} /> Retry</button>
    </div>
  } else if (formOpen) {
    body = <LlmProviderForm key={editingProvider?.id ?? 'new-jev'} userId={userId}
      provider={editingProvider} lockedType="jev" onDirtyChange={onDirtyChange}
      onSave={() => onFormDone(true)} onCancel={() => onFormDone(false)} />
  } else {
    body = <div className={styles.empty}>
      <div className={styles.emptyActions}>
        <button type="button" className="primaryButton" onClick={() => onOpenForm(null)}><Plus size={14} /> Add Jev provider</button>
        <a className={settingsStyles.apiKeyLink} href={JEV_TYPE.apiKeyUrl} target="_blank" rel="noopener noreferrer">
          Get a TypeSafe API key <ExternalLink size={12} />
        </a>
      </div>
      {providers.length === 0 && <span>No Jev providers configured. Add a named entry, then explicitly select it in each project.</span>}
      {providers.map(provider => {
        const type = PROVIDER_TYPES.find(p => p.id === provider.providerType)!
        const Icon = type.Icon
        return <div className={settingsStyles.providerCard} key={provider.id}>
          <span className={settingsStyles.providerIcon} aria-label={type.name}><Icon size={28} /></span>
          <div className={settingsStyles.providerInfo}>
            <div className={settingsStyles.providerName}>{provider.name || type.name}</div>
            <div className={settingsStyles.providerMeta}>{type.name} — <span data-testid="jev-masked-key">{provider.apiKey}</span> — {provider.modelIdentifier || JEV_MODEL}</div>
            {usageChip?.(provider)}
          </div>
          <div className={settingsStyles.providerActions}>
            <button className="iconButton" title="Edit" aria-label={`Edit Jev provider ${provider.name}`} onClick={() => onOpenForm(provider)}><Pencil size={14} /></button>
            <button className="iconButton" title="Delete" aria-label={`Delete Jev provider ${provider.name}`} onClick={() => provider.id && onDelete(provider.id)}><Trash2 size={14} /></button>
          </div>
        </div>
      })}
    </div>
  }
  return <section className={styles.section} aria-labelledby="jev-provider-title">
    <h3 id="jev-provider-title" className={styles.title}>Jev providers</h3>
    <p className={styles.intro}>
      Jev answers typed questions for recon hooks; it is not a chat model and never appears in a model picker.
      Configure multiple named TypeSafe or OpenRouter entries, then explicitly select one per project.
      There is no automatic selection or failover. Deleting a selected entry clears the affected projects' selection;
      their Jev hooks use deterministic fallbacks until another entry is selected.
    </p>
    {body}
  </section>
}
