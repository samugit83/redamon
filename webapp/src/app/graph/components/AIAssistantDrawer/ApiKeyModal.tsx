'use client'

import React from 'react'
import { Eye, EyeOff, Loader2 } from 'lucide-react'
import styles from './AIAssistantDrawer.module.css'

interface ApiKeyInfo {
  label: string
  hint: string
  url: string
}

interface ApiKeyModalProps {
  apiKeyModal: string | null
  apiKeyInfo: Record<string, ApiKeyInfo>
  apiKeyValue: string
  apiKeyVisible: boolean
  apiKeySaving: boolean
  setApiKeyValue: (v: string) => void
  setApiKeyVisible: React.Dispatch<React.SetStateAction<boolean>>
  closeApiKeyModal: () => void
  saveApiKey: () => void
}

export function ApiKeyModal({
  apiKeyModal,
  apiKeyInfo,
  apiKeyValue,
  apiKeyVisible,
  apiKeySaving,
  setApiKeyValue,
  setApiKeyVisible,
  closeApiKeyModal,
  saveApiKey,
}: ApiKeyModalProps) {
  if (!apiKeyModal || !apiKeyInfo[apiKeyModal]) return null

  const info = apiKeyInfo[apiKeyModal]

  return (
    <div className={styles.apiKeyOverlay} onClick={closeApiKeyModal}>
      <div className={styles.apiKeyModal} onClick={e => e.stopPropagation()}>
        <h3 className={styles.apiKeyModalTitle}>{info.label} API Key</h3>
        <div className="formGroup">
          <label className="formLabel">{info.label} API Key</label>
          <div className={styles.apiKeyInputWrapper}>
            <input
              className="textInput"
              type={apiKeyVisible ? 'text' : 'password'}
              value={apiKeyValue}
              onChange={e => setApiKeyValue(e.target.value)}
              placeholder={`Enter ${info.label.toLowerCase()} API key`}
              autoFocus
            />
            <button
              className={styles.apiKeyToggle}
              onClick={() => setApiKeyVisible(v => !v)}
              type="button"
            >
              {apiKeyVisible ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          <span className="formHint">
            {info.hint}
            {' — '}
            <a href={info.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
              Get API key
            </a>
          </span>
        </div>
        <div className={styles.apiKeyModalActions}>
          <button className="secondaryButton" onClick={closeApiKeyModal}>Cancel</button>
          <button
            className="primaryButton"
            disabled={!apiKeyValue.trim() || apiKeySaving}
            onClick={saveApiKey}
          >
            {apiKeySaving ? <Loader2 size={14} className={styles.spinner} /> : null}
            Save
          </button>
        </div>
      </div>
    </div>
  )
}
