'use client'

import { useState } from 'react'
import { ChevronDown, Code, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface JsluiceSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function JsluiceSection({ data, updateField, onRun }: JsluiceSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Code size={16} />
          jsluice JS Analyzer
          <NodeInfoTooltip section="Jsluice" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.jsluiceEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run jsluice JS Analyzer"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.jsluiceEnabled}
              onChange={(checked) => updateField('jsluiceEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Static analysis of JavaScript files using jsluice from Bishop Fox. Extracts hidden API endpoints, paths, query parameters, and secrets (AWS keys, API tokens) from JS source code discovered by Katana and Hakrawler. No additional traffic to the target beyond fetching JS files.
          </p>

          {data.jsluiceEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max JS Files</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceMaxFiles}
                    onChange={(e) => updateField('jsluiceMaxFiles', parseInt(e.target.value) || 100)}
                    min={1}
                    max={1000}
                  />
                  <span className={styles.fieldHint}>Maximum number of .js files to download and analyze</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceTimeout}
                    onChange={(e) => updateField('jsluiceTimeout', parseInt(e.target.value) || 300)}
                    min={30}
                  />
                  <span className={styles.fieldHint}>Overall analysis timeout</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Concurrency</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceConcurrency}
                    onChange={(e) => updateField('jsluiceConcurrency', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Files processed concurrently by jsluice</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Parallelism</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.jsluiceParallelism ?? 3}
                    onChange={(e) => updateField('jsluiceParallelism', parseInt(e.target.value) || 3)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Parallel base URL analysis batches</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Extraction Modes</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Extract URLs</span>
                    <p className={styles.toggleDescription}>Find API endpoints, paths, and parameters in fetch(), XMLHttpRequest, jQuery.ajax, and string literals</p>
                  </div>
                  <Toggle
                    checked={data.jsluiceExtractUrls}
                    onChange={(checked) => updateField('jsluiceExtractUrls', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Extract Secrets</span>
                    <p className={styles.toggleDescription}>Detect AWS keys, GCP credentials, GitHub tokens, and other embedded secrets with context</p>
                  </div>
                  <Toggle
                    checked={data.jsluiceExtractSecrets}
                    onChange={(checked) => updateField('jsluiceExtractSecrets', checked)}
                  />
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
