'use client'

import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SqliSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function SqliSection({ data, updateField }: SqliSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure SQLMap scan intensity and WAF bypass settings.
      </p>

      {/* Level + Risk */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>SQLMap Level (1-5)</label>
          <input
            type="number"
            className="textInput"
            value={data.sqliLevel ?? 1}
            onChange={(e) => updateField('sqliLevel', parseInt(e.target.value) || 1)}
            min={1}
            max={5}
          />
          <span className={styles.fieldHint}>
            Higher levels test more injection points (headers, cookies). Default: 1.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>SQLMap Risk (1-3)</label>
          <input
            type="number"
            className="textInput"
            value={data.sqliRisk ?? 1}
            onChange={(e) => updateField('sqliRisk', parseInt(e.target.value) || 1)}
            min={1}
            max={3}
          />
          <span className={styles.fieldHint}>
            Higher risk uses more aggressive payloads (e.g., OR-based). Default: 1.
          </span>
        </div>
      </div>

      {/* Tamper Scripts */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Tamper Scripts</label>
          <input
            type="text"
            className="textInput"
            value={data.sqliTamperScripts ?? ''}
            onChange={(e) => updateField('sqliTamperScripts', e.target.value)}
            placeholder="e.g., space2comment,randomcase"
          />
          <span className={styles.fieldHint}>
            Comma-separated SQLMap tamper scripts for WAF bypass. Leave empty for auto-detection.
          </span>
        </div>
      </div>
    </div>
  )
}
