'use client'

import type { Project } from '@prisma/client'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface DosSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function DosSection({ data, updateField }: DosSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure availability testing settings. These control test intensity,
        duration limits, and whether to perform assessment-only (non-destructive) checks.
      </p>

      {/* Max Duration + Max Attempts */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Max Duration (seconds)</label>
          <input
            type="number"
            className="textInput"
            value={data.dosMaxDuration ?? 60}
            onChange={(e) => updateField('dosMaxDuration', parseInt(e.target.value) || 60)}
            min={10}
            max={300}
          />
          <span className={styles.fieldHint}>
            Max seconds per individual availability test. Caps hping3, MSF modules, slowhttptest.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Max Attempts</label>
          <input
            type="number"
            className="textInput"
            value={data.dosMaxAttempts ?? 3}
            onChange={(e) => updateField('dosMaxAttempts', parseInt(e.target.value) || 3)}
            min={1}
            max={10}
          />
          <span className={styles.fieldHint}>
            Max different vectors to try before reporting service is resilient.
          </span>
        </div>
      </div>

      {/* Concurrent Connections */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Concurrent Connections</label>
          <input
            type="number"
            className="textInput"
            value={data.dosConcurrentConnections ?? 1000}
            onChange={(e) => updateField('dosConcurrentConnections', parseInt(e.target.value) || 1000)}
            min={10}
            max={10000}
          />
          <span className={styles.fieldHint}>
            Connections for app-layer testing (slowloris sockets, slowhttptest -c). Controls intensity.
          </span>
        </div>
      </div>

      {/* Assessment Only toggle */}
      <div className={styles.fieldRow} style={{ marginTop: 'var(--space-4)' }}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>
            <input
              type="checkbox"
              checked={data.dosAssessmentOnly ?? false}
              onChange={(e) => updateField('dosAssessmentOnly', e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            Assessment Only
          </label>
          <span className={styles.fieldHint}>
            Only check for availability vulnerabilities (nmap scripts, nuclei) without active testing.
          </span>
        </div>
      </div>
    </div>
  )
}
