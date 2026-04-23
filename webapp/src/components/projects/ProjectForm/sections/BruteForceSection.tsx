'use client'

import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface HydraSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function HydraSection({ data, updateField }: HydraSectionProps) {
  // Parse extra checks string into individual flags
  const extraChecks = (data.hydraExtraChecks ?? 'nsr') as string
  const hasNull = extraChecks.includes('n')
  const hasLoginAsPass = extraChecks.includes('s')
  const hasReversed = extraChecks.includes('r')

  const toggleExtraCheck = (flag: string) => {
    let current = extraChecks
    if (current.includes(flag)) {
      current = current.replace(flag, '')
    } else {
      current += flag
    }
    updateField('hydraExtraChecks', current)
  }

  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure THC Hydra credential testing settings. Hydra supports 50+ protocols
        including SSH, FTP, RDP, SMB, HTTP forms, databases, and more.
      </p>

      {/* Threads + Wait Between Connections */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Threads (-t)</label>
          <input
            type="number"
            className="textInput"
            value={data.hydraThreads ?? 16}
            onChange={(e) => updateField('hydraThreads', parseInt(e.target.value) || 16)}
            min={1}
            max={64}
          />
          <span className={styles.fieldHint}>
            Parallel connections per target. SSH max 4, RDP max 1. Default: 16.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Wait Between Connections (-W)</label>
          <input
            type="number"
            className="textInput"
            value={data.hydraWaitBetweenConnections ?? 0}
            onChange={(e) => updateField('hydraWaitBetweenConnections', parseInt(e.target.value) || 0)}
            min={0}
            max={300}
          />
          <span className={styles.fieldHint}>
            Seconds between each connection per task. 0 = no delay.
          </span>
        </div>
      </div>

      {/* Connection Timeout + Max Wordlist Attempts */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Connection Timeout (-w)</label>
          <input
            type="number"
            className="textInput"
            value={data.hydraConnectionTimeout ?? 32}
            onChange={(e) => updateField('hydraConnectionTimeout', parseInt(e.target.value) || 32)}
            min={5}
            max={120}
          />
          <span className={styles.fieldHint}>
            Max seconds to wait for a response from the target. Default: 32.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Max Wordlist Attempts</label>
          <input
            type="number"
            className="textInput"
            value={data.hydraMaxWordlistAttempts ?? 3}
            onChange={(e) => updateField('hydraMaxWordlistAttempts', parseInt(e.target.value) || 3)}
            min={1}
            max={10}
          />
          <span className={styles.fieldHint}>
            How many wordlist strategies to try before giving up.
          </span>
        </div>
      </div>

      {/* Stop On First Found + Verbose */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>
            <input
              type="checkbox"
              checked={data.hydraStopOnFirstFound ?? true}
              onChange={(e) => updateField('hydraStopOnFirstFound', e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            Stop On First Found (-f)
          </label>
          <span className={styles.fieldHint}>
            Stop immediately when valid credentials are found.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>
            <input
              type="checkbox"
              checked={data.hydraVerbose ?? true}
              onChange={(e) => updateField('hydraVerbose', e.target.checked)}
              style={{ marginRight: '8px' }}
            />
            Verbose Output (-V)
          </label>
          <span className={styles.fieldHint}>
            Show each login attempt in output for progress tracking.
          </span>
        </div>
      </div>

      {/* Extra Password Checks */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Extra Password Checks (-e)</label>
          <div style={{ display: 'flex', gap: '16px', marginTop: '4px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              <input
                type="checkbox"
                checked={hasNull}
                onChange={() => toggleExtraCheck('n')}
              />
              Null/empty password (n)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              <input
                type="checkbox"
                checked={hasLoginAsPass}
                onChange={() => toggleExtraCheck('s')}
              />
              Username as password (s)
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              <input
                type="checkbox"
                checked={hasReversed}
                onChange={() => toggleExtraCheck('r')}
              />
              Reversed username (r)
            </label>
          </div>
          <span className={styles.fieldHint}>
            Additional password variations tried before the wordlist. Common quick wins.
          </span>
        </div>
      </div>
    </div>
  )
}
