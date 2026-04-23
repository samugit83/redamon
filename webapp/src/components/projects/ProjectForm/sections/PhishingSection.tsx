'use client'

import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface PhishingSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function PhishingSection({ data, updateField }: PhishingSectionProps) {
  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)' }}>
      <p className={styles.sectionDescription}>
        Configure SMTP settings for social engineering simulation email delivery. The agent uses these when sending
        payloads or documents via email. Leave empty to be asked at runtime.
      </p>

      {/* SMTP Configuration Textarea */}
      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup} style={{ flex: 1 }}>
          <label className={styles.fieldLabel}>SMTP Configuration (optional)</label>
          <textarea
            className="textInput"
            value={data.phishingSmtpConfig ?? ''}
            onChange={(e) => updateField('phishingSmtpConfig', e.target.value)}
            placeholder={`SMTP_HOST: smtp.gmail.com\nSMTP_PORT: 587\nSMTP_USER: pentest@gmail.com\nSMTP_PASS: abcd efgh ijkl mnop\nSMTP_FROM: it-support@company.com\nUSE_TLS: true`}
            rows={6}
            style={{ fontFamily: 'monospace', fontSize: '13px', resize: 'vertical' }}
          />
          <span className={styles.fieldHint}>
            Free-text SMTP settings injected into the agent prompt for social engineering email delivery.
            The agent reads this as-is when the social engineering simulation skill is active.
          </span>
        </div>
      </div>
    </div>
  )
}
