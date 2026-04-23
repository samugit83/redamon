'use client'

import { useState } from 'react'
import { ChevronDown, Search, AlertTriangle } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import Link from 'next/link'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TrufflehogSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  hasGithubToken?: boolean
}

export function TrufflehogSection({ data, updateField, hasGithubToken = false }: TrufflehogSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const hasConfig =
    ((data as any).trufflehogGithubOrg ?? '').length > 0 ||
    ((data as any).trufflehogGithubRepos ?? '').length > 0

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          TruffleHog Secret Scanner
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Deep secret scanning with 700+ detectors and optional verification against live APIs.
          </p>

          {!hasGithubToken && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '10px 14px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '8px',
              marginBottom: '12px',
            }}>
              <AlertTriangle size={16} style={{ color: '#f59e0b', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                GitHub Access Token required.{' '}
                <Link href="/settings" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                  Configure it in Global Settings
                </Link>
              </span>
            </div>
          )}

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>GitHub Organization</label>
            <input
              type="text"
              className="textInput"
              value={(data as any).trufflehogGithubOrg ?? ''}
              onChange={(e) => updateField('trufflehogGithubOrg' as any, e.target.value)}
              placeholder="organization-name"
              disabled={!hasGithubToken}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>GitHub Repositories</label>
            <input
              type="text"
              className="textInput"
              value={(data as any).trufflehogGithubRepos ?? ''}
              onChange={(e) => updateField('trufflehogGithubRepos' as any, e.target.value)}
              placeholder="org/repo1, org/repo2"
              disabled={!hasGithubToken}
            />
            <span className={styles.fieldHint}>
              Comma-separated. Full URLs or org/repo format.
            </span>
          </div>

          {hasConfig && hasGithubToken && (
            <>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Only Verified Secrets</span>
                  <p className={styles.toggleDescription}>Only output secrets verified as active against live APIs</p>
                </div>
                <Toggle
                  checked={(data as any).trufflehogOnlyVerified ?? false}
                  onChange={(checked) => updateField('trufflehogOnlyVerified' as any, checked)}
                />
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Skip Verification</span>
                  <p className={styles.toggleDescription}>Skip API verification for faster scanning</p>
                </div>
                <Toggle
                  checked={(data as any).trufflehogNoVerification ?? false}
                  onChange={(checked) => updateField('trufflehogNoVerification' as any, checked)}
                />
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Concurrency</label>
                <input
                  type="number"
                  className="textInput"
                  value={(data as any).trufflehogConcurrency ?? 8}
                  onChange={(e) => updateField('trufflehogConcurrency' as any, parseInt(e.target.value) || 8)}
                  min={1}
                  max={32}
                />
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Include Detectors</label>
                <input
                  type="text"
                  className="textInput"
                  value={(data as any).trufflehogIncludeDetectors ?? ''}
                  onChange={(e) => updateField('trufflehogIncludeDetectors' as any, e.target.value)}
                  placeholder="AWS,GitHub,Slack"
                />
                <span className={styles.fieldHint}>
                  Comma-separated, e.g. AWS,GitHub,Slack. Leave empty for all.
                </span>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Exclude Detectors</label>
                <input
                  type="text"
                  className="textInput"
                  value={(data as any).trufflehogExcludeDetectors ?? ''}
                  onChange={(e) => updateField('trufflehogExcludeDetectors' as any, e.target.value)}
                  placeholder="DetectorName1,DetectorName2"
                />
                <span className={styles.fieldHint}>
                  Comma-separated detectors to skip
                </span>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
