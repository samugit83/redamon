'use client'

import { useState } from 'react'
import { ChevronDown, Github, AlertTriangle } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'
import Link from 'next/link'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface GithubSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  hasGithubToken?: boolean
}

export function GithubSection({ data, updateField, hasGithubToken = false }: GithubSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Github size={16} />
          GitHub Secret Hunting
          <NodeInfoTooltip section="Github" />
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
            Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain. Identifies leaked sensitive data that could enable unauthorized access to systems and services.
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
            <label className={styles.fieldLabel}>Target Organization</label>
            <input
              type="text"
              className="textInput"
              value={data.githubTargetOrg}
              onChange={(e) => updateField('githubTargetOrg', e.target.value)}
              placeholder="organization-name"
              disabled={!hasGithubToken}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Target Repositories</label>
            <input
              type="text"
              className="textInput"
              value={data.githubTargetRepos}
              onChange={(e) => updateField('githubTargetRepos', e.target.value)}
              placeholder="repo1, repo2, repo3"
              disabled={!hasGithubToken}
            />
            <span className={styles.fieldHint}>
              Comma-separated list. Leave empty to scan all repositories.
            </span>
          </div>

          {hasGithubToken && (
            <>
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Scan Options</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Scan Member Repositories</span>
                    <p className={styles.toggleDescription}>Include repositories of organization members</p>
                  </div>
                  <Toggle
                    checked={data.githubScanMembers}
                    onChange={(checked) => updateField('githubScanMembers', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Scan Gists</span>
                    <p className={styles.toggleDescription}>Search for secrets in gists</p>
                  </div>
                  <Toggle
                    checked={data.githubScanGists}
                    onChange={(checked) => updateField('githubScanGists', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Scan Commits</span>
                    <p className={styles.toggleDescription}>Search commit history for secrets</p>
                    <TimeEstimate estimate="Most expensive operation — disabling saves 50%+ time" />
                  </div>
                  <Toggle
                    checked={data.githubScanCommits}
                    onChange={(checked) => updateField('githubScanCommits', checked)}
                  />
                </div>
              </div>

              {data.githubScanCommits && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Commits to Scan</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.githubMaxCommits}
                    onChange={(e) => updateField('githubMaxCommits', parseInt(e.target.value) || 100)}
                    min={1}
                    max={1000}
                  />
                  <span className={styles.fieldHint}>Number of commits to scan per repository</span>
                  <TimeEstimate estimate="Scales linearly: 100 = default, 1000 = ~10x slower" />
                </div>
              )}

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Output as JSON</span>
                  <p className={styles.toggleDescription}>Save results in JSON format</p>
                </div>
                <Toggle
                  checked={data.githubOutputJson}
                  onChange={(checked) => updateField('githubOutputJson', checked)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
