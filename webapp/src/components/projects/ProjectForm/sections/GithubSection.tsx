'use client'

import { useState } from 'react'
import { ChevronDown, Github } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface GithubSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function GithubSection({ data, updateField }: GithubSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const hasToken = data.githubAccessToken.length > 0

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Github size={16} />
          GitHub Secret Hunting
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
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>GitHub Access Token</label>
            <input
              type="password"
              className="textInput"
              value={data.githubAccessToken}
              onChange={(e) => updateField('githubAccessToken', e.target.value)}
              placeholder="ghp_xxxxxxxxxxxx"
            />
            <span className={styles.fieldHint}>
              Required for GitHub secret scanning. Create a token with repo scope.
            </span>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Target Organization</label>
            <input
              type="text"
              className="textInput"
              value={data.githubTargetOrg}
              onChange={(e) => updateField('githubTargetOrg', e.target.value)}
              placeholder="organization-name"
              disabled={!hasToken}
            />
          </div>

          {hasToken && (
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

          {!hasToken && (
            <div className={styles.subSection}>
              <p className={styles.fieldHint}>
                Enter a GitHub access token to enable secret scanning options.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
