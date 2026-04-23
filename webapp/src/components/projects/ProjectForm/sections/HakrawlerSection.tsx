'use client'

import { useState } from 'react'
import { Bug, ChevronDown, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface HakrawlerSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function HakrawlerSection({ data, updateField, onRun }: HakrawlerSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Bug size={16} />
          Hakrawler Web Crawler
          <NodeInfoTooltip section="Hakrawler" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.hakrawlerEnabled && (
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
              title="Run Hakrawler Web Crawler"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.hakrawlerEnabled}
              onChange={(checked) => updateField('hakrawlerEnabled', checked)}
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
            Fast Go-based web crawler for discovering URLs and JavaScript file locations. Complements Katana with a different crawl engine that may find additional endpoints. Uses stdin-based Docker execution.
          </p>

          {data.hakrawlerEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Crawl Depth</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.hakrawlerDepth}
                    onChange={(e) => updateField('hakrawlerDepth', parseInt(e.target.value) || 2)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>How many links deep to follow</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max URLs</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.hakrawlerMaxUrls}
                    onChange={(e) => updateField('hakrawlerMaxUrls', parseInt(e.target.value) || 500)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Maximum URLs to collect (process killed at limit)</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.hakrawlerThreads}
                    onChange={(e) => updateField('hakrawlerThreads', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Concurrent crawl threads</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.hakrawlerTimeout}
                    onChange={(e) => updateField('hakrawlerTimeout', parseInt(e.target.value) || 30)}
                    min={5}
                  />
                  <span className={styles.fieldHint}>Per-URL crawl timeout</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Parallelism</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.hakrawlerParallelism ?? 4}
                    onChange={(e) => updateField('hakrawlerParallelism', parseInt(e.target.value) || 4)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Number of URLs to crawl in parallel</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Options</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Include Subdomains</span>
                    <p className={styles.toggleDescription}>Allow crawler to follow links to subdomains of the target. Results are still scope-filtered</p>
                  </div>
                  <Toggle
                    checked={data.hakrawlerIncludeSubs}
                    onChange={(checked) => updateField('hakrawlerIncludeSubs', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Insecure TLS</span>
                    <p className={styles.toggleDescription}>Skip TLS certificate verification (useful for self-signed certs)</p>
                  </div>
                  <Toggle
                    checked={data.hakrawlerInsecure}
                    onChange={(checked) => updateField('hakrawlerInsecure', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Headers</label>
                  <textarea
                    className="textarea"
                    value={(data.hakrawlerCustomHeaders ?? []).join('\n')}
                    onChange={(e) => updateField('hakrawlerCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                    placeholder="Cookie: session=abc123&#10;Authorization: Bearer token..."
                    rows={3}
                  />
                  <span className={styles.fieldHint}>One header per line (e.g., Cookie: value). Sent with every request</span>
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Docker Image</label>
                <input
                  type="text"
                  className="textInput"
                  value={data.hakrawlerDockerImage}
                  disabled
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
