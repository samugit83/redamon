'use client'

import { useState } from 'react'
import { Bug, ChevronDown, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { FileImportButton } from '../FileImportButton'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface HakrawlerSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function HakrawlerSection({ data, updateField, onRun }: HakrawlerSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const jevStatus = useHasJevProvider()

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Bug size={16} />
          Hakrawler Web Crawler
          <NodeInfoTooltip section="Hakrawler" />
          <WikiInfoButton target="Hakrawler" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.hakrawlerEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
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
                    onChange={(e) => updateField('hakrawlerMaxUrls', parseInt(e.target.value) || 50000)}
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
                <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)' }}>
                  <AiToggleLabel
                    label="Order seeds with Jev"
                    tooltip={
                      'Hakrawler crawls its seeds in list order and stops at Max URLs, so under a tight ' +
                      'cap late-alphabet hosts are never crawled. Jev is asked, per probed host, whether ' +
                      'it has a rich web application surface, and Hakrawler crawls in that order ' +
                      '(alphabetical when Jev is unavailable). Ordering only, never a dropped seed; ' +
                      'partial recon keeps the alphabetical order. Same switch as in the Target tab AI ' +
                      'panel. ' +
                      (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                    }
                  />
                  <JevEngineControl
                    variant="jevOnly"
                    value={data.hakrawlerJevSeedOrder}
                    enabled={data.aiInPipeline}
                    jevStatus={jevStatus}
                    disabledHint='Enable "AI in Pipeline" in the Target tab to turn this on.'
                    onSelect={(on) => updateField('hakrawlerJevSeedOrder', on)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Headers</label>
                  <div className={styles.fileImportWrap}>
                    <textarea
                      className="textarea"
                      value={(data.hakrawlerCustomHeaders ?? []).join('\n')}
                      onChange={(e) => updateField('hakrawlerCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                      placeholder="Cookie: session=abc123&#10;Authorization: Bearer token..."
                      rows={3}
                    />
                    <FileImportButton
                      variant="textarea"
                      fieldName="headers"
                      onImport={(values) => updateField('hakrawlerCustomHeaders', values)}
                    />
                  </div>
                  <span className={styles.fieldHint}>One header per line (e.g., Cookie: value). Sent with every request</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
