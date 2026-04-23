'use client'

import { useState } from 'react'
import { Bug, ChevronDown, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface KatanaSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function KatanaSection({ data, updateField, onRun }: KatanaSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Bug size={16} />
          Katana Web Crawler (DAST)
          <NodeInfoTooltip section="Katana" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.katanaEnabled && (
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
              title="Run Katana Web Crawler"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.katanaEnabled}
              onChange={(checked) => updateField('katanaEnabled', checked)}
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
            Active web crawling using Katana from ProjectDiscovery. Discovers URLs, endpoints, and parameters by following links and parsing JavaScript. Found URLs with parameters feed into Nuclei DAST mode for vulnerability fuzzing.
          </p>

          {data.katanaEnabled && (
            <>
          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Crawl Depth</label>
              <input
                type="number"
                className="textInput"
                value={data.katanaDepth}
                onChange={(e) => updateField('katanaDepth', parseInt(e.target.value) || 2)}
                min={1}
                max={10}
              />
              <span className={styles.fieldHint}>How many links deep to follow. Higher = more URLs but slower</span>
              <TimeEstimate estimate="Each level adds ~50% time (depth 3 = ~2x depth 2)" />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Max URLs</label>
              <input
                type="number"
                className="textInput"
                value={data.katanaMaxUrls}
                onChange={(e) => updateField('katanaMaxUrls', parseInt(e.target.value) || 300)}
                min={1}
              />
              <span className={styles.fieldHint}>Maximum number of URLs to collect per domain</span>
              <TimeEstimate estimate="300 URLs: ~1-2 min/domain | 1000+: scales linearly" />
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Rate Limit</label>
              <input
                type="number"
                className="textInput"
                value={data.katanaRateLimit}
                onChange={(e) => updateField('katanaRateLimit', parseInt(e.target.value) || 50)}
                min={1}
              />
              <span className={styles.fieldHint}>Requests per second to avoid overloading target</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Timeout (seconds)</label>
              <input
                type="number"
                className="textInput"
                value={data.katanaTimeout}
                onChange={(e) => updateField('katanaTimeout', parseInt(e.target.value) || 3600)}
                min={60}
              />
              <span className={styles.fieldHint}>Overall crawl timeout (default: 60 minutes)</span>
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Parallelism</label>
              <input
                type="number"
                className="textInput"
                value={data.katanaParallelism ?? 5}
                onChange={(e) => updateField('katanaParallelism', parseInt(e.target.value) || 5)}
                min={1}
                max={50}
              />
              <span className={styles.fieldHint}>Number of target URLs to crawl simultaneously</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Concurrency</label>
              <input
                type="number"
                className="textInput"
                value={data.katanaConcurrency ?? 10}
                onChange={(e) => updateField('katanaConcurrency', parseInt(e.target.value) || 10)}
                min={1}
                max={50}
              />
              <span className={styles.fieldHint}>Concurrent fetchers per target URL</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Options</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>JavaScript Crawling</span>
                <p className={styles.toggleDescription}>Parse JS files to find hidden endpoints and API calls. Slower but finds more URLs</p>
                <TimeEstimate estimate="+50-100% (uses headless browser)" />
              </div>
              <Toggle
                checked={data.katanaJsCrawl}
                onChange={(checked) => updateField('katanaJsCrawl', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Parameters Only</span>
                <p className={styles.toggleDescription}>Only keep URLs with query parameters (?key=value) for DAST fuzzing</p>
              </div>
              <Toggle
                checked={data.katanaParamsOnly}
                onChange={(checked) => updateField('katanaParamsOnly', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Exclude Patterns</h3>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>URL Patterns to Exclude</label>
              <textarea
                className="textarea"
                value={(data.katanaExcludePatterns ?? []).join('\n')}
                onChange={(e) => updateField('katanaExcludePatterns', e.target.value.split('\n').filter(Boolean))}
                placeholder="/_next/static&#10;.png&#10;.css&#10;/images/"
                rows={5}
              />
              <span className={styles.fieldHint}>
                Skip static assets, images, and CDN URLs. These aren't vulnerable to injection attacks
              </span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Custom Headers</h3>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Request Headers</label>
              <textarea
                className="textarea"
                value={(data.katanaCustomHeaders ?? []).join('\n')}
                onChange={(e) => updateField('katanaCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                placeholder="User-Agent: Mozilla/5.0...&#10;Accept: text/html..."
                rows={3}
              />
              <span className={styles.fieldHint}>Browser-like headers help avoid detection during DAST crawling</span>
            </div>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Docker Image</label>
            <input
              type="text"
              className="textInput"
              value={data.katanaDockerImage}
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
