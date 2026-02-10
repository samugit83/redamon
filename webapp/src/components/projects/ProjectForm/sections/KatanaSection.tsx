'use client'

import { useState } from 'react'
import { ChevronDown, Bug } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface KatanaSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function KatanaSection({ data, updateField }: KatanaSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Bug size={16} />
          Katana Web Crawler (DAST)
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Active web crawling using Katana from ProjectDiscovery. Discovers URLs, endpoints, and parameters by following links and parsing JavaScript. Found URLs with parameters feed into Nuclei DAST mode for vulnerability fuzzing.
          </p>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable Katana</span>
              <p className={styles.toggleDescription}>Active web crawling to discover endpoints and parameters for DAST vulnerability fuzzing</p>
            </div>
            <Toggle
              checked={data.katanaEnabled}
              onChange={(checked) => updateField('katanaEnabled', checked)}
            />
          </div>

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
                value={data.katanaExcludePatterns.join('\n')}
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
                value={data.katanaCustomHeaders.join('\n')}
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
