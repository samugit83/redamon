'use client'

import { useState } from 'react'
import { ChevronDown, Search, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ArjunSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

const METHOD_OPTIONS = ['GET', 'POST', 'JSON', 'XML']

const METHOD_LABELS: Record<string, string> = {
  GET: 'GET — Query parameters',
  POST: 'POST — Form body',
  JSON: 'JSON — JSON body',
  XML: 'XML — XML body',
}

export function ArjunSection({ data, updateField, onRun }: ArjunSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const toggleMethod = (method: string) => {
    const current = data.arjunMethods ?? ['GET']
    if (current.includes(method)) {
      // Don't allow deselecting the last method
      if (current.length <= 1) return
      updateField('arjunMethods', current.filter(m => m !== method))
    } else {
      updateField('arjunMethods', [...current, method])
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          Arjun (Parameter Discovery)
          <NodeInfoTooltip section="Arjun" />
          <span className={styles.badgeActive}>Active</span>
          {data.arjunPassive && <span className={styles.badgePassive}>Passive</span>}
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.arjunEnabled && (
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
              title="Run Arjun"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.arjunEnabled}
              onChange={(checked) => updateField('arjunEnabled', checked)}
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
            Discovers hidden HTTP query and body parameters by testing ~25,000 common parameter names against discovered endpoints. Finds debug parameters, admin functionality, and hidden API inputs that aren&apos;t visible in HTML forms or JavaScript. Multiple methods run in parallel.
          </p>

          {data.arjunEnabled && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>HTTP Methods</label>
                <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Select which parameter positions to test. Multiple methods run in parallel.</p>
                <div className={styles.checkboxGroup}>
                  {METHOD_OPTIONS.map(method => (
                    <label key={method} className="checkboxLabel">
                      <input
                        type="checkbox"
                        className="checkbox"
                        checked={(data.arjunMethods ?? ['GET']).includes(method)}
                        onChange={() => toggleMethod(method)}
                      />
                      {METHOD_LABELS[method]}
                    </label>
                  ))}
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Endpoints</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.arjunMaxEndpoints}
                    onChange={(e) => updateField('arjunMaxEndpoints', parseInt(e.target.value) || 50)}
                    min={1}
                    max={500}
                  />
                  <span className={styles.fieldHint}>Max discovered endpoints to test. API/dynamic endpoints are prioritized.</span>
                  <TimeEstimate estimate="~10s per endpoint per method" />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.arjunThreads}
                    onChange={(e) => updateField('arjunThreads', parseInt(e.target.value) || 2)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Concurrent parameter testing threads</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.arjunTimeout}
                    onChange={(e) => updateField('arjunTimeout', parseInt(e.target.value) || 15)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Per-request timeout</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Scan Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.arjunScanTimeout}
                    onChange={(e) => updateField('arjunScanTimeout', parseInt(e.target.value) || 600)}
                    min={60}
                  />
                  <span className={styles.fieldHint}>Overall scan timeout per method</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Chunk Size</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.arjunChunkSize}
                    onChange={(e) => updateField('arjunChunkSize', parseInt(e.target.value) || 500)}
                    min={10}
                    max={5000}
                  />
                  <span className={styles.fieldHint}>Parameters tested per request batch. Lower = more requests, higher accuracy</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.arjunRateLimit}
                    onChange={(e) => updateField('arjunRateLimit', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Max requests/sec (0 = unlimited)</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Options</h3>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Stable Mode</span>
                    <p className={styles.toggleDescription}>Add random delays between requests to avoid WAF detection</p>
                  </div>
                  <Toggle
                    checked={data.arjunStable}
                    onChange={(checked) => updateField('arjunStable', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Passive Mode</span>
                    <p className={styles.toggleDescription}>Use CommonCrawl, OTX, and WaybackMachine only — no active requests to target</p>
                  </div>
                  <Toggle
                    checked={data.arjunPassive}
                    onChange={(checked) => updateField('arjunPassive', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Disable Redirects</span>
                    <p className={styles.toggleDescription}>Do not follow HTTP redirects during parameter testing</p>
                  </div>
                  <Toggle
                    checked={data.arjunDisableRedirects}
                    onChange={(checked) => updateField('arjunDisableRedirects', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Headers</label>
                  <textarea
                    className="textarea"
                    value={(data.arjunCustomHeaders ?? []).join('\n')}
                    onChange={(e) => updateField('arjunCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                    placeholder="Authorization: Bearer token123&#10;X-API-Key: key123"
                    rows={3}
                  />
                  <span className={styles.fieldHint}>Add auth tokens or custom headers for authenticated parameter testing</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
