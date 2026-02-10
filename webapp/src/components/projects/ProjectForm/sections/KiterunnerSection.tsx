'use client'

import { useState } from 'react'
import { ChevronDown, Zap } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface KiterunnerSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function KiterunnerSection({ data, updateField }: KiterunnerSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Zap size={16} />
          Kiterunner API Discovery
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            API endpoint bruteforcing using Kiterunner from Assetnote. Discovers hidden REST API routes by testing against comprehensive wordlists derived from real-world Swagger/OpenAPI specifications.
          </p>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable Kiterunner</span>
              <p className={styles.toggleDescription}>Bruteforce API routes using Swagger/OpenAPI specifications to find hidden endpoints</p>
              <TimeEstimate estimate="5-30 min per endpoint" />
            </div>
            <Toggle
              checked={data.kiterunnerEnabled}
              onChange={(checked) => updateField('kiterunnerEnabled', checked)}
            />
          </div>

          {data.kiterunnerEnabled && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Wordlist</label>
                <select
                  className="select"
                  value={data.kiterunnerWordlists[0] || 'routes-large'}
                  onChange={(e) => updateField('kiterunnerWordlists', [e.target.value])}
                >
                  <option value="routes-large">routes-large (~100k API routes)</option>
                  <option value="routes-small">routes-small (~20k API routes)</option>
                </select>
                <span className={styles.fieldHint}>API route wordlist from Assetnote CDN. Custom .kite files can be used via CLI</span>
                <TimeEstimate estimate="routes-large: ~10-30 min/endpoint | routes-small: ~5-10 min" />
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.kiterunnerRateLimit}
                    onChange={(e) => updateField('kiterunnerRateLimit', parseInt(e.target.value) || 100)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Requests/sec. Lower is stealthier</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Connections</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.kiterunnerConnections}
                    onChange={(e) => updateField('kiterunnerConnections', parseInt(e.target.value) || 100)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Concurrent connections per target</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.kiterunnerTimeout}
                    onChange={(e) => updateField('kiterunnerTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Per-request timeout</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Scan Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.kiterunnerScanTimeout}
                    onChange={(e) => updateField('kiterunnerScanTimeout', parseInt(e.target.value) || 1000)}
                    min={60}
                  />
                  <span className={styles.fieldHint}>Overall scan timeout. Large wordlists need more time</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.kiterunnerThreads}
                    onChange={(e) => updateField('kiterunnerThreads', parseInt(e.target.value) || 50)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Parallel scanning threads</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Min Content Length</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.kiterunnerMinContentLength}
                    onChange={(e) => updateField('kiterunnerMinContentLength', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Ignore responses smaller than this (bytes)</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Status Code Filters</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Ignore Status Codes</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.kiterunnerIgnoreStatus.join(', ')}
                    onChange={(e) => updateField('kiterunnerIgnoreStatus', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                    placeholder="(empty = use whitelist only)"
                  />
                  <span className={styles.fieldHint}>Blacklist: filter out noise from common errors</span>
                </div>
                <div className={styles.fieldGroup} style={{ marginTop: '1rem' }}>
                  <label className={styles.fieldLabel}>Match Status Codes</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.kiterunnerMatchStatus.join(', ')}
                    onChange={(e) => updateField('kiterunnerMatchStatus', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                    placeholder="200, 201, 204, 301, 302, 401, 403, 405"
                  />
                  <span className={styles.fieldHint}>Whitelist: only show endpoints with these status codes (includes auth-protected)</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Headers</label>
                  <textarea
                    className="textarea"
                    value={data.kiterunnerHeaders.join('\n')}
                    onChange={(e) => updateField('kiterunnerHeaders', e.target.value.split('\n').filter(Boolean))}
                    placeholder="Authorization: Bearer token123&#10;X-API-Key: key123"
                    rows={3}
                  />
                  <span className={styles.fieldHint}>Add auth tokens for authenticated API scanning</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Method Detection</h3>
                <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Kiterunner wordlists only contain GET routes. Detect POST/PUT/DELETE methods on found endpoints</p>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Detect Methods</span>
                    <p className={styles.toggleDescription}>Find additional HTTP methods beyond GET</p>
                    <TimeEstimate estimate="+30-50% scan time" />
                  </div>
                  <Toggle
                    checked={data.kiterunnerDetectMethods}
                    onChange={(checked) => updateField('kiterunnerDetectMethods', checked)}
                  />
                </div>

                {data.kiterunnerDetectMethods && (
                  <>
                    <div className={styles.fieldGroup} style={{ marginTop: '0.75rem' }}>
                      <label className={styles.fieldLabel}>Detection Mode</label>
                      <select
                        className="select"
                        value={data.kiterunnerMethodDetectionMode}
                        onChange={(e) => updateField('kiterunnerMethodDetectionMode', e.target.value)}
                      >
                        <option value="bruteforce">Bruteforce - Try each method (slower, more accurate)</option>
                        <option value="options">OPTIONS Header - Parse Allow header (faster)</option>
                      </select>
                      <span className={styles.fieldHint}>How to discover allowed HTTP methods</span>
                    </div>
                    <div className={styles.fieldGroup} style={{ marginTop: '0.75rem' }}>
                      <label className={styles.fieldLabel}>Bruteforce Methods</label>
                      <input
                        type="text"
                        className="textInput"
                        value={data.kiterunnerBruteforceMethods.join(', ')}
                        onChange={(e) =>
                          updateField(
                            'kiterunnerBruteforceMethods',
                            e.target.value.split(',').map(s => s.trim().toUpperCase()).filter(Boolean)
                          )
                        }
                        placeholder="POST, PUT, DELETE, PATCH"
                      />
                      <span className={styles.fieldHint}>Methods to try in bruteforce mode</span>
                    </div>
                    <div className={styles.fieldRow} style={{ marginTop: '0.75rem' }}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Method Detect Timeout</label>
                        <input
                          type="number"
                          className="textInput"
                          value={data.kiterunnerMethodDetectTimeout}
                          onChange={(e) => updateField('kiterunnerMethodDetectTimeout', parseInt(e.target.value) || 5)}
                          min={1}
                        />
                        <span className={styles.fieldHint}>Seconds per request</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Method Detect Rate Limit</label>
                        <input
                          type="number"
                          className="textInput"
                          value={data.kiterunnerMethodDetectRateLimit}
                          onChange={(e) => updateField('kiterunnerMethodDetectRateLimit', parseInt(e.target.value) || 50)}
                          min={1}
                        />
                        <span className={styles.fieldHint}>Requests/second</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Method Detect Threads</label>
                        <input
                          type="number"
                          className="textInput"
                          value={data.kiterunnerMethodDetectThreads}
                          onChange={(e) => updateField('kiterunnerMethodDetectThreads', parseInt(e.target.value) || 25)}
                          min={1}
                        />
                        <span className={styles.fieldHint}>Concurrent threads</span>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
