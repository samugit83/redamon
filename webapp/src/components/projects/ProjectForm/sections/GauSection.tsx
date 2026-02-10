'use client'

import { useState } from 'react'
import { ChevronDown, Link } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface GauSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const PROVIDER_OPTIONS = ['wayback', 'commoncrawl', 'otx', 'urlscan']

export function GauSection({ data, updateField }: GauSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const toggleProvider = (provider: string) => {
    const current = data.gauProviders
    if (current.includes(provider)) {
      updateField('gauProviders', current.filter(p => p !== provider))
    } else {
      updateField('gauProviders', [...current, provider])
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Link size={16} />
          GAU (GetAllUrls) Passive Discovery
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Passive URL discovery using GetAllUrls (GAU). Retrieves historical URLs from web archives and threat intelligence sources without touching the target directly. Complements Katana's active crawling with archived data.
          </p>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable GAU</span>
              <p className={styles.toggleDescription}>Fetch historical URLs from Wayback Machine, Common Crawl, OTX, and URLScan</p>
              <TimeEstimate estimate="~20-60 sec per domain" />
            </div>
            <Toggle
              checked={data.gauEnabled}
              onChange={(checked) => updateField('gauEnabled', checked)}
            />
          </div>

          {data.gauEnabled && (
            <>
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Providers</h3>
                <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Data sources to query for archived URLs</p>
                <div className={styles.checkboxGroup}>
                  {PROVIDER_OPTIONS.map(provider => (
                    <label key={provider} className="checkboxLabel">
                      <input
                        type="checkbox"
                        className="checkbox"
                        checked={data.gauProviders.includes(provider)}
                        onChange={() => toggleProvider(provider)}
                      />
                      {provider}
                    </label>
                  ))}
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max URLs</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.gauMaxUrls}
                    onChange={(e) => updateField('gauMaxUrls', parseInt(e.target.value) || 1000)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Maximum URLs to fetch per domain (0 = unlimited)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.gauTimeout}
                    onChange={(e) => updateField('gauTimeout', parseInt(e.target.value) || 60)}
                    min={10}
                  />
                  <span className={styles.fieldHint}>Request timeout per provider</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.gauThreads}
                    onChange={(e) => updateField('gauThreads', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel fetch threads</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Year Range</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.gauYearRange.join(', ')}
                    onChange={(e) => updateField('gauYearRange', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                    placeholder="2020, 2024 (empty = all years)"
                  />
                  <span className={styles.fieldHint}>Filter Wayback Machine by year (e.g., 2020, 2024)</span>
                </div>
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Verbose Output</span>
                  <p className={styles.toggleDescription}>Enable detailed logging for debugging</p>
                </div>
                <Toggle
                  checked={data.gauVerbose}
                  onChange={(checked) => updateField('gauVerbose', checked)}
                />
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Blacklist Extensions</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>File Extensions to Exclude</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.gauBlacklistExtensions.join(', ')}
                    onChange={(e) => updateField('gauBlacklistExtensions', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                    placeholder="png, jpg, css, pdf, zip"
                  />
                  <span className={styles.fieldHint}>Skip static assets like images, fonts, and documents</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>URL Verification</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Verify URLs</span>
                    <p className={styles.toggleDescription}>HTTP check to confirm archived URLs still exist. Filters out dead links</p>
                    <TimeEstimate estimate="Doubles or triples GAU time" />
                  </div>
                  <Toggle
                    checked={data.gauVerifyUrls}
                    onChange={(checked) => updateField('gauVerifyUrls', checked)}
                  />
                </div>

                {data.gauVerifyUrls && (
                  <>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Verify Timeout</label>
                        <input
                          type="number"
                          className="textInput"
                          value={data.gauVerifyTimeout}
                          onChange={(e) => updateField('gauVerifyTimeout', parseInt(e.target.value) || 5)}
                          min={1}
                        />
                        <span className={styles.fieldHint}>Seconds per URL check</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Verify Rate Limit</label>
                        <input
                          type="number"
                          className="textInput"
                          value={data.gauVerifyRateLimit}
                          onChange={(e) => updateField('gauVerifyRateLimit', parseInt(e.target.value) || 100)}
                          min={1}
                        />
                        <span className={styles.fieldHint}>Requests/second</span>
                      </div>
                    </div>

                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Verify Threads</label>
                        <input
                          type="number"
                          className="textInput"
                          value={data.gauVerifyThreads}
                          onChange={(e) => updateField('gauVerifyThreads', parseInt(e.target.value) || 50)}
                          min={1}
                          max={100}
                        />
                        <span className={styles.fieldHint}>Concurrent verification threads</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Verify Docker Image</label>
                        <input
                          type="text"
                          className="textInput"
                          value={data.gauVerifyDockerImage}
                          disabled
                        />
                      </div>
                    </div>

                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Accept Status Codes</label>
                      <input
                        type="text"
                        className="textInput"
                        value={data.gauVerifyAcceptStatus.join(', ')}
                        onChange={(e) => updateField('gauVerifyAcceptStatus', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                        placeholder="200, 201, 301, 302, 307, 308, 401, 403"
                      />
                      <span className={styles.fieldHint}>Status codes that indicate a live URL. Include 401/403 for auth-protected endpoints</span>
                    </div>

                    <div className={styles.toggleRow}>
                      <div>
                        <span className={styles.toggleLabel}>Detect HTTP Methods</span>
                        <p className={styles.toggleDescription}>Send OPTIONS request to discover allowed methods (GET, POST, PUT, DELETE)</p>
                        <TimeEstimate estimate="+30-50% on top of verification time" />
                      </div>
                      <Toggle
                        checked={data.gauDetectMethods}
                        onChange={(checked) => updateField('gauDetectMethods', checked)}
                      />
                    </div>

                    {data.gauDetectMethods && (
                      <div className={styles.fieldRow}>
                        <div className={styles.fieldGroup}>
                          <label className={styles.fieldLabel}>Method Detect Timeout</label>
                          <input
                            type="number"
                            className="textInput"
                            value={data.gauMethodDetectTimeout}
                            onChange={(e) => updateField('gauMethodDetectTimeout', parseInt(e.target.value) || 5)}
                            min={1}
                          />
                          <span className={styles.fieldHint}>Seconds per OPTIONS request</span>
                        </div>
                        <div className={styles.fieldGroup}>
                          <label className={styles.fieldLabel}>Method Detect Rate Limit</label>
                          <input
                            type="number"
                            className="textInput"
                            value={data.gauMethodDetectRateLimit}
                            onChange={(e) => updateField('gauMethodDetectRateLimit', parseInt(e.target.value) || 50)}
                            min={1}
                          />
                          <span className={styles.fieldHint}>Requests/second</span>
                        </div>
                        <div className={styles.fieldGroup}>
                          <label className={styles.fieldLabel}>Method Detect Threads</label>
                          <input
                            type="number"
                            className="textInput"
                            value={data.gauMethodDetectThreads}
                            onChange={(e) => updateField('gauMethodDetectThreads', parseInt(e.target.value) || 25)}
                            min={1}
                          />
                          <span className={styles.fieldHint}>Concurrent threads</span>
                        </div>
                      </div>
                    )}

                    <div className={styles.toggleRow}>
                      <div>
                        <span className={styles.toggleLabel}>Filter Dead Endpoints</span>
                        <p className={styles.toggleDescription}>Exclude URLs returning 404/500/timeout from final results</p>
                      </div>
                      <Toggle
                        checked={data.gauFilterDeadEndpoints}
                        onChange={(checked) => updateField('gauFilterDeadEndpoints', checked)}
                      />
                    </div>
                  </>
                )}
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Docker Image</label>
                <input
                  type="text"
                  className="textInput"
                  value={data.gauDockerImage}
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
