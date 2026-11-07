'use client'

import { useState } from 'react'
import { ChevronDown, Play, Radar } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'
import { FileImportButton } from '../FileImportButton'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ZapAjaxSpiderSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function ZapAjaxSpiderSection({ data, updateField, onRun }: ZapAjaxSpiderSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Radar size={16} />
          ZAP Ajax Spider
          <NodeInfoTooltip section="ZapAjaxSpider" />
          <WikiInfoButton target="ZapAjaxSpider" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.zapAjaxSpiderEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run ZAP Ajax Spider"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.zapAjaxSpiderEnabled}
              onChange={(checked) => updateField('zapAjaxSpiderEnabled', checked)}
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
            Browser-driven Ajax Spider crawling using OWASP ZAP. Discovers API endpoints that only appear after JavaScript execution, SPA route changes, and authenticated browser requests.
          </p>

          {data.zapAjaxSpiderEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Seed Mode</label>
                  <select
                    className="select"
                    value={data.zapAjaxSpiderSeedMode}
                    onChange={(e) => updateField('zapAjaxSpiderSeedMode', e.target.value)}
                  >
                    <option value="base_urls">BaseURLs only</option>
                    <option value="base_urls_and_endpoints">BaseURLs and Endpoints</option>
                  </select>
                  <span className={styles.fieldHint}>Endpoint seeding can improve SPA/API coverage when prior crawlers found routes</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Browser</label>
                  <select
                    className="select"
                    value={data.zapAjaxSpiderBrowserId}
                    onChange={(e) => updateField('zapAjaxSpiderBrowserId', e.target.value)}
                  >
                    <option value="firefox-headless">firefox-headless</option>
                    <option value="chrome-headless">chrome-headless</option>
                    <option value="firefox">firefox</option>
                  </select>
                  <span className={styles.fieldHint}>Headless browsers are recommended for containerized recon</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Duration (minutes)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderMaxDuration}
                    onChange={(e) => updateField('zapAjaxSpiderMaxDuration', parseInt(e.target.value) || 10)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Maximum Ajax Spider runtime per seed URL</span>
                  <TimeEstimate estimate="10 min/seed is a practical default for SPAs; authenticated apps often need longer" />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Parallelism</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderParallelism}
                    onChange={(e) => updateField('zapAjaxSpiderParallelism', parseInt(e.target.value) || 3)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Number of seed URLs crawled simultaneously</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Seeds</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderMaxSeeds}
                    onChange={(e) => updateField('zapAjaxSpiderMaxSeeds', parseInt(e.target.value) || 250)}
                    min={1}
                    max={100000}
                  />
                  <span className={styles.fieldHint}>Most seed URLs crawled per run; each is a full browser crawl, so this bounds the phase&apos;s duration. Over the cap, every host keeps its base URL first</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Crawl Depth</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderMaxCrawlDepth}
                    onChange={(e) => updateField('zapAjaxSpiderMaxCrawlDepth', parseInt(e.target.value) || 5)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>How far ZAP follows browser interaction paths from each seed</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Crawl States</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderMaxCrawlStates}
                    onChange={(e) => updateField('zapAjaxSpiderMaxCrawlStates', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Maximum discovered browser states per seed (0 = unlimited)</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Number of Browsers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderNumberOfBrowsers}
                    onChange={(e) => updateField('zapAjaxSpiderNumberOfBrowsers', parseInt(e.target.value) || 1)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Concurrent browser instances inside ZAP</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max URLs</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderMaxUrls}
                    onChange={(e) => updateField('zapAjaxSpiderMaxUrls', parseInt(e.target.value) || 5000)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Maximum in-scope URLs to ingest into the graph</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Event Wait (ms)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderEventWait}
                    onChange={(e) => updateField('zapAjaxSpiderEventWait', parseInt(e.target.value) || 1000)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Wait after browser events so JavaScript requests can finish</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Reload Wait (ms)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zapAjaxSpiderReloadWait}
                    onChange={(e) => updateField('zapAjaxSpiderReloadWait', parseInt(e.target.value) || 1000)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Wait after page reloads and navigation changes</span>
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Scope Check</label>
                <select
                  className="select"
                  value={data.zapAjaxSpiderScopeCheck}
                  onChange={(e) => updateField('zapAjaxSpiderScopeCheck', e.target.value)}
                >
                  <option value="Strict">Strict</option>
                  <option value="Flexible">Flexible</option>
                </select>
                <span className={styles.fieldHint}>Strict keeps crawling close to configured BaseURLs; Flexible allows broader in-scope navigation</span>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Browser Interaction</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Click Default Elements</span>
                    <p className={styles.toggleDescription}>Click common links, buttons, and interactive controls during browser crawling</p>
                  </div>
                  <Toggle
                    checked={data.zapAjaxSpiderClickDefaultElems}
                    onChange={(checked) => updateField('zapAjaxSpiderClickDefaultElems', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Click Elements Once</span>
                    <p className={styles.toggleDescription}>Avoid repeated clicks on the same element to reduce loops and duplicate traffic</p>
                  </div>
                  <Toggle
                    checked={data.zapAjaxSpiderClickElemsOnce}
                    onChange={(checked) => updateField('zapAjaxSpiderClickElemsOnce', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Random Inputs</span>
                    <p className={styles.toggleDescription}>Fill basic form inputs with generated values to expose request paths</p>
                  </div>
                  <Toggle
                    checked={data.zapAjaxSpiderRandomInputs}
                    onChange={(checked) => updateField('zapAjaxSpiderRandomInputs', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Logout Avoidance</span>
                    <p className={styles.toggleDescription}>Avoid likely logout actions during authenticated browser crawling</p>
                  </div>
                  <Toggle
                    checked={data.zapAjaxSpiderLogoutAvoidance}
                    onChange={(checked) => updateField('zapAjaxSpiderLogoutAvoidance', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers and Cookies</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Header Lines</label>
                  <div className={styles.fileImportWrap}>
                    <textarea
                      className="textarea"
                      value={(data.zapAjaxSpiderCustomHeaders ?? []).join('\n')}
                      onChange={(e) => updateField('zapAjaxSpiderCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                      placeholder="Authorization: Bearer token123&#10;Cookie: session=abc; csrftoken=xyz"
                      rows={4}
                    />
                    <FileImportButton
                      variant="textarea"
                      fieldName="headers"
                      onImport={(values) => updateField('zapAjaxSpiderCustomHeaders', values)}
                    />
                  </div>
                  <span className={styles.fieldHint}>One raw header per line. Values are only shown here and sent to ZAP for authenticated crawling.</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Exclude Patterns</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>URL Patterns to Exclude</label>
                  <div className={styles.fileImportWrap}>
                    <textarea
                      className="textarea"
                      value={(data.zapAjaxSpiderExcludePatterns ?? []).join('\n')}
                      onChange={(e) => updateField('zapAjaxSpiderExcludePatterns', e.target.value.split('\n').filter(Boolean))}
                      placeholder="/logout&#10;/signout&#10;\\.png$&#10;\\.css$"
                      rows={5}
                    />
                    <FileImportButton
                      variant="textarea"
                      fieldName="exclude patterns"
                      onImport={(values) => updateField('zapAjaxSpiderExcludePatterns', values)}
                    />
                  </div>
                  <span className={styles.fieldHint}>Regexes for logout routes, static assets, and noisy browser paths</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
