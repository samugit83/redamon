'use client'

import { useState } from 'react'
import { ChevronDown, DatabaseZap, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { RegistryFields } from '../RegistryFields'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface WebCachePoisonSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function WebCachePoisonSection({ data, updateField, onRun }: WebCachePoisonSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <DatabaseZap size={16} />
          Web Cache Poisoning
          <NodeInfoTooltip section="WebCachePoison" />
          <WikiInfoButton target="WebCachePoison" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.webCachePoisonEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Web Cache Poisoning scan"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.webCachePoisonEnabled}
              onChange={(checked) => updateField('webCachePoisonEnabled', checked)}
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
            Detects <strong>web cache poisoning</strong> and <strong>web cache deception</strong> on live URLs.
            Runs the <strong>WCVS</strong> breadth engine for wide technique coverage, then a RedAmon-native
            <strong> 5-phase confirmation</strong> (cache oracle, isolated cache-buster, framework hypotheses,
            baseline&rarr;poison&rarr;clean persistence check, confidence scoring). Only findings at or above the
            confidence threshold become <code>Vulnerability</code> nodes with
            <code>source=&quot;cache_poisoning&quot;</code>. Tests use benign canaries and
            isolated cache buckets so the real cache is never poisoned.
          </p>

          {data.webCachePoisonEnabled && (
            <>
              {/* Scan profile */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Scan profile</label>
                <select
                  className="textInput"
                  value={data.webCachePoisonScanProfile || 'safe-confirm'}
                  onChange={(e) => updateField('webCachePoisonScanProfile', e.target.value)}
                >
                  <option value="safe-confirm">safe-confirm (production recon - benign, isolated)</option>
                  <option value="extended">extended (owned test targets)</option>
                  <option value="research">research (lab only - enables CPDoS if allowed)</option>
                </select>
                <span className={styles.fieldHint}>
                  <code>safe-confirm</code> never sends destructive payloads and always isolates tests.
                </span>
              </div>

              {/* Technique toggles */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Techniques</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Framework hypothesis packs</div>
                    <div className={styles.toggleDescription}>
                      Fire Next.js / Nuxt / Remix-specific vectors (<code>x-invoke-status</code>, <code>__nextDataReq</code>, <code>/_payload.json</code>, <code>_data</code>) only when the technology fingerprint matches.
                    </div>
                  </div>
                  <Toggle
                    checked={data.webCachePoisonAllowFrameworkPacks}
                    onChange={(c) => updateField('webCachePoisonAllowFrameworkPacks', c)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Silent-cache detection (frozen-Date)</div>
                    <div className={styles.toggleDescription}>
                      Catch caches that emit no <code>X-Cache</code>/<code>Age</code> headers (default Varnish/nginx, hardened CDNs) by fetching twice across a short delay and checking whether the origin <code>Date</code> is frozen. Without this, silent caches are skipped.
                    </div>
                  </div>
                  <Toggle
                    checked={data.webCachePoisonBehavioralOracle}
                    onChange={(c) => updateField('webCachePoisonBehavioralOracle', c)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Non-reflective (differential) detection</div>
                    <div className={styles.toggleDescription}>
                      Also confirm poisons that change the response <em>behaviour</em> (a persisted status code, <code>Location</code> redirect, or body) with no echoed marker, guarded against false positives by requiring the affected dimension to be stable across two clean baselines. Catches CPDoS status flips and scheme/redirect poisoning. Adds one extra baseline request per vector. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.webCachePoisonDifferential ?? true}
                    onChange={(c) => updateField('webCachePoisonDifferential', c)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Web cache deception</div>
                    <div className={styles.toggleDescription}>
                      Path-confusion tricks (<code>/account/x.css</code>) that fool the cache into storing a private page.
                    </div>
                  </div>
                  <Toggle
                    checked={data.webCachePoisonAllowDeception}
                    onChange={(c) => updateField('webCachePoisonAllowDeception', c)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Allow CPDoS (cache-poisoned DoS)</div>
                    <div className={styles.toggleDescription}>
                      Oversized-header / meta-char tests that can serve errors to all visitors. Only honored in the <code>research</code> profile. Off by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.webCachePoisonAllowCpdos}
                    onChange={(c) => updateField('webCachePoisonAllowCpdos', c)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Cross-vantage revalidation</div>
                    <div className={styles.toggleDescription}>
                      Re-confirm findings from a second network vantage. Requires extra egress infrastructure; off by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.webCachePoisonCrossVantage}
                    onChange={(c) => updateField('webCachePoisonCrossVantage', c)}
                  />
                </div>
              </div>

              {/* Performance */}
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Min confidence (0–1)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.webCachePoisonMinConfidence ?? 0.8}
                    onChange={(e) => updateField('webCachePoisonMinConfidence', parseFloat(e.target.value) || 0.8)}
                    min={0}
                    max={1}
                    step={0.05}
                  />
                  <span className={styles.fieldHint}>Only findings scoring at or above this become Vulnerability nodes. 0.8 keeps Confirmed + Strong.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>WCVS threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.webCachePoisonConcurrency ?? 10}
                    onChange={(e) => updateField('webCachePoisonConcurrency', parseInt(e.target.value, 10) || 10)}
                    min={1}
                    max={50}
                  />
                  <span className={styles.fieldHint}>Parallelism for the WCVS breadth sweep. Higher = faster, louder for the target.</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Confirmation workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.webCachePoisonConfirmWorkers ?? 6}
                    onChange={(e) => updateField('webCachePoisonConfirmWorkers', parseInt(e.target.value, 10) || 6)}
                    min={1}
                    max={16}
                  />
                  <span className={styles.fieldHint}>How many URLs the native confirmation tests in parallel (bounds concurrent in-flight requests). Higher = faster; lower = stealthier. 1 = fully sequential.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max requests/sec per host (0 = unlimited)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.webCachePoisonMaxRpsPerHost ?? 0}
                    onChange={(e) => updateField('webCachePoisonMaxRpsPerHost', parseFloat(e.target.value) || 0)}
                    min={0}
                    max={1000}
                    step={0.5}
                  />
                  <span className={styles.fieldHint}>Rate cap passed to WCVS. Use a low value to stay under WAF thresholds.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Custom cache header (optional)</label>
                  <input
                    type="text"
                    className="textInput"
                    placeholder="e.g. X-Cache-Status"
                    value={data.webCachePoisonCacheHeader || ''}
                    onChange={(e) => updateField('webCachePoisonCacheHeader', e.target.value)}
                  />
                  <span className={styles.fieldHint}>Override the cache hit/miss header if the target uses a non-standard one.</span>
                </div>
              </div>

              {data.webCachePoisonBehavioralOracle && (
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Silent-cache probe delay (seconds)</label>
                    <input
                      type="number"
                      className="textInput"
                      value={data.webCachePoisonBehavioralDelay ?? 1.1}
                      onChange={(e) => updateField('webCachePoisonBehavioralDelay', parseFloat(e.target.value) || 1.1)}
                      min={0.5}
                      max={10}
                      step={0.1}
                    />
                    <span className={styles.fieldHint}>Wait between the two frozen-Date probes. Larger = more reliable on slow origins, but adds this much latency per silent URL. Default 1.1.</span>
                  </div>
                </div>
              )}
            </>
          )}

          <RegistryFields
            keys={['webCachePoisonCacheBusterParam', 'webCachePoisonTimeout', 'webCachePoisonTimeoutPerReq', 'webCachePoisonVerifySsl']}
            data={data}
            updateField={updateField}
            title="Advanced"
            description="Settings this tool accepts that have no dedicated control. Bounds, options and descriptions come from the settings registry, so they are the same ones the API enforces."
          />
        </div>
      )}
    </div>
  )
}
