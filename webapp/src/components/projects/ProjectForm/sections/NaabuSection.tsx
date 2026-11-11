'use client'

import { useState } from 'react'
import { ChevronDown, Play, Radio } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'
import { FileImportButton } from '../FileImportButton'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface NaabuSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function NaabuSection({ data, updateField, onRun }: NaabuSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Radio size={16} />
          Naabu Port Scanner
          <NodeInfoTooltip section="Naabu" />
          <WikiInfoButton target="Naabu" />
          <span className={styles.badgeActive}>Active</span>
          {data.naabuPassiveMode && <span className={styles.badgePassive}>Passive</span>}
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.naabuEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Naabu Port Scanner"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.naabuEnabled}
              onChange={(checked) => updateField('naabuEnabled', checked)}
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
            Fast port scanning using Naabu from ProjectDiscovery. Identifies open ports and services across discovered hosts, enabling targeted HTTP probing and vulnerability assessment on active endpoints.
          </p>

          {data.naabuEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Top Ports</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.naabuTopPorts}
                    onChange={(e) => updateField('naabuTopPorts', e.target.value)}
                    placeholder="1000"
                  />
                  <span className={styles.fieldHint}>Use &ldquo;100&rdquo;, &ldquo;1000&rdquo;, or &ldquo;full&rdquo; for all 65535 ports</span>
                  <TimeEstimate estimate="100: seconds | 1000: ~15 sec/host | full: minutes to hours" />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Custom Ports</label>
                  <div className={styles.fileImportWrap}>
                    <input
                      type="text"
                      className="textInput"
                      value={data.naabuCustomPorts}
                      onChange={(e) => updateField('naabuCustomPorts', e.target.value)}
                      placeholder="80,443,8080-8090"
                    />
                    <FileImportButton
                      fieldName="custom ports"
                      onImport={(values) => updateField('naabuCustomPorts', values.join(','))}
                    />
                  </div>
                  {data.naabuCustomPorts ? (
                    <span className={styles.fieldHintWarning}>
                      Custom Ports set - Top Ports is ignored. Only these ports are scanned and probed.
                    </span>
                  ) : (
                    <span className={styles.fieldHint}>Overrides Top Ports if set. Use ranges: 8080-8090</span>
                  )}
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.naabuRateLimit}
                    onChange={(e) => updateField('naabuRateLimit', parseInt(e.target.value) || 1000)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Packets/sec. Higher = faster but may trigger rate limiting</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.naabuThreads}
                    onChange={(e) => updateField('naabuThreads', parseInt(e.target.value) || 25)}
                    min={1}
                    max={100}
                  />
                  <span className={styles.fieldHint}>Concurrent scanning threads</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (ms)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.naabuTimeout}
                    onChange={(e) => updateField('naabuTimeout', parseInt(e.target.value) || 10000)}
                    min={1000}
                  />
                  <span className={styles.fieldHint}>Time to wait for port response (milliseconds)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Retries</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.naabuRetries}
                    onChange={(e) => updateField('naabuRetries', parseInt(e.target.value) || 1)}
                    min={0}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Retry attempts for failed port probes</span>
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Run Timeout (s)</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.naabuRunTimeout ?? 1800}
                  onChange={(e) => updateField('naabuRunTimeout', parseInt(e.target.value) || 1800)}
                  min={1}
                  max={86400}
                />
                <span className={styles.fieldHint}>
                  Cap on the whole naabu run, in seconds. When it is reached the container is stopped and the scan goes on: the open ports found so far are kept, and the targets naabu had not finished are recorded as not checked, never as having no open port. A low rate limit (or the engagement ceiling) slows the run, so a long target list may need more.
                </span>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Scan Type</label>
                <select
                  className="select"
                  value={data.naabuScanType}
                  onChange={(e) => updateField('naabuScanType', e.target.value)}
                >
                  <option value="s">SYN Scan (s) - Faster, requires root</option>
                  <option value="c">Connect Scan (c) - No root needed</option>
                </select>
                <span className={styles.fieldHint}>SYN is stealthier and faster but requires elevated privileges</span>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Options</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Exclude CDN</span>
                    <p className={styles.toggleDescription}>Only scan ports 80/443 on CDN hosts. Disable for cloud-hosted targets</p>
                  </div>
                  <Toggle
                    checked={data.naabuExcludeCdn}
                    onChange={(checked) => updateField('naabuExcludeCdn', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Display CDN</span>
                    <p className={styles.toggleDescription}>Include CDN provider info (Cloudflare, Akamai, etc.) in results</p>
                  </div>
                  <Toggle
                    checked={data.naabuDisplayCdn}
                    onChange={(checked) => updateField('naabuDisplayCdn', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Skip Host Discovery</span>
                    <p className={styles.toggleDescription}>Assume all hosts are up. Recommended for web targets</p>
                  </div>
                  <Toggle
                    checked={data.naabuSkipHostDiscovery}
                    onChange={(checked) => updateField('naabuSkipHostDiscovery', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Verify Ports</span>
                    <p className={styles.toggleDescription}>Extra TCP handshake to confirm ports are truly open</p>
                    <TimeEstimate estimate="+10-20% scan time" />
                  </div>
                  <Toggle
                    checked={data.naabuVerifyPorts}
                    onChange={(checked) => updateField('naabuVerifyPorts', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Passive Mode</span>
                    <p className={styles.toggleDescription}>Query Shodan InternetDB instead of active scanning. Stealthier but may be outdated</p>
                    <TimeEstimate estimate="Passive (Shodan): near-instant | Active: minutes per host" />
                  </div>
                  <Toggle
                    checked={data.naabuPassiveMode}
                    onChange={(checked) => updateField('naabuPassiveMode', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>AI Port Catalog</span>
                    <p className={styles.toggleDescription}>Annotate AI-bearing ports (Ollama 11434, Qdrant 6333, Open WebUI 8080, vLLM, LiteLLM, Triton, Milvus, Gradio, ComfyUI, …) - emits Technology nodes with category=ai-* linked to the Service</p>
                  </div>
                  <Toggle
                    checked={data.portScanAiPortCatalogEnabled ?? true}
                    onChange={(checked) => updateField('portScanAiPortCatalogEnabled', checked)}
                  />
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
