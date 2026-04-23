'use client'

import { useState } from 'react'
import { ChevronDown, Play, Radar } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface MasscanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function MasscanSection({ data, updateField, onRun }: MasscanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Radar size={16} />
          Masscan Port Scanner
          <NodeInfoTooltip section="Masscan" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.masscanEnabled && (
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
              title="Run Masscan Port Scanner"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.masscanEnabled}
              onChange={(checked) => updateField('masscanEnabled', checked)}
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
            High-speed SYN port scanner optimized for large networks and IP/CIDR ranges.
            Uses raw packets for maximum speed. Requires root or CAP_NET_RAW.
            Incompatible with Tor (raw SYN packets bypass TCP stack).
          </p>

          {data.masscanEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Top Ports</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.masscanTopPorts}
                    onChange={(e) => updateField('masscanTopPorts', e.target.value)}
                    placeholder="1000"
                  />
                  <span className={styles.fieldHint}>Use &ldquo;100&rdquo;, &ldquo;1000&rdquo;, or &ldquo;full&rdquo; for all 65535 ports</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Custom Ports</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.masscanCustomPorts}
                    onChange={(e) => updateField('masscanCustomPorts', e.target.value)}
                    placeholder="80,443,8080-8090"
                  />
                  <span className={styles.fieldHint}>Overrides Top Ports if set. Use ranges: 8080-8090</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate (packets/sec)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.masscanRate}
                    onChange={(e) => updateField('masscanRate', parseInt(e.target.value) || 1000)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Packets/sec. Masscan can handle very high rates (10k+)</span>
                  <TimeEstimate estimate="1000: safe default | 10000+: fast but may overwhelm targets" />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Wait (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.masscanWait}
                    onChange={(e) => updateField('masscanWait', parseInt(e.target.value) || 10)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Seconds to wait for late responses after scan completes</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Retries</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.masscanRetries}
                    onChange={(e) => updateField('masscanRetries', parseInt(e.target.value) || 1)}
                    min={0}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Retry attempts for unresponsive ports</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Exclude Targets</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.masscanExcludeTargets}
                    onChange={(e) => updateField('masscanExcludeTargets', e.target.value)}
                    placeholder="10.0.0.1, 192.168.0.0/24"
                  />
                  <span className={styles.fieldHint}>Comma-separated IPs/CIDRs to exclude from scanning</span>
                </div>
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Banner Grabbing</span>
                  <p className={styles.toggleDescription}>Capture service banners (SSH, HTTP, etc.). Increases scan time but provides richer data.</p>
                </div>
                <Toggle
                  checked={data.masscanBanners}
                  onChange={(checked) => updateField('masscanBanners', checked)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
