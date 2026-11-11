'use client'

import { useState } from 'react'
import { ChevronDown, Play, Shield } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface NmapSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function NmapSection({ data, updateField, onRun }: NmapSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          Nmap Service Detection
          <NodeInfoTooltip section="Nmap" />
          <WikiInfoButton target="Nmap" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.nmapEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Nmap Service Detection"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.nmapEnabled}
              onChange={(checked) => updateField('nmapEnabled', checked)}
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
            Deep service version detection (-sV) and NSE vulnerability scripts (--script vuln).
            Runs after port discovery to identify exact software versions and known CVEs on each open port.
          </p>

          {data.nmapEnabled && (
            <>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Version Detection (-sV)</span>
                  <p className={styles.toggleDescription}>Probe open ports to determine service/version info. Essential for CVE matching.</p>
                </div>
                <Toggle
                  checked={data.nmapVersionDetection}
                  onChange={(checked) => updateField('nmapVersionDetection', checked)}
                />
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>NSE Vulnerability Scripts (--script vuln)</span>
                  <p className={styles.toggleDescription}>Run Nmap Scripting Engine vulnerability checks (vsftpd backdoor, Log4Shell, etc.). Disabled in stealth mode.</p>
                </div>
                <Toggle
                  checked={data.nmapScriptScan}
                  onChange={(checked) => updateField('nmapScriptScan', checked)}
                />
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timing Template</label>
                  <select
                    className="textInput"
                    value={data.nmapTimingTemplate}
                    onChange={(e) => updateField('nmapTimingTemplate', e.target.value)}
                  >
                    <option value="T1">T1 - Sneaky</option>
                    <option value="T2">T2 - Polite</option>
                    <option value="T3">T3 - Normal (default)</option>
                    <option value="T4">T4 - Aggressive</option>
                    <option value="T5">T5 - Insane</option>
                  </select>
                  <span className={styles.fieldHint}>Higher = faster but noisier. Stealth mode forces T2.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Total Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.nmapTimeout}
                    onChange={(e) => updateField('nmapTimeout', parseInt(e.target.value) || 600)}
                    min={60}
                  />
                  <span className={styles.fieldHint}>Maximum total scan duration</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Per-Host Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.nmapHostTimeout}
                    onChange={(e) => updateField('nmapHostTimeout', parseInt(e.target.value) || 300)}
                    min={30}
                  />
                  <span className={styles.fieldHint}>Max time per host before moving on</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Parallelism</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.nmapParallelism ?? 5}
                    onChange={(e) => updateField('nmapParallelism', parseInt(e.target.value) || 5)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Number of IPs to scan concurrently</span>
                </div>
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>AI Runtime Version Regex</span>
                  <p className={styles.toggleDescription}>Regex nmap product/version strings against AI runtimes (Ollama, vLLM, LiteLLM, TGI, Triton, llama.cpp). On match, sets Service.ai_runtime_version so downstream CVE lookups can join against AI library CVE clusters.</p>
                </div>
                <Toggle
                  checked={data.nmapAiVersionRegexEnabled ?? true}
                  onChange={(checked) => updateField('nmapAiVersionRegexEnabled', checked)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
