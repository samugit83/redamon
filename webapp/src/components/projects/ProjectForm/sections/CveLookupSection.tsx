'use client'

import { useState } from 'react'
import { ChevronDown, Database } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface CveLookupSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function CveLookupSection({ data, updateField }: CveLookupSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Database size={16} />
          CVE Lookup
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Enrich vulnerability findings with detailed CVE data from NVD and other sources. Provides CVSS scores, affected versions, exploitation status, and remediation guidance for discovered vulnerabilities.
          </p>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable CVE Lookup</span>
              <p className={styles.toggleDescription}>Enrich findings with CVE data</p>
              <TimeEstimate estimate="~1-5 min depending on technologies found" />
            </div>
            <Toggle
              checked={data.cveLookupEnabled}
              onChange={(checked) => updateField('cveLookupEnabled', checked)}
            />
          </div>

          {data.cveLookupEnabled && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>CVE Source</label>
                <select
                  className="select"
                  value={data.cveLookupSource}
                  onChange={(e) => updateField('cveLookupSource', e.target.value)}
                >
                  <option value="nvd">NVD (National Vulnerability Database)</option>
                  <option value="vulners">Vulners</option>
                </select>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max CVEs per Finding</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.cveLookupMaxCves}
                    onChange={(e) => updateField('cveLookupMaxCves', parseInt(e.target.value) || 20)}
                    min={1}
                    max={100}
                  />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Min CVSS Score</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.cveLookupMinCvss}
                    onChange={(e) => updateField('cveLookupMinCvss', parseFloat(e.target.value) || 0)}
                    min={0}
                    max={10}
                    step={0.1}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>API Keys (Optional)</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>NVD API Key</label>
                  <input
                    type="password"
                    className="textInput"
                    value={data.nvdApiKey}
                    onChange={(e) => updateField('nvdApiKey', e.target.value)}
                    placeholder="Enter NVD API key for higher rate limits"
                  />
                  <span className={styles.fieldHint}>
                    Get a free key at https://nvd.nist.gov/developers/request-an-api-key
                  </span>
                  <TimeEstimate estimate="Without key: rate-limited (10 req/min) | With key: ~80x faster" />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Vulners API Key</label>
                  <input
                    type="password"
                    className="textInput"
                    value={data.vulnersApiKey}
                    onChange={(e) => updateField('vulnersApiKey', e.target.value)}
                    placeholder="Enter Vulners API key"
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
