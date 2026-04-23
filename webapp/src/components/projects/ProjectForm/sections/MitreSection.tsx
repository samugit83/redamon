'use client'

import { useState } from 'react'
import { ChevronDown, Network } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface MitreSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function MitreSection({ data, updateField }: MitreSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Network size={16} />
          MITRE ATT&CK / CWE / CAPEC
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.mitreEnabled}
              onChange={(checked) => updateField('mitreEnabled', checked)}
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
            Map discovered vulnerabilities to MITRE ATT&CK techniques, CWE weaknesses, and CAPEC attack patterns. Provides context for understanding how vulnerabilities could be exploited and prioritizing remediation efforts.
          </p>
          {data.mitreEnabled && (
          <>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Auto Update Database</span>
              <p className={styles.toggleDescription}>Keep MITRE data updated automatically</p>
            </div>
            <Toggle
              checked={data.mitreAutoUpdateDb}
              onChange={(checked) => updateField('mitreAutoUpdateDb', checked)}
            />
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Data Sources</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Include CWE</span>
                <p className={styles.toggleDescription}>Common Weakness Enumeration</p>
              </div>
              <Toggle
                checked={data.mitreIncludeCwe}
                onChange={(checked) => updateField('mitreIncludeCwe', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Include CAPEC</span>
                <p className={styles.toggleDescription}>Common Attack Pattern Enumeration</p>
              </div>
              <Toggle
                checked={data.mitreIncludeCapec}
                onChange={(checked) => updateField('mitreIncludeCapec', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Enrichment</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Enrich Recon Results</span>
                <p className={styles.toggleDescription}>Add MITRE data to reconnaissance findings</p>
              </div>
              <Toggle
                checked={data.mitreEnrichRecon}
                onChange={(checked) => updateField('mitreEnrichRecon', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Enrich GVM Results</span>
                <p className={styles.toggleDescription}>Add MITRE data to GVM findings</p>
              </div>
              <Toggle
                checked={data.mitreEnrichGvm}
                onChange={(checked) => updateField('mitreEnrichGvm', checked)}
              />
            </div>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Cache TTL (hours)</label>
            <input
              type="number"
              className="textInput"
              value={data.mitreCacheTtlHours}
              onChange={(e) => updateField('mitreCacheTtlHours', parseInt(e.target.value) || 24)}
              min={1}
              max={168}
            />
          </div>
          </>
          )}
        </div>
      )}
    </div>
  )
}
