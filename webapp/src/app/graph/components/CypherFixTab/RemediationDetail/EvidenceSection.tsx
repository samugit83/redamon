'use client'

import { memo } from 'react'
import { AlertTriangle, Link, Terminal } from 'lucide-react'
import { ExternalLink } from '@/components/ui'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

interface EvidenceSectionProps {
  remediation: Remediation
}

export const EvidenceSection = memo(function EvidenceSection({ remediation }: EvidenceSectionProps) {
  const assets = Array.isArray(remediation.affectedAssets) ? remediation.affectedAssets : []

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <AlertTriangle size={14} />
        Evidence
      </h4>

      {/* Affected Assets */}
      {assets.length > 0 && (
        <div className={styles.subsection}>
          <h5 className={styles.subsectionTitle}>
            <Link size={12} />
            Affected Assets ({assets.length})
          </h5>
          <div className={styles.assetList}>
            {assets.map((asset, i) => (
              <div key={i} className={styles.assetItem}>
                <span className={styles.assetType}>{asset.type}</span>
                <span className={styles.assetName}>{asset.name}</span>
                {asset.url && <span className={styles.assetUrl}><ExternalLink href={asset.url}>{asset.url}</ExternalLink></span>}
                {asset.ip && <span className={styles.assetIp}>{asset.ip}{asset.port ? `:${asset.port}` : ''}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CVE/CWE/CAPEC */}
      {(remediation.cveIds.length > 0 || remediation.cweIds.length > 0) && (
        <div className={styles.subsection}>
          <h5 className={styles.subsectionTitle}>Identifiers</h5>
          <div className={styles.identifiers}>
            {remediation.cveIds.map(id => (
              <span key={id} className={styles.cveTag}>{id}</span>
            ))}
            {remediation.cweIds.map(id => (
              <span key={id} className={styles.cweTag}>{id}</span>
            ))}
            {remediation.capecIds.map(id => (
              <span key={id} className={styles.capecTag}>{id}</span>
            ))}
          </div>
        </div>
      )}

      {/* Raw Evidence */}
      {remediation.evidence && (
        <div className={styles.subsection}>
          <h5 className={styles.subsectionTitle}>
            <Terminal size={12} />
            Raw Evidence
          </h5>
          <pre className={styles.evidenceBlock}>{remediation.evidence}</pre>
        </div>
      )}

      {/* Attack Chain Path */}
      {remediation.attackChainPath && (
        <div className={styles.subsection}>
          <h5 className={styles.subsectionTitle}>Attack Chain Path</h5>
          <pre className={styles.evidenceBlock}>{remediation.attackChainPath}</pre>
        </div>
      )}
    </div>
  )
})
