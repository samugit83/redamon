'use client'

import { Waypoints } from 'lucide-react'
import { Tooltip } from '@/components/ui'
import { SECTION_NODE_MAP, SECTION_INPUT_MAP, SECTION_ENRICH_MAP } from './nodeMapping'
import styles from './ProjectForm.module.css'

interface NodeInfoTooltipProps {
  section: string
}

export function NodeInfoTooltip({ section }: NodeInfoTooltipProps) {
  const inputNodes = SECTION_INPUT_MAP[section] ?? []
  const outputNodes = SECTION_NODE_MAP[section] ?? []
  const enrichNodes = SECTION_ENRICH_MAP[section] ?? []

  if (!inputNodes.length && !outputNodes.length && !enrichNodes.length) return null

  const content = (
    <div className={styles.nodeInfoContent}>
      {inputNodes.length > 0 && (
        <>
          <span className={styles.nodeInfoLabel}>Consumes</span>
          <div className={styles.nodeInfoPills}>
            {inputNodes.map(node => (
              <span key={node} className={styles.nodeInfoPillInput}>{node}</span>
            ))}
          </div>
        </>
      )}
      {outputNodes.length > 0 && (
        <>
          <span className={styles.nodeInfoLabel}>Produces</span>
          <div className={styles.nodeInfoPills}>
            {outputNodes.map(node => (
              <span key={node} className={styles.nodeInfoPill}>{node}</span>
            ))}
          </div>
        </>
      )}
      {enrichNodes.length > 0 && (
        <>
          <span className={styles.nodeInfoLabel}>Enriches</span>
          <div className={styles.nodeInfoPills}>
            {enrichNodes.map(node => (
              <span key={node} className={styles.nodeInfoPillEnrich}>{node}</span>
            ))}
          </div>
        </>
      )}
    </div>
  )

  return (
    <Tooltip content={content} position="bottom" delay={150}>
      <Waypoints size={13} className={styles.nodeInfoIcon} />
    </Tooltip>
  )
}
