'use client'

import { Globe, Radar, ArrowDown, MessageSquare } from 'lucide-react'
import styles from './GraphEmptyState.module.css'

export function GraphEmptyState() {
  return (
    <div className={styles.wrapper}>
      <div className={styles.card}>
        <div className={styles.iconWrapper}>
          <Globe size={48} strokeWidth={1.5} />
        </div>
        <h2 className={styles.title}>No Recon Data Yet</h2>
        <p className={styles.description}>
          Run the recon pipeline to discover and map your target's attack surface.
          The graph will populate with domains, subdomains, IPs, ports, services,
          and vulnerabilities.
        </p>
        <div className={styles.steps}>
          <div className={styles.step}>
            <Radar size={16} />
            <span>Run recon pipeline on your target</span>
          </div>
          <ArrowDown size={14} className={styles.arrow} />
          <div className={styles.step}>
            <Globe size={16} />
            <span>Graph populates with discovered assets</span>
          </div>
          <ArrowDown size={14} className={styles.arrow} />
          <div className={styles.step}>
            <MessageSquare size={16} />
            <span>Use the AI agent to analyze and exploit</span>
          </div>
        </div>
      </div>
    </div>
  )
}
