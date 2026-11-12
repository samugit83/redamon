'use client'

import { Loader2, Play } from 'lucide-react'
import { usePermissionRefused } from '@/hooks/useCan'
import { ForbiddenNotice, forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import type { EmptyGraphState } from '../../utils/emptyGraph'
import styles from './GraphEmptyState.module.css'

interface GraphEmptyStateProps {
  state: EmptyGraphState
  onStartRecon: () => void
  onResumeRecon: () => void
}

const COPY: Record<EmptyGraphState, { title: string; description: string }> = {
  start: {
    title: 'No graph yet',
    description:
      'This project has no recon data. Start the recon pipeline to map its attack surface: subdomains, IPs, ports, services, technologies and vulnerabilities appear here as they are discovered.',
  },
  paused: {
    title: 'Recon paused',
    description:
      'The pipeline was paused before it wrote anything to the graph. Resume it to keep mapping the attack surface.',
  },
  running: {
    title: 'Recon in progress',
    description:
      'Nothing has been written to the graph yet. Nodes appear here as soon as the first results come in.',
  },
  readOnly: {
    title: 'This version is empty',
    description:
      'The saved version you are viewing has no nodes. Switch back to the active version to run a scan.',
  },
}

const TARGET = { x: 120, y: 62 }

// The undiscovered nodes around the target, in the order they light up while a
// scan runs. `from` is the node each one hangs off (the target when omitted).
const GHOSTS: { x: number; y: number; r: number; color: string; from?: number }[] = [
  { x: 62, y: 34, r: 8, color: 'var(--node-subdomain)' },
  { x: 180, y: 38, r: 8, color: 'var(--node-ip)' },
  { x: 74, y: 96, r: 7, color: 'var(--node-baseurl)' },
  { x: 172, y: 92, r: 7, color: 'var(--node-service)' },
  { x: 22, y: 58, r: 6, color: 'var(--node-technology)', from: 0 },
  { x: 222, y: 66, r: 6, color: 'var(--node-endpoint)', from: 1 },
  { x: 212, y: 108, r: 5.5, color: 'var(--node-vulnerability)', from: 3 },
]

export function GraphEmptyState({ state, onStartRecon, onResumeRecon }: GraphEmptyStateProps) {
  const { title, description } = COPY[state]
  // Start and resume both ask recon:scan (route manifest).
  const refused = usePermissionRefused('recon:scan')
  const refusedTitle = refused ? forbiddenNoticeText('recon:scan') : undefined

  return (
    <div className={styles.wrapper}>
      <section className={styles.card} data-state={state} aria-labelledby="graph-empty-title">
        <svg className={styles.illustration} viewBox="0 0 244 124" aria-hidden="true">
          {GHOSTS.map((ghost, i) => {
            const origin = ghost.from === undefined ? TARGET : GHOSTS[ghost.from]
            return (
              <line
                key={`link-${i}`}
                className={styles.link}
                x1={origin.x}
                y1={origin.y}
                x2={ghost.x}
                y2={ghost.y}
              />
            )
          })}
          {GHOSTS.map((ghost, i) => (
            <g key={`ghost-${i}`}>
              <circle className={styles.ghostBacking} cx={ghost.x} cy={ghost.y} r={ghost.r} />
              <circle
                className={styles.ghost}
                cx={ghost.x}
                cy={ghost.y}
                r={ghost.r}
                style={{ color: ghost.color, animationDelay: `${i * 0.35}s` }}
              />
            </g>
          ))}
          <circle className={styles.halo} cx={TARGET.x} cy={TARGET.y} r={12} />
          <circle className={styles.target} cx={TARGET.x} cy={TARGET.y} r={12} />
        </svg>

        <h2 id="graph-empty-title" className={styles.title}>{title}</h2>
        <p className={styles.description}>{description}</p>

        {state === 'start' && (
          <button type="button" className={styles.startButton} onClick={onStartRecon} disabled={refused} title={refusedTitle}>
            <Play size={15} />
            <span>Start Recon Pipeline</span>
          </button>
        )}
        {state === 'paused' && (
          <button type="button" className={styles.startButton} onClick={onResumeRecon} disabled={refused} title={refusedTitle}>
            <Play size={15} />
            <span>Resume Recon</span>
          </button>
        )}
        {refused && (state === 'start' || state === 'paused') && (
          <ForbiddenNotice permission="recon:scan" className={styles.notice} />
        )}
        {state === 'running' && (
          <div className={styles.running} role="status">
            <Loader2 size={14} className={styles.spinner} />
            <span>Scan running</span>
          </div>
        )}
      </section>
    </div>
  )
}
