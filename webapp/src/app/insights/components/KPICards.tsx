'use client'

import { Activity, Shield, Github, Terminal } from 'lucide-react'
import { formatNumber } from '../utils/formatters'
import type { PipelineStatusData, UnreachablePipeline } from '../types'
import type { SessionsData } from '@/lib/websocket-types'
import { useSessionsAccess } from '@/hooks/useActiveSessions'
import styles from './KPICards.module.css'

interface KPI {
  label: string
  value: number
  accent?: string
}

interface KPICardsProps {
  items: KPI[]
  isLoading?: boolean
  pipeline?: PipelineStatusData | undefined
  sessions?: SessionsData | undefined
  /** The pipeline-status request itself failed: every pipeline's state is unknown. */
  pipelineError?: string | null
  /** The agent sessions request failed: the count is unknown, not 0. */
  sessionsError?: string | null
}

type PipelineEntry = PipelineStatusData[keyof PipelineStatusData]

function isUnreachable(p: PipelineEntry | undefined): p is UnreachablePipeline {
  return !!p && (p as UnreachablePipeline).reachable === false
}

/** "status unavailable (code · upstream HTTP n)" when the state is unknown; null when it is known. */
function unavailableText(p: PipelineEntry | undefined, requestError: string | null | undefined): string | null {
  if (isUnreachable(p)) {
    return `status unavailable (${[p.code, p.upstreamStatus ? `upstream HTTP ${p.upstreamStatus}` : ''].filter(Boolean).join(' · ')})`
  }
  return requestError ? 'status unavailable' : null
}

function PipelineCard({ label, icon, status, phase, unavailable, unavailableTitle }: {
  label: string
  icon: React.ReactNode
  status: string | undefined
  phase?: string
  unavailable?: string | null
  unavailableTitle?: string | null
}) {
  if (unavailable) {
    return (
      <div className="statCard">
        <div className="statLabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {icon}{label}
        </div>
        <div className={styles.pipelineStatus} title={unavailableTitle || unavailable}>
          <span className={`${styles.dot} ${styles.dotUnknown}`} />
          <span className={`${styles.statusText} ${styles.unavailable}`}>{unavailable}</span>
        </div>
      </div>
    )
  }

  const s = status?.toLowerCase() || 'idle'
  let dotCls = styles.dotIdle
  if (s === 'running' || s === 'starting') dotCls = styles.dotRunning
  else if (s === 'completed') dotCls = styles.dotCompleted
  else if (s === 'error' || s === 'failed') dotCls = styles.dotError
  else if (s === 'paused') dotCls = styles.dotPaused

  return (
    <div className="statCard">
      <div className="statLabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {icon}{label}
      </div>
      <div className={styles.pipelineStatus}>
        <span className={`${styles.dot} ${dotCls}`} />
        <span className={styles.statusText}>{status || 'idle'}</span>
        {phase && <span className={styles.phase}>{phase}</span>}
      </div>
    </div>
  )
}

function SessionsCard({ sessions, error }: { sessions: SessionsData | undefined; error?: string | null }) {
  // Someone without agent:sessions is never sent the count (the query is off too): no card at all.
  const refused = useSessionsAccess() === 'refused'
  const msf = sessions?.sessions || []
  const nonMsf = sessions?.non_msf_sessions || []
  const total = msf.length + nonMsf.length

  if (refused) return null

  if (error) {
    return (
      <div className="statCard" title={error}>
        <div className="statLabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Terminal size={12} />Active Shells
        </div>
        <div className={`statValue ${styles.unavailable}`}>unavailable</div>
      </div>
    )
  }

  return (
    <div className="statCard">
      <div className="statLabel" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Terminal size={12} />Active Shells
      </div>
      <div className="statValue" style={total > 0 ? { color: 'var(--status-success)' } : undefined}>
        {total}
      </div>
    </div>
  )
}

export function KPICards({ items, isLoading, pipeline, sessions, pipelineError, sessionsError }: KPICardsProps) {
  if (isLoading) {
    return (
      <div className={styles.grid}>
        {Array.from({ length: 10 }).map((_, i) => (
          <div key={i} className="statCard">
            <div className={`statLabel ${styles.skeletonLabel}`} />
            <div className={`statValue ${styles.skeletonValue}`} />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className={styles.grid}>
      {items.map((kpi) => (
        <div key={kpi.label} className="statCard">
          <div className="statLabel">{kpi.label}</div>
          <div className="statValue" style={kpi.accent ? { color: kpi.accent } : undefined}>
            {formatNumber(kpi.value)}
          </div>
        </div>
      ))}
      <SessionsCard sessions={sessions} error={sessionsError} />
      <PipelineCard label="Recon Pipeline" icon={<Activity size={12} />} status={pipeline?.recon?.status} phase={pipeline?.recon?.currentPhase}
        unavailable={unavailableText(pipeline?.recon, pipelineError)} unavailableTitle={pipelineError} />
      <PipelineCard label="GVM Scan" icon={<Shield size={12} />} status={pipeline?.gvm?.status}
        unavailable={unavailableText(pipeline?.gvm, pipelineError)} unavailableTitle={pipelineError} />
      <PipelineCard label="GitHub Hunt" icon={<Github size={12} />} status={pipeline?.githubHunt?.status}
        unavailable={unavailableText(pipeline?.githubHunt, pipelineError)} unavailableTitle={pipelineError} />
    </div>
  )
}
