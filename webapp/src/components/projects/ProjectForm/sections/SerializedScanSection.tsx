'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ChevronDown, Binary, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SerializedScanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

/**
 * Serialized object scan: a passive, in-memory recon module (GROUP 5b, beside
 * JS Recon). It flags serialized-object signatures across every family as
 * info-severity :Vulnerability candidates; the agent's deserialization skill
 * confirms them out of band. TrafficMind (capture proxy) is a soft prerequisite
 * -- without captured traffic the agent has no request-side corpus to confirm
 * against, so we surface a warning rather than block (plan §4.1).
 */
export function SerializedScanSection({ data, updateField, onRun }: SerializedScanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const jevStatus = useHasJevProvider()

  const d = data as unknown as {
    serializedScanEnabled?: boolean
    captureProxyEnabled?: boolean
    attackSkillConfig?: unknown
  }
  const enabled = !!d.serializedScanEnabled
  const captureOff = !d.captureProxyEnabled

  // The recon module only FLAGS candidates; the agent's built-in
  // `deserialization` skill is what CONFIRMS and promotes them. Mirror
  // AttackSkillsSection.isBuiltInEnabled exactly: present-and-not-false is on,
  // and a missing key is off (the shipped default), matching the agent's
  // get_enabled_builtin_skills. So the alert fires when the scan is on but the
  // confirming skill is not, i.e. the detect->confirm loop is half-wired.
  const builtIn: Record<string, unknown> =
    d.attackSkillConfig && typeof d.attackSkillConfig === 'object'
      && 'builtIn' in (d.attackSkillConfig as Record<string, unknown>)
      ? ((d.attackSkillConfig as { builtIn?: Record<string, unknown> }).builtIn ?? {})
      : {}
  const deserSkillOn = 'deserialization' in builtIn ? builtIn.deserialization !== false : false

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Binary size={16} />
          Serialized Object Scan
          <NodeInfoTooltip section="SerializedScan" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Serialized Object Scan"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('serializedScanEnabled' as keyof FormData, checked as never)}
              aria-label="Enable Serialized Object Scan"
            />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Scans the response headers, Set-Cookie values, enumerated parameters and crawled form fields the
            pipeline already holds for serialized-object signatures: native Java, polymorphic JSON
            (Jackson/FastJSON), XMLDecoder, XStream, SnakeYAML, PHP, Python pickle, .NET BinaryFormatter /
            ViewState, Ruby Marshal and Hessian. It is passive and in-memory, sends no extra traffic and never
            deserializes anything. Each format a value carries becomes one info-severity candidate, which the
            agent&apos;s deserialization skill confirms with a non-destructive oracle (out-of-band callback,
            timing or error differential).
          </p>

          {enabled && (
          <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)' }}>
            <AiToggleLabel
              label="Rank candidates with Jev"
              tooltip={
                'Jev is asked, per distinct flagged blob, which serialization format it is and how ' +
                'likely it is to be an attacker-reachable sink. Both land on the candidate, and the ' +
                "agent's deserialization skill confirms the most reachable first. It never drops a " +
                'candidate or changes the format the signatures matched; without a Jev provider selected, or for ' +
                'a blob Jev cannot answer, the candidates stay exactly as the signatures flagged ' +
                'them. Same switch as in the Target tab AI panel. ' +
                (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
              }
            />
            <JevEngineControl
              variant="jevOnly"
              value={data.serializedScanJevRank}
              enabled={data.aiInPipeline}
              jevStatus={jevStatus}
              disabledHint='Enable "AI in Pipeline" in the Target tab to turn this on.'
              onSelect={(on) => updateField('serializedScanJevRank', on)}
            />
          </div>
          )}

          {enabled && !deserSkillOn && (
            <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`} role="alert">
              <strong>Half a cycle.</strong> This module only FLAGS candidates (info severity). The agent&apos;s
              built-in <strong>Insecure Deserialization</strong> skill is what CONFIRMS them with the
              non-destructive oracle and promotes the real ones. It is currently OFF, so every hit will
              sit as an unconfirmed lead. Enable it under AI Agent &gt; Attack Skills for the full detect to confirm
              cycle.
            </p>
          )}

          {enabled && captureOff && (
            <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
              Works best with TrafficMind (HTTP capture) enabled: the agent needs captured request traffic to
              confirm candidates. Enable it under Scan Modules &gt; Traffic capture, or on the{' '}
              <Link href="/traffic" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                TrafficMind
              </Link>{' '}
              page. Detection still runs without it, but with a thinner corpus.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
