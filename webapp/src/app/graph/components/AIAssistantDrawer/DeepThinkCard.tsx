/**
 * Deep Think Card Component
 *
 * Displays the agent's deep reasoning analysis at key decision points.
 */

'use client'

import { useState } from 'react'
import { Lightbulb, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import styles from './DeepThinkCard.module.css'
import type { DeepThinkItem } from './AgentTimeline'

interface DeepThinkCardProps {
  item: DeepThinkItem
  isExpanded: boolean
  onToggleExpand: () => void
}

export function DeepThinkCard({ item, isExpanded, onToggleExpand }: DeepThinkCardProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(item.analysis)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Silent fail
    }
  }

  // Parse the markdown-formatted analysis into sections
  const sections = parseAnalysis(item.analysis)

  return (
    <div className={styles.card}>
      <div className={styles.cardHeaderWrapper} onClick={onToggleExpand}>
        <div className={styles.cardHeaderTop}>
          <div className={styles.cardIcon}>
            <Lightbulb size={14} className={styles.deepThinkIcon} />
          </div>
          <div className={styles.headerInfo}>
            <span className={styles.titleText}>Deep Think</span>
            <span className={styles.triggerBadge}>{item.trigger_reason}</span>
          </div>
          <div className={styles.cardActions}>
            <button
              className={styles.copyButton}
              onClick={(e) => {
                e.stopPropagation()
                handleCopy()
              }}
              title="Copy analysis"
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
            </button>
            <button className={styles.expandButton}>
              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          </div>
        </div>
        {!isExpanded && sections.situation && (
          <div className={styles.compactPreview}>
            <p className={styles.previewText}>{sections.situation}</p>
          </div>
        )}
      </div>

      {isExpanded && (
        <div className={styles.cardContent}>
          {sections.situation && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Situation</div>
              <p className={styles.text}>{sections.situation}</p>
            </div>
          )}
          {sections.vectors && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Attack Vectors</div>
              <p className={styles.text}>{sections.vectors}</p>
            </div>
          )}
          {sections.approach && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Approach</div>
              <p className={styles.text}>{sections.approach}</p>
            </div>
          )}
          {sections.priority && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Priority</div>
              <p className={styles.text}>{sections.priority}</p>
            </div>
          )}
          {sections.risks && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Risks</div>
              <p className={styles.text}>{sections.risks}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

interface AnalysisSections {
  situation: string
  vectors: string
  approach: string
  priority: string
  risks: string
}

function parseAnalysis(analysis: string): AnalysisSections {
  const result: AnalysisSections = { situation: '', vectors: '', approach: '', priority: '', risks: '' }

  // The analysis is formatted as: **Label:** value\n\n**Label:** value
  const lines = analysis.split('\n\n')
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith('**Situation:**')) {
      result.situation = trimmed.replace('**Situation:**', '').trim()
    } else if (trimmed.startsWith('**Attack Vectors:**')) {
      result.vectors = trimmed.replace('**Attack Vectors:**', '').trim()
    } else if (trimmed.startsWith('**Approach:**')) {
      result.approach = trimmed.replace('**Approach:**', '').trim()
    } else if (trimmed.startsWith('**Priority:**')) {
      result.priority = trimmed.replace('**Priority:**', '').trim()
    } else if (trimmed.startsWith('**Risks:**')) {
      result.risks = trimmed.replace('**Risks:**', '').trim()
    }
  }

  // Fallback: if nothing parsed, use raw analysis as situation
  if (!result.situation && !result.vectors && !result.approach) {
    result.situation = analysis
  }

  return result
}
