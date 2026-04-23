/**
 * Thinking Card Component
 *
 * Displays agent's thought process, reasoning, and action decisions.
 */

'use client'

import { useState } from 'react'
import { Brain, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import styles from './ThinkingCard.module.css'
import { TodoListWidget } from './TodoListWidget'
import { formatTokenCount } from '@/lib/formatTokens'
import type { ThinkingItem } from './AgentTimeline'

interface ThinkingCardProps {
  item: ThinkingItem
  isExpanded: boolean
  onToggleExpand: () => void
}

export function ThinkingCard({ item, isExpanded, onToggleExpand }: ThinkingCardProps) {
  const [copied, setCopied] = useState(false)
  const inTok = item.input_tokens ?? 0
  const outTok = item.output_tokens ?? 0
  const hasTokens = inTok > 0 || outTok > 0

  const handleCopy = async () => {
    try {
      const data = {
        thought: item.thought,
        reasoning: item.reasoning,
        action: item.action,
        tool_name: item.tool_name,
        tool_args: item.tool_args,
      }
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Silent fail
    }
  }

  return (
    <div className={styles.card}>
      <div className={styles.cardHeaderWrapper} onClick={onToggleExpand}>
        <div className={styles.cardHeaderTop}>
          <div className={styles.cardIcon}>
            <Brain size={14} className={styles.thinkingIcon} />
          </div>
          <div className={styles.headerInfo}>
            <span className={styles.titleText}>Thinking</span>
            {item.action && item.action !== 'thinking' && (
              <span className={styles.actionBadge}>{item.action}</span>
            )}
            {hasTokens && (
              <span className={styles.tokenMeta} title="LLM usage for this step">
                in {formatTokenCount(inTok)} · out {formatTokenCount(outTok)}
              </span>
            )}
          </div>
          <div className={styles.cardActions}>
            <button
              className={styles.copyButton}
              onClick={(e) => {
                e.stopPropagation()
                handleCopy()
              }}
              title="Copy JSON"
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
            </button>
            <button className={styles.expandButton}>
              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          </div>
        </div>
        {!isExpanded && (
          <div className={styles.compactPreview}>
            {item.thought && item.thought.trim() && (
              <p className={styles.previewText}>{item.thought}</p>
            )}
            {item.reasoning && item.reasoning.trim() && (
              <p className={styles.previewReasoning}>→ {item.reasoning}</p>
            )}
          </div>
        )}
      </div>

      {isExpanded && (
        <div className={styles.cardContent}>
          {/* Thought */}
          {item.thought && item.thought.trim() && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Thought</div>
              <div className={styles.sectionContent}>
                <p className={styles.text}>{item.thought}</p>
              </div>
            </div>
          )}

          {/* Reasoning */}
          {item.reasoning && item.reasoning.trim() && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Reasoning</div>
              <div className={styles.sectionContent}>
                <p className={styles.text}>{item.reasoning}</p>
              </div>
            </div>
          )}

          {/* Action (skip redundant "thinking" label) */}
          {item.action && item.action !== 'thinking' && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Action</div>
              <div className={styles.sectionContent}>
                <span className={styles.badge}>{item.action}</span>
                {item.tool_name && (
                  <>
                    <span className={styles.separator}>→</span>
                    <span className={styles.toolName}>{item.tool_name}</span>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Todo List */}
          {item.updated_todo_list && item.updated_todo_list.length > 0 && (
            <div className={styles.section}>
              <div className={styles.sectionLabel}>Tasks</div>
              <div className={styles.sectionContent}>
                <TodoListWidget items={item.updated_todo_list} />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
