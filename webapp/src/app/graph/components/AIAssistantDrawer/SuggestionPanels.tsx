'use client'

import React, { useState } from 'react'
import { Shield, Target, Zap, ChevronDown } from 'lucide-react'
import { INFORMATIONAL_GROUPS, EXPLOITATION_GROUPS, POST_EXPLOITATION_GROUPS } from './suggestionData'
import styles from './AIAssistantDrawer.module.css'

interface SuggestionPanelsProps {
  isConnected: boolean
  setInputValue: (v: string) => void
}

export function SuggestionPanels({ isConnected, setInputValue }: SuggestionPanelsProps) {
  const [openTemplateGroup, setOpenTemplateGroup] = useState<string | null>(null)
  const [openInfoSubGroup, setOpenInfoSubGroup] = useState<string | null>(null)
  const [openExploitSubGroup, setOpenExploitSubGroup] = useState<string | null>(null)
  const [openPostSubGroup, setOpenPostSubGroup] = useState<string | null>(null)

  return (
    <div className={styles.templateGroups}>
      {/* Informational */}
      <div className={styles.templateGroup}>
        <button
          className={`${styles.templateGroupHeader} ${openTemplateGroup === 'informational' ? styles.templateGroupHeaderOpen : ''}`}
          onClick={() => setOpenTemplateGroup(prev => prev === 'informational' ? null : 'informational')}
          style={{ '--tg-color': 'var(--text-tertiary)' } as React.CSSProperties}
        >
          <Shield size={14} />
          <span>Informational</span>
          <ChevronDown size={14} className={styles.templateGroupChevron} />
        </button>
        {openTemplateGroup === 'informational' && (
          <div className={styles.templateGroupItems}>
            {INFORMATIONAL_GROUPS.map(group => (
              <React.Fragment key={group.id}>
                <button
                  className={`${styles.templateSubGroupHeader} ${openInfoSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                  onClick={() => setOpenInfoSubGroup(prev => prev === group.id ? null : group.id)}
                >
                  <span>{group.title}</span>
                  <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                </button>
                {openInfoSubGroup === group.id && (
                  <div className={styles.templateSubGroupItems}>
                    {group.items.map((section, i) => (
                      <React.Fragment key={i}>
                        {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                        {section.suggestions.map((s, j) => (
                          <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                            {s.label}
                          </button>
                        ))}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        )}
      </div>

      {/* Exploitation */}
      <div className={styles.templateGroup}>
        <button
          className={`${styles.templateGroupHeader} ${openTemplateGroup === 'exploitation' ? styles.templateGroupHeaderOpen : ''}`}
          onClick={() => setOpenTemplateGroup(prev => prev === 'exploitation' ? null : 'exploitation')}
          style={{ '--tg-color': 'var(--status-warning)' } as React.CSSProperties}
        >
          <Target size={14} />
          <span>Exploitation</span>
          <ChevronDown size={14} className={styles.templateGroupChevron} />
        </button>
        {openTemplateGroup === 'exploitation' && (
          <div className={styles.templateGroupItems}>
            {EXPLOITATION_GROUPS.map(group => (
              <React.Fragment key={group.id}>
                <button
                  className={`${styles.templateSubGroupHeader} ${openExploitSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                  onClick={() => setOpenExploitSubGroup(prev => prev === group.id ? null : group.id)}
                >
                  <span>{group.title}</span>
                  <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                </button>
                {openExploitSubGroup === group.id && (
                  <div className={styles.templateSubGroupItems}>
                    {group.items.map((section, i) => (
                      <React.Fragment key={i}>
                        {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                        {section.suggestions.map((s, j) => (
                          <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                            {s.label}
                          </button>
                        ))}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        )}
      </div>

      {/* Post-Exploitation */}
      <div className={styles.templateGroup}>
        <button
          className={`${styles.templateGroupHeader} ${openTemplateGroup === 'post_exploitation' ? styles.templateGroupHeaderOpen : ''}`}
          onClick={() => setOpenTemplateGroup(prev => prev === 'post_exploitation' ? null : 'post_exploitation')}
          style={{ '--tg-color': 'var(--status-error)' } as React.CSSProperties}
        >
          <Zap size={14} />
          <span>Post-Exploitation</span>
          <ChevronDown size={14} className={styles.templateGroupChevron} />
        </button>
        {openTemplateGroup === 'post_exploitation' && (
          <div className={styles.templateGroupItems}>
            {POST_EXPLOITATION_GROUPS.map(group => (
              <React.Fragment key={group.id}>
                <button
                  className={`${styles.templateSubGroupHeader} ${openPostSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                  onClick={() => setOpenPostSubGroup(prev => prev === group.id ? null : group.id)}
                >
                  <span>{group.title}</span>
                  <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                </button>
                {openPostSubGroup === group.id && (
                  <div className={styles.templateSubGroupItems}>
                    {group.items.map((section, i) => (
                      <React.Fragment key={i}>
                        {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                        {section.suggestions.map((s, j) => (
                          <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                            {s.label}
                          </button>
                        ))}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
