'use client'

import React, { KeyboardEvent, useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Send, Loader2, Square, Play, Zap, X, Download, Upload } from 'lucide-react'
import { useAlertModal } from '@/components/ui'
import styles from './AIAssistantDrawer.module.css'
import type { ActiveSkill } from './hooks/useSendHandlers'

interface ChatSkillSummary {
  id: string
  name: string
  description: string | null
  category: string
}

interface InputAreaProps {
  inputRef: React.RefObject<HTMLTextAreaElement | null>
  inputValue: string
  handleInputChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  handleKeyDown: (e: KeyboardEvent<HTMLTextAreaElement>) => void
  handleSend: () => void
  handleStop: () => void
  handleResume: () => void
  isConnected: boolean
  isLoading: boolean
  isStopped: boolean
  isStopping: boolean
  awaitingApproval: boolean
  awaitingQuestion: boolean
  awaitingToolConfirmation: boolean
  userId: string
  setInputValue: (v: string) => void
  activeSkill: ActiveSkill | null
  setActiveSkill: (v: ActiveSkill | null) => void
  onSkillActivate: (skillId: string, skillName?: string) => Promise<any>
  // Set to true when the user drags the native resize grip, so keystroke
  // auto-grow stops fighting the user's chosen height until next send.
  userResizedRef: React.MutableRefObject<boolean>
}

interface GroupedSkill {
  category: string
  skills: ChatSkillSummary[]
}

function groupByCategory(skills: ChatSkillSummary[]): GroupedSkill[] {
  const map: Record<string, ChatSkillSummary[]> = {}
  for (const s of skills) {
    const cat = s.category || 'general'
    if (!map[cat]) map[cat] = []
    map[cat].push(s)
  }
  return Object.entries(map)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, skills]) => ({ category, skills }))
}

export function InputArea({
  inputRef,
  inputValue,
  handleInputChange,
  handleKeyDown: parentHandleKeyDown,
  handleSend,
  handleStop,
  handleResume,
  isConnected,
  isLoading,
  isStopped,
  isStopping,
  awaitingApproval,
  awaitingQuestion,
  awaitingToolConfirmation,
  userId,
  setInputValue,
  activeSkill,
  setActiveSkill,
  onSkillActivate,
  userResizedRef,
}: InputAreaProps) {
  const { alert: showAlert } = useAlertModal()
  const [skills, setSkills] = useState<ChatSkillSummary[]>([])
  const [skillsFetched, setSkillsFetched] = useState(false)
  const [showSkillPicker, setShowSkillPicker] = useState(false)
  const [showAutocomplete, setShowAutocomplete] = useState(false)
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [importing, setImporting] = useState(false)
  const [uploading, setUploading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const pickerRef = useRef<HTMLDivElement>(null)

  // Fetch skills on mount
  useEffect(() => {
    if (!userId || skillsFetched) return
    let cancelled = false
    fetch(`/api/users/${userId}/chat-skills`)
      .then((res: Response) => res.ok ? res.json() : [])
      .then((data: ChatSkillSummary[]) => {
        if (!cancelled) {
          setSkills(data)
          setSkillsFetched(true)
        }
      })
      .catch(() => {
        if (!cancelled) setSkillsFetched(true)
      })
    return () => { cancelled = true }
  }, [userId, skillsFetched])

  // Determine if autocomplete should show based on input -- works anywhere in text
  const autocompleteMatch = useMemo((): { filter: string; start: number; end: number } | null => {
    // Find /s, /sk, /ski, /skil, /skill, or /skill <query> anywhere in the input
    const match = inputValue.match(/\/s(k(i(l(l( +(\S*))?)?)?)?)?/i)
    if (!match) return null
    const fullStart = match.index!
    const fullEnd = fullStart + match[0].length
    // If we have "/skill " with a space and query text, extract the filter
    const skillMatch = inputValue.slice(fullStart).match(/^\/skill +(\S*)/i)
    if (skillMatch) {
      return { filter: skillMatch[1].toLowerCase(), start: fullStart, end: fullEnd }
    }
    // Otherwise show all (we matched /s, /sk, etc.)
    return { filter: '', start: fullStart, end: fullEnd }
  }, [inputValue])

  const autocompleteFilter = autocompleteMatch?.filter ?? null

  // Show/hide autocomplete based on filter
  useEffect(() => {
    if (autocompleteFilter !== null) {
      setShowAutocomplete(true)
      setSelectedIndex(0)
    } else {
      setShowAutocomplete(false)
    }
  }, [autocompleteFilter])

  // Filtered and grouped skills for autocomplete
  const filteredSkills = useMemo(() => {
    if (autocompleteFilter === null) return []
    if (autocompleteFilter === '') return skills
    return skills.filter((s: ChatSkillSummary) =>
      s.name.toLowerCase().includes(autocompleteFilter) ||
      s.category.toLowerCase().includes(autocompleteFilter)
    )
  }, [skills, autocompleteFilter])

  const groupedFiltered = useMemo(() => groupByCategory(filteredSkills), [filteredSkills])

  // Flat list for keyboard navigation
  const flatFiltered = useMemo((): ChatSkillSummary[] => {
    const flat: ChatSkillSummary[] = []
    for (const g of groupedFiltered) {
      for (const s of g.skills) flat.push(s)
    }
    return flat
  }, [groupedFiltered])

  // Skills for the picker button (all, grouped)
  const groupedAll = useMemo(() => groupByCategory(skills), [skills])
  const flatAll = useMemo((): ChatSkillSummary[] => {
    const flat: ChatSkillSummary[] = []
    for (const g of groupedAll) {
      for (const s of g.skills) flat.push(s)
    }
    return flat
  }, [groupedAll])

  // Import from Community
  const handleImportCommunity = useCallback(async () => {
    if (importing || !userId) return
    setImporting(true)
    try {
      const res = await fetch(`/api/users/${userId}/chat-skills/import-community`, { method: 'POST' })
      if (res.ok) {
        const data = await res.json()
        // Refresh skills list
        setSkillsFetched(false)
        showAlert(`Imported ${data.imported} skill${data.imported !== 1 ? 's' : ''}${data.skipped ? `, ${data.skipped} skipped (already exist)` : ''}`)
      }
    } catch { /* silent */ }
    setImporting(false)
  }, [userId, importing])

  // Upload .md file
  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !userId) return
    setUploading(true)
    const reader = new FileReader()
    reader.onload = async () => {
      const content = reader.result as string
      const name = file.name.replace(/\.md$/i, '').replace(/_/g, ' ')
      try {
        const res = await fetch(`/api/users/${userId}/chat-skills`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, content, category: 'general' }),
        })
        if (res.ok) {
          setSkillsFetched(false) // refresh
        }
      } catch { /* silent */ }
      setUploading(false)
    }
    reader.readAsText(file)
    e.target.value = '' // reset for re-upload
  }, [userId])

  // Select a skill: activate it, and remove the /skill... portion from input (keep surrounding text)
  const selectSkill = useCallback((skill: ChatSkillSummary) => {
    setShowAutocomplete(false)
    setShowSkillPicker(false)
    // If triggered from autocomplete mid-text, remove the /skill... token and keep the rest
    if (autocompleteMatch && !showSkillPicker) {
      const before = inputValue.slice(0, autocompleteMatch.start).trimEnd()
      const after = inputValue.slice(autocompleteMatch.end).trimStart()
      const remaining = [before, after].filter(Boolean).join(' ')
      setInputValue(remaining)
    } else {
      setInputValue('')
    }
    onSkillActivate(skill.id, skill.name)
    inputRef.current?.focus()
  }, [inputRef, setInputValue, onSkillActivate, autocompleteMatch, inputValue, showSkillPicker])

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as Node
      const insideDropdown = dropdownRef.current?.contains(target)
      const insidePicker = pickerRef.current?.contains(target)
      if (!insideDropdown && !insidePicker) {
        setShowSkillPicker(false)
        setShowAutocomplete(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Keyboard handler that intercepts arrow keys and enter for autocomplete
  const handleKeyDownInternal = useCallback((e: KeyboardEvent<HTMLTextAreaElement>) => {
    const isDropdownOpen = showAutocomplete || showSkillPicker
    const currentFlat = showSkillPicker ? flatAll : flatFiltered

    if (isDropdownOpen && currentFlat.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex((prev: number) => (prev + 1) % currentFlat.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex((prev: number) => (prev - 1 + currentFlat.length) % currentFlat.length)
        return
      }
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        selectSkill(currentFlat[selectedIndex])
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setShowAutocomplete(false)
        setShowSkillPicker(false)
        return
      }
      if (e.key === 'Tab') {
        e.preventDefault()
        selectSkill(currentFlat[selectedIndex])
        return
      }
    }

    // Not intercepted, pass through to parent
    parentHandleKeyDown(e)
  }, [showAutocomplete, showSkillPicker, flatFiltered, flatAll, selectedIndex, selectSkill, parentHandleKeyDown])

  // Scroll selected item into view
  useEffect(() => {
    const container = dropdownRef.current || pickerRef.current
    if (!container) return
    const activeEl = container.querySelector(`.${styles.skillDropdownItemActive}`)
    if (activeEl) {
      activeEl.scrollIntoView({ block: 'nearest' })
    }
  }, [selectedIndex])

  const renderDropdownContent = (grouped: GroupedSkill[], flat: ChatSkillSummary[], showActions: boolean) => {
    return (
      <>
        {/* Action buttons -- always visible at top */}
        {showActions && (
          <div className={styles.skillDropdownActions}>
            <button
              className={styles.skillDropdownActionBtn}
              onMouseDown={(e: React.MouseEvent) => {
                e.preventDefault()
                handleImportCommunity()
              }}
              disabled={importing}
            >
              <Download size={11} />
              {importing ? 'Importing...' : 'Import from Community'}
            </button>
            <button
              className={styles.skillDropdownActionBtn}
              onMouseDown={(e: React.MouseEvent) => {
                e.preventDefault()
                fileInputRef.current?.click()
              }}
              disabled={uploading}
            >
              <Upload size={11} />
              {uploading ? 'Uploading...' : 'Upload .md'}
            </button>
          </div>
        )}

        {flat.length === 0 ? (
          <div className={styles.skillDropdownEmpty}>
            {skills.length === 0
              ? 'No Chat Skills yet. Import from community or upload a .md file above.'
              : 'No matching skills'}
          </div>
        ) : (
          <>
            {(() => {
              let globalIdx = 0
              return grouped.map(group => (
                <div key={group.category}>
                  <div className={styles.skillCategoryLabel}>{group.category}</div>
                  {group.skills.map(skill => {
                    const idx = globalIdx++
                    return (
                      <div
                        key={skill.id}
                        className={`${styles.skillDropdownItem} ${idx === selectedIndex ? styles.skillDropdownItemActive : ''}`}
                        onMouseDown={(e: React.MouseEvent) => {
                          e.preventDefault()
                          selectSkill(skill)
                        }}
                        onMouseEnter={() => setSelectedIndex(idx)}
                      >
                        <span className={styles.skillItemName}>{skill.name}</span>
                        <span className={styles.skillCategoryBadge}>{skill.category}</span>
                      </div>
                    )
                  })}
                </div>
              ))
            })()}
            <div className={styles.skillDropdownHint}>
              <span><kbd>↑↓</kbd> navigate</span>
              <span><kbd>Enter</kbd> select</span>
              <span><kbd>Esc</kbd> close</span>
            </div>
          </>
        )}
      </>
    )
  }

  return (
    <div className={styles.inputContainer}>
      <div className={styles.inputWrapperOuter}>
        {/* Autocomplete dropdown (triggered by typing /s...) */}
        {/* Hidden file input for upload */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".md"
          style={{ display: 'none' }}
          onChange={handleFileUpload}
        />

        {showAutocomplete && !showSkillPicker && (
          <div className={styles.skillDropdown} ref={dropdownRef}>
            {renderDropdownContent(groupedFiltered, flatFiltered, skills.length === 0)}
          </div>
        )}

        {/* Skill picker dropdown (triggered by button click) */}
        {showSkillPicker && (
          <div className={styles.skillDropdown} ref={pickerRef}>
            {renderDropdownContent(groupedAll, flatAll, true)}
          </div>
        )}

        {activeSkill && (
          <div className={styles.activeSkillBadge}>
            <Zap size={11} />
            <span className={styles.activeSkillBadgeName}>{activeSkill.name}</span>
            <span className={styles.activeSkillBadgeCategory}>{activeSkill.category}</span>
            <button
              className={styles.activeSkillRemove}
              onClick={() => setActiveSkill(null)}
              aria-label="Remove active skill"
              title="Remove active skill"
              type="button"
            >
              <X size={10} />
            </button>
          </div>
        )}

        <div className={styles.inputWrapper}>
          <textarea
            ref={inputRef}
            className={styles.input}
            value={inputValue}
            onChange={handleInputChange}
            onKeyDown={handleKeyDownInternal}
            onMouseDown={(e) => {
              // Native resize grip sits in the bottom-right corner (~16px).
              // Flag the ref so keystroke auto-grow stops overriding the user's drag.
              const rect = e.currentTarget.getBoundingClientRect()
              if (e.clientX >= rect.right - 16 && e.clientY >= rect.bottom - 16) {
                userResizedRef.current = true
              }
            }}
            placeholder={
              !isConnected
                ? 'Connecting to agent...'
                : awaitingApproval
                ? 'Respond to the approval request above...'
                : awaitingQuestion
                ? 'Answer the question above...'
                : isStopped
                ? 'Agent stopped. Click resume to continue...'
                : isLoading
                ? 'Send guidance to the agent...'
                : 'Ask a question or type /skill...'
            }
            rows={2}
            disabled={awaitingApproval || awaitingQuestion || awaitingToolConfirmation || !isConnected || isStopped}
          />
          <div className={styles.inputActions}>
            <button
              className={styles.skillPickerButton}
              onClick={() => {
                setShowSkillPicker((prev: boolean) => !prev)
                setShowAutocomplete(false)
                setSelectedIndex(0)
              }}
              aria-label="Browse skills"
              title="Browse Chat Skills"
              type="button"
            >
              <Zap size={13} />
            </button>
            {(isLoading || isStopped || isStopping) && (
              <button
                className={`${styles.stopResumeButton} ${isStopped ? styles.resumeButton : styles.stopButton}`}
                onClick={isStopped ? handleResume : handleStop}
                disabled={isStopping}
                aria-label={isStopping ? 'Stopping...' : isStopped ? 'Resume agent' : 'Stop agent'}
                title={isStopping ? 'Stopping...' : isStopped ? 'Resume execution' : 'Stop execution'}
              >
                {isStopping ? <Loader2 size={13} className={styles.spinner} /> : isStopped ? <Play size={13} /> : <Square size={13} />}
              </button>
            )}
            <button
              className={styles.sendButton}
              onClick={handleSend}
              disabled={!inputValue.trim() || awaitingApproval || awaitingQuestion || awaitingToolConfirmation || !isConnected || isStopped}
              aria-label="Send message"
            >
              <Send size={13} />
            </button>
          </div>
        </div>
      </div>
      <span className={styles.inputHint}>
        {isConnected
          ? isLoading
            ? 'Send guidance or stop the agent'
            : 'Press Enter to send, Shift+Enter for new line'
          : 'Waiting for connection...'}
      </span>
    </div>
  )
}
