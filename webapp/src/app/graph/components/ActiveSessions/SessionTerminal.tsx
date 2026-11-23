'use client'

import { useState, useRef, useEffect, useCallback, memo } from 'react'
import { Send, Terminal, AlertTriangle, Sparkles, Loader2 } from 'lucide-react'
import type { SessionInteractResult } from '@/lib/websocket-types'
import { FeatureModelLine, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'
import { toApiError } from '@/lib/apiError'
import styles from './SessionTerminal.module.css'

/**
 * The whisperer's failure line, with the provider's class and HTTP status when
 * the agent sent them (it never sends the provider's text): "The model call
 * failed. (RateLimitError · provider HTTP 429)". A body that is not JSON says
 * its HTTP status.
 */
export function whispererErrorText(status: number, data: unknown): string {
  const body = data && typeof data === 'object' ? data as Record<string, unknown> : null
  const code = readFeatureModelCode(body)
  const text = code
    ? featureModelMessage(code, typeof body?.model === 'string' ? body.model : undefined)
    : (typeof body?.error === 'string' && body.error.trim()) || `Error ${status}`
  const cls = body?.error_class ?? body?.errorClass
  const provider = body?.provider_status ?? body?.providerStatus
  const parts: string[] = []
  if (typeof cls === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(cls)) parts.push(cls)
  if (typeof provider === 'number' && Number.isInteger(provider) && provider >= 100 && provider <= 599) {
    parts.push(`provider HTTP ${provider}`)
  }
  return parts.length ? `${text} (${parts.join(' · ')})` : text
}

/** A contended command's answer came back cut short (`still_running`): the session manager answers before the agent gives up. */
const STILL_RUNNING_TEXT = 'The command is still running in the session; its remaining output will not be shown'

interface TerminalLine {
  text: string
  type: 'command' | 'output' | 'error' | 'system'
}

interface SessionTerminalProps {
  sessionId: number | null
  /** Which row is open, (sandbox, number): two sandboxes' session 1 are two terminals. Defaults to the number. */
  sessionKey?: string | null
  sessionType: 'meterpreter' | 'shell' | string
  agentBusy: boolean
  /** Whose sandbox and project the session is, shown to a holder of every session only. */
  owner?: string | null
  projectId: string
  onInteract: (sessionId: number, command: string) => Promise<SessionInteractResult>
  /** A complete list no longer holds this session: the output stays, no more commands. */
  ended?: boolean
  /** Its kill is pending: no more commands until it is killed or comes back. */
  killing?: boolean
}

export const SessionTerminal = memo(function SessionTerminal({
  sessionId,
  sessionKey,
  sessionType,
  agentBusy,
  owner = null,
  projectId,
  onInteract,
  ended = false,
  killing = false,
}: SessionTerminalProps) {
  const [lines, setLines] = useState<TerminalLine[]>([])
  const [input, setInput] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [commandHistory, setCommandHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [nlpInput, setNlpInput] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [nlpError, setNlpError] = useState<string | null>(null)
  const outputRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const nlpInputRef = useRef<HTMLInputElement>(null)
  const prevSessionRef = useRef<string | number | null>(null)
  const { ensureFeatureModel, fetchWithFeatureModel } = useFeatureModelGate()
  const openRow = sessionKey ?? sessionId
  const closed = ended || killing

  // Clear terminal when session changes
  useEffect(() => {
    if (openRow !== prevSessionRef.current) {
      setLines([])
      setInput('')
      setHistoryIndex(-1)
      setNlpInput('')
      setNlpError(null)
      prevSessionRef.current = openRow
    }
  }, [openRow])

  // Auto-scroll to bottom on new output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [lines])

  // Focus input when terminal is shown
  useEffect(() => {
    if (sessionId !== null) {
      inputRef.current?.focus()
    }
  }, [sessionId, openRow])

  const handleSend = useCallback(async () => {
    if (!input.trim() || !sessionId || isSending || closed) return

    const command = input.trim()
    setInput('')
    setIsSending(true)
    setHistoryIndex(-1)

    // Add to history
    setCommandHistory(prev => {
      const filtered = prev.filter(c => c !== command)
      return [command, ...filtered].slice(0, 50)
    })

    // Show command in terminal
    setLines(prev => [...prev, { text: `$ ${command}`, type: 'command' }])

    const result = await onInteract(sessionId, command)

    if (result.busy) {
      setLines(prev => [...prev, { text: result.message || 'Agent is busy, try again shortly', type: 'error' }])
    } else {
      if (result.output) setLines(prev => [...prev, { text: result.output!, type: 'output' }])
      if ((result as { still_running?: unknown }).still_running === true) {
        setLines(prev => [...prev, { text: STILL_RUNNING_TEXT, type: 'system' }])
      }
    }

    setIsSending(false)
    inputRef.current?.focus()
  }, [input, sessionId, isSending, closed, onInteract])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleSend()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (commandHistory.length > 0) {
        const newIdx = Math.min(historyIndex + 1, commandHistory.length - 1)
        setHistoryIndex(newIdx)
        setInput(commandHistory[newIdx])
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex > 0) {
        const newIdx = historyIndex - 1
        setHistoryIndex(newIdx)
        setInput(commandHistory[newIdx])
      } else {
        setHistoryIndex(-1)
        setInput('')
      }
    }
  }, [handleSend, commandHistory, historyIndex])

  // Command Whisperer - NLP to command translation
  const handleNlpSubmit = useCallback(async () => {
    if (!nlpInput.trim() || isGenerating) return

    setNlpError(null)
    // The route runs the user's own "Command whisperer" model; this only makes
    // sure one is saved before the request.
    if (!(await ensureFeatureModel('command_whisperer'))) return
    setIsGenerating(true)

    try {
      const resp = await fetchWithFeatureModel('command_whisperer', () => fetch('/api/agent/command-whisperer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: nlpInput.trim(),
          session_type: sessionType,
          project_id: projectId,
        }),
      }))

      if (!resp.ok) {
        setNlpError(whispererErrorText(resp.status, await resp.json().catch(() => null)))
        return
      }

      const data = await resp.json()
      if (data.command) {
        setInput(data.command)
        setNlpInput('')
        inputRef.current?.focus()
      }
    } catch (err) {
      setNlpError(toApiError(err, 'The command whisperer could not be reached').message)
    } finally {
      setIsGenerating(false)
    }
  }, [nlpInput, isGenerating, sessionType, projectId, ensureFeatureModel, fetchWithFeatureModel])

  const handleNlpKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleNlpSubmit()
    }
  }, [handleNlpSubmit])

  // Empty state - no session selected
  if (sessionId === null) {
    return (
      <div className={styles.emptyTerminal}>
        <Terminal size={32} />
        <p>Select a session to interact</p>
      </div>
    )
  }

  const promptSymbol = sessionType === 'meterpreter' ? 'meterpreter >' : '$'

  return (
    <div className={styles.terminal}>
      <div className={styles.terminalHeader}>
        <div className={styles.terminalTitle}>
          <span className={styles.dot} />
          Session #{sessionId} - {sessionType}
          {owner && <span className={styles.ownerLabel} data-testid="session-owner"> · {owner}</span>}
        </div>
      </div>

      {killing ? (
        <div className={styles.endedBanner} role="status">
          <Loader2 size={12} />
          Killing…
        </div>
      ) : ended && (
        <div className={styles.endedBanner} role="status">
          <Terminal size={12} />
          Session ended
        </div>
      )}

      {agentBusy && !closed && (
        <div className={styles.busyBanner}>
          <AlertTriangle size={12} />
          Agent is executing a command - interaction may be delayed
        </div>
      )}

      <div ref={outputRef} className={styles.outputArea}>
        {lines.map((line, i) => (
          <pre
            key={i}
            className={`${styles.outputLine} ${
              line.type === 'command' ? styles.commandLine :
              line.type === 'error' ? styles.errorLine : ''
            }`}
          >
            {line.text}
          </pre>
        ))}
        {isSending && (
          <pre className={`${styles.outputLine} ${styles.sending}`}>
            Executing...
          </pre>
        )}
      </div>

      {/* Command Whisperer - NLP input */}
      <div className={styles.nlpArea}>
        <Sparkles size={13} className={styles.nlpIcon} />
        <input
          ref={nlpInputRef}
          className={styles.nlpInput}
          value={nlpInput}
          onChange={e => { setNlpInput(e.target.value); setNlpError(null) }}
          onKeyDown={handleNlpKeyDown}
          placeholder="Describe what you want to do..."
          disabled={isGenerating}
          autoComplete="off"
          spellCheck={false}
        />
        {isGenerating ? (
          <Loader2 size={13} className={styles.nlpSpinner} />
        ) : (
          <button
            className={styles.nlpBtn}
            onClick={handleNlpSubmit}
            disabled={!nlpInput.trim() || isGenerating}
            title="Generate command"
          >
            <Send size={11} />
          </button>
        )}
        {nlpError && <span className={styles.nlpError}>{nlpError}</span>}
        <div className={styles.nlpModel}>
          <FeatureModelLine featureId="command_whisperer" />
        </div>
      </div>

      <div className={styles.inputArea}>
        <span className={styles.prompt}>{promptSymbol}</span>
        <input
          ref={inputRef}
          className={styles.input}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type a command..."
          disabled={isSending || closed}
          autoComplete="off"
          spellCheck={false}
        />
        <button
          className={styles.sendBtn}
          onClick={handleSend}
          disabled={!input.trim() || isSending || closed}
          title="Send command"
        >
          <Send size={13} />
        </button>
      </div>
    </div>
  )
})
