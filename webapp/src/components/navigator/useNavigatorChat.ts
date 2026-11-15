/**
 * One AI Navigator conversation in the browser: load it, send a message, read the SSE answer, stop.
 *
 * The answer is a stream, so a send checks the status and content type first: JSON is an error
 * answer (the feature model gate opens on model_required / model_unavailable and the send is retried
 * once), `text/event-stream` is the answer. Deltas are applied once per animation frame, not per
 * token. The server stays the source of truth: the history the agent sees is read from the database.
 */
'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { stripUnknownMarkers } from '@/lib/navigator/events'

export interface CitationView {
  id: string
  title: string
  heading: string
  url: string
  mirror_url: string
}

export interface TraceView {
  route: string
  tool: string
  status: 'start' | 'end' | 'error'
  summary: string
  detail?: string
}

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  status: 'complete' | 'stopped' | 'failed' | 'streaming'
  routes: string[]
  citations: CitationView[]
  trace: TraceView[]
  errorCode: string | null
  actedByAdmin?: boolean
}

export interface ChatError {
  code: string | null
  status?: number
  retryAfterSeconds?: number
  threadId?: string
}

interface SavedMessage {
  id: string
  role: string
  content: string
  status: string
  routes?: string[]
  citations?: unknown
  trace?: unknown
  errorCode?: string | null
  actedByAdmin?: boolean
}

function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : []
}

export function fromSaved(m: SavedMessage): ChatMessage {
  return {
    id: m.id,
    role: m.role === 'user' ? 'user' : 'assistant',
    content: m.content,
    status: (['complete', 'stopped', 'failed'].includes(m.status) ? m.status : 'complete') as ChatMessage['status'],
    routes: asArray<string>(m.routes),
    citations: asArray<CitationView>(m.citations),
    trace: asArray<TraceView>(m.trace),
    errorCode: m.errorCode ?? null,
    actedByAdmin: m.actedByAdmin === true,
  }
}

/** Splits an SSE buffer into complete events; answers the leftover. */
export function parseSse(buffer: string): { events: Array<{ type: string; data: unknown }>; rest: string } {
  const events: Array<{ type: string; data: unknown }> = []
  let rest = buffer
  let idx: number
  while ((idx = rest.indexOf('\n\n')) >= 0) {
    const block = rest.slice(0, idx)
    rest = rest.slice(idx + 2)
    let type = 'message'
    const data: string[] = []
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) type = line.slice(6).trim()
      else if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
    }
    if (!data.length) continue
    try {
      events.push({ type, data: JSON.parse(data.join('\n')) })
    } catch {
      // a malformed block is skipped; the server validated what it sent
    }
  }
  return { events, rest }
}

const api = (projectId: string) => `/api/navigator/projects/${encodeURIComponent(projectId)}`

export interface UseNavigatorChat {
  threadId: string | null
  messages: ChatMessage[]
  streaming: boolean
  loading: boolean
  error: ChatError | null
  handoff: boolean
  send: (text: string) => Promise<void>
  stop: () => void
  open: (threadId: string | null) => Promise<void>
  clearError: () => void
}

export function useNavigatorChat(projectId: string | null, opts: {
  pagePath?: string
  onThreadCreated?: (threadId: string) => void
  onAnswerDone?: () => void
  onModelNoTools?: () => void
} = {}): UseNavigatorChat {
  const { fetchWithFeatureModel } = useFeatureModelGate()
  const [threadId, setThreadId] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [streaming, setStreaming] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ChatError | null>(null)
  const [handoff, setHandoff] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const threadRef = useRef<string | null>(null)
  const optsRef = useRef(opts)
  optsRef.current = opts

  const stop = useCallback(() => {
    const tid = threadRef.current
    abortRef.current?.abort()
    abortRef.current = null
    if (projectId && tid) {
      void fetch(`${api(projectId)}/threads/${encodeURIComponent(tid)}/stop`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      }).catch(() => undefined)
    }
  }, [projectId])

  // A project switch ends the answer in flight (§9.7) and clears the conversation.
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
      abortRef.current = null
    }
  }, [projectId])

  const open = useCallback(async (tid: string | null) => {
    abortRef.current?.abort()
    abortRef.current = null
    setStreaming(false)
    setError(null)
    setHandoff(false)
    threadRef.current = tid
    setThreadId(tid)
    if (!tid || !projectId) {
      setMessages([])
      return
    }
    setLoading(true)
    try {
      const res = await fetch(`${api(projectId)}/threads/${encodeURIComponent(tid)}`, { cache: 'no-store' })
      const body = await res.json().catch(() => null) as { messages?: SavedMessage[]; code?: string } | null
      if (!res.ok || !body) {
        setError({ code: body?.code ?? null, status: res.status })
        setMessages([])
        return
      }
      if (threadRef.current === tid) setMessages(asArray<SavedMessage>(body.messages).map(fromSaved))
    } catch {
      setError({ code: 'agent_unreachable' })
    } finally {
      setLoading(false)
    }
  }, [projectId])

  const send = useCallback(async (text: string) => {
    if (!projectId || streaming) return
    const trimmed = text.trim()
    if (!trimmed) return
    setError(null)
    setHandoff(false)
    const tempUser: ChatMessage = {
      id: `local-user-${Date.now()}`, role: 'user', content: trimmed, status: 'complete', routes: [], citations: [], trace: [], errorCode: null,
    }
    const tempAnswer: ChatMessage = {
      id: `local-answer-${Date.now()}`, role: 'assistant', content: '', status: 'streaming', routes: [], citations: [], trace: [], errorCode: null,
    }
    setMessages((m) => [...m, tempUser, tempAnswer])
    setStreaming(true)
    const controller = new AbortController()
    abortRef.current = controller
    const sentThread = threadRef.current

    const patchAnswer = (fn: (a: ChatMessage) => ChatMessage) =>
      setMessages((list) => list.map((m) => (m.id === tempAnswer.id ? fn(m) : m)))

    let res: Response
    try {
      res = await fetchWithFeatureModel('navigator', () => fetch(`${api(projectId)}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threadId: sentThread, text: trimmed, pageContext: opts.pagePath ? { path: opts.pagePath } : undefined }),
        signal: controller.signal,
      }))
    } catch {
      setStreaming(false)
      setMessages((list) => list.filter((m) => m.id !== tempAnswer.id && m.id !== tempUser.id))
      if (!controller.signal.aborted) setError({ code: 'agent_unreachable' })
      return
    }

    const type = res.headers.get('content-type') ?? ''
    if (!res.ok || !type.includes('text/event-stream') || !res.body) {
      const body = await res.json().catch(() => null) as { code?: string; retryAfterSeconds?: number; threadId?: string } | null
      setStreaming(false)
      setMessages((list) => list.filter((m) => m.id !== tempAnswer.id && m.id !== tempUser.id))
      setError({ code: body?.code ?? null, status: res.status, retryAfterSeconds: body?.retryAfterSeconds, threadId: body?.threadId })
      // The message was saved before the agent failed: show the thread as the server has it.
      if (body?.threadId) {
        if (!sentThread) optsRef.current.onThreadCreated?.(body.threadId)
        threadRef.current = body.threadId
        setThreadId(body.threadId)
        void open(body.threadId).then(() => setError({ code: body?.code ?? null, status: res.status }))
      }
      return
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let pending = ''
    let frame: number | null = null
    const flush = () => {
      frame = null
      if (!pending) return
      const chunk = pending
      pending = ''
      patchAnswer((a) => ({ ...a, content: a.content + chunk }))
    }
    let finalStatus: ChatMessage['status'] = 'stopped'
    let finalCode: string | null = null
    try {
      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const parsed = parseSse(buffer)
        buffer = parsed.rest
        for (const ev of parsed.events) {
          const d = ev.data as Record<string, unknown>
          switch (ev.type) {
            case 'thread': {
              const tid = String(d.thread_id ?? '')
              if (tid) {
                if (!sentThread) optsRef.current.onThreadCreated?.(tid)
                threadRef.current = tid
                setThreadId(tid)
              }
              patchAnswer((a) => a)
              setMessages((list) => list.map((m) => (m.id === tempUser.id ? { ...m, id: String(d.user_message_id ?? m.id) } : m)))
              break
            }
            case 'route':
              patchAnswer((a) => ({ ...a, routes: asArray<string>(d.routes).filter((r) => r !== 'direct') }))
              break
            case 'refused_route':
              patchAnswer((a) => ({ ...a, trace: [...a.trace, { route: String(d.route), tool: 'refused_route', status: 'error', summary: String(d.reason_code) }] }))
              break
            case 'tool':
              patchAnswer((a) => {
                const entry: TraceView = {
                  route: String(d.route), tool: String(d.name), status: d.status as TraceView['status'], summary: String(d.summary),
                  ...(typeof d.detail === 'string' ? { detail: d.detail } : {}),
                }
                if (entry.status === 'start') return { ...a, trace: [...a.trace, entry] }
                const idx = a.trace.findIndex((t) => t.tool === entry.tool && t.status === 'start')
                const trace = [...a.trace]
                if (idx >= 0) trace[idx] = entry
                else trace.push(entry)
                return { ...a, trace }
              })
              break
            case 'delta':
              pending += typeof d.text === 'string' ? d.text : ''
              if (frame === null) frame = requestAnimationFrame(flush)
              break
            case 'citations':
              patchAnswer((a) => ({ ...a, citations: asArray<CitationView>(d.items) }))
              break
            case 'handoff':
              setHandoff(true)
              patchAnswer((a) => ({ ...a, trace: [...a.trace, { route: 'direct', tool: 'handoff', status: 'end', summary: 'Offered the AI Agent' }] }))
              break
            case 'done':
              finalStatus = 'complete'
              break
            case 'error':
              finalCode = typeof d.code === 'string' ? d.code : 'navigator_error'
              finalStatus = finalCode === 'stopped' || finalCode === 'answer_too_long' ? 'stopped' : 'failed'
              break
          }
        }
      }
    } catch {
      // aborted (Stop, a project switch) or the connection dropped
    } finally {
      if (frame !== null) cancelAnimationFrame(frame)
      flush()
      abortRef.current = null
      setStreaming(false)
      // The saved row drops a marker no section backs (stream.ts); the live view does the same.
      patchAnswer((a) => ({
        ...a,
        content: stripUnknownMarkers(a.content, a.citations),
        status: finalStatus,
        errorCode: finalCode,
        trace: a.trace.filter((t) => t.status !== 'start'),
      }))
      if (finalCode === 'model_no_tools') optsRef.current.onModelNoTools?.()
      if (finalCode && finalStatus === 'failed') setError({ code: finalCode })
      optsRef.current.onAnswerDone?.()
    }
  }, [projectId, streaming, fetchWithFeatureModel, opts.pagePath, open])

  return { threadId, messages, streaming, loading, error, handoff, send, stop, open, clearError: () => setError(null) }
}
