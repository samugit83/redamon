'use client'

import { useEffect, useRef, useState, useCallback, memo } from 'react'
import { Terminal as TerminalIcon, Wifi, WifiOff, RefreshCw, Maximize2, Minimize2 } from 'lucide-react'
import type { Terminal } from '@xterm/xterm'
import type { FitAddon } from '@xterm/addon-fit'
import { buildAgentWsUrl } from '@/hooks/agentWsUrl'
import { describeWsClose, wsUrlForDisplay } from '@/hooks/agentWsClose'
import { mintWsTicket, type WsTicketResult } from '@/lib/wsTicket'
import styles from './KaliTerminal.module.css'

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error'

const MAX_RECONNECT_ATTEMPTS = 5
const BASE_RECONNECT_INTERVAL = 2000
const PING_INTERVAL_MS = 30000

// STRIDE S3: the agent proxy requires a ws-ticket to open the PTY; buildAgentWsUrl
// appends it as a query param so the raw byte bridge is unchanged.
function getWsUrl(ticket?: string): string {
  return buildAgentWsUrl('/ws/kali-terminal', ticket)
}

/** Always on screen: the sandbox, its /workspace and its shell history are one for every project. */
export const SHARED_ENVIRONMENT_NOTICE = "Shared environment: other projects' files are visible here."

/**
 * The line for a ticket the terminal could not use: the mint's own refusal
 * (no terminal grant, expired session, no project access, a version activation
 * in progress), or no ticket at all, which here means the webapp has no ticket
 * secret: the terminal proxy fails closed without one.
 */
export function ticketFailureLine(minted: WsTicketResult): string | null {
  if (!minted.ok) {
    if (minted.error.status === 403) return `Terminal not available: ${minted.error.message}`
    return `Terminal authentication failed: ${minted.error.message}`
  }
  if (!minted.ticket) {
    return 'Terminal authentication failed: the webapp issued no ticket (AGENT_WS_TICKET_SECRET is not set). Run ./redamon.sh update, then restart the webapp and agent.'
  }
  return null
}

/** "Disconnected from kali-sandbox (close 1011: Kali sandbox terminal unavailable (ConnectionRefusedError))". */
export function disconnectLine(code: number, reason: string): string {
  return `Disconnected from kali-sandbox (${describeWsClose(code, reason)})`
}

export interface KaliTerminalProps {
  userId?: string | null
  projectId?: string | null
}

export const KaliTerminal = memo(function KaliTerminal({ userId, projectId }: KaliTerminalProps = {}) {
  const termRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const [status, setStatus] = useState<ConnectionStatus>('disconnected')
  const [isFullscreen, setIsFullscreen] = useState(false)
  const reconnectTimerRef = useRef<NodeJS.Timeout | null>(null)
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const inputDisposablesRef = useRef<Array<{ dispose: () => void }>>([])
  const mountedRef = useRef(true)
  const initializedRef = useRef(false)
  const reconnectAttemptRef = useRef(0)
  const tenantRef = useRef<{ userId?: string | null; projectId?: string | null }>({ userId, projectId })
  tenantRef.current = { userId, projectId }
  const firstTenantRunRef = useRef(true)
  // STRIDE S3: stable per-terminal session id for the ws-ticket `sid` claim.
  const sessionIdRef = useRef<string>(
    typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : `kali-${Date.now()}`
  )
  // S3: connect() awaits a ws-ticket fetch; this synchronous sentinel closes the
  // double-fire window the await opened (a concurrent connect would otherwise open
  // an orphan socket).
  const connectingRef = useRef(false)

  const connect = useCallback(async () => {
    if (!termRef.current || !mountedRef.current) return
    if (connectingRef.current) return
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) return
    connectingRef.current = true

    setStatus('connecting')

    // Dynamically import xterm to avoid SSR issues
    let TerminalCtor, FitAddonCtor, WebLinksAddonCtor
    try {
      const [termMod, fitMod, linksMod] = await Promise.all([
        import('@xterm/xterm'),
        import('@xterm/addon-fit'),
        import('@xterm/addon-web-links'),
      ])
      TerminalCtor = termMod.Terminal
      FitAddonCtor = fitMod.FitAddon
      WebLinksAddonCtor = linksMod.WebLinksAddon
    } catch {
      setStatus('error')
      return
    }

    if (!mountedRef.current) return

    // Only create terminal once
    if (!terminalRef.current) {
      const fitAddon = new FitAddonCtor()
      fitAddonRef.current = fitAddon

      const terminal = new TerminalCtor({
        cursorBlink: true,
        cursorStyle: 'block',
        fontSize: 13,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Menlo', monospace",
        lineHeight: 1.3,
        letterSpacing: 0.5,
        theme: {
          background: '#0a0e14',
          foreground: '#e6e1cf',
          cursor: '#ff3333',
          cursorAccent: '#0a0e14',
          selectionBackground: '#33415580',
          selectionForeground: '#e6e1cf',
          black: '#1a1e29',
          red: '#ff3333',
          green: '#bae67e',
          yellow: '#ffd580',
          blue: '#73d0ff',
          magenta: '#d4bfff',
          cyan: '#95e6cb',
          white: '#e6e1cf',
          brightBlack: '#4d556a',
          brightRed: '#ff6666',
          brightGreen: '#91d076',
          brightYellow: '#ffe6b3',
          brightBlue: '#5ccfe6',
          brightMagenta: '#c3a6ff',
          brightCyan: '#a6f0db',
          brightWhite: '#fafafa',
        },
        scrollback: 10000,
        allowProposedApi: true,
      })

      terminal.loadAddon(fitAddon)
      terminal.loadAddon(new WebLinksAddonCtor())

      if (termRef.current) {
        terminal.open(termRef.current)
        fitAddon.fit()
      }

      terminalRef.current = terminal
    } else {
      terminalRef.current.clear()
    }

    const terminal = terminalRef.current!
    const fitAddon = fitAddonRef.current

    terminal.writeln('')
    terminal.writeln('\x1b[1;31m  ____          _    _                       \x1b[0m')
    terminal.writeln('\x1b[1;31m |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __\x1b[0m')
    terminal.writeln('\x1b[1;31m | |_) / _ \\/ _` | / _ \\ | \'_ ` _ \\ / _ \\| \'_ \\\x1b[0m')
    terminal.writeln('\x1b[1;31m |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |\x1b[0m')
    terminal.writeln('\x1b[1;31m |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|\x1b[0m')
    terminal.writeln('')
    terminal.writeln('\x1b[1;36m  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\x1b[0m')
    terminal.writeln('\x1b[1;36m  \u2502\x1b[0m  \x1b[1;33m\u26a1 Kali Sandbox Terminal\x1b[0m                     \x1b[1;36m\u2502\x1b[0m')
    terminal.writeln('\x1b[1;36m  \u2502\x1b[0m  \x1b[2;37mFull access to Kali Linux pentesting tools\x1b[0m  \x1b[1;36m\u2502\x1b[0m')
    terminal.writeln('\x1b[1;36m  \u2502\x1b[0m  \x1b[2;37mmetasploit \u2022 nmap \u2022 nuclei \u2022 hydra \u2022 sqlmap\x1b[0m \x1b[1;36m\u2502\x1b[0m')
    terminal.writeln('\x1b[1;36m  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\x1b[0m')
    terminal.writeln('')
    terminal.writeln('\x1b[2;37m  Connecting to kali-sandbox...\x1b[0m')

    // STRIDE S3: mint a ws-ticket (bound to the effective user + project) before
    // dialing. Without a valid ticket the agent proxy now closes the socket.
    const pid = tenantRef.current.projectId
    if (!pid) {
      connectingRef.current = false
      setStatus('error')
      terminal.writeln('\x1b[1;31m✗ No project selected - open a project to use the terminal\x1b[0m')
      return
    }
    const minted = await mintWsTicket(String(pid), sessionIdRef.current, 'kali-terminal')
    if (!minted.ok || !minted.ticket) {
      connectingRef.current = false
      setStatus('error')
      terminal.writeln(`\x1b[1;31m✗ ${ticketFailureLine(minted)}\x1b[0m`)
      return
    }
    if (!mountedRef.current) { connectingRef.current = false; return }

    const url = getWsUrl(minted.ticket)
    const ws = new WebSocket(url)
    wsRef.current = ws
    connectingRef.current = false

    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      if (!mountedRef.current) {
        ws.close()
        return
      }
      setStatus('connected')
      reconnectAttemptRef.current = 0
      terminal.writeln('\x1b[1;32m\u2713 Connected\x1b[0m\n')

      // The terminal server reads the first frame before it forks the shell and
      // replays anything but an init into it, so the init goes first. It carries
      // no ids: the shell's user and project are the ones the agent proxy took
      // from the verified ticket.
      ws.send(JSON.stringify({ type: 'init' }))

      // Send terminal size
      if (fitAddon) {
        const dims = fitAddon.proposeDimensions()
        if (dims) {
          ws.send(JSON.stringify({ type: 'resize', rows: dims.rows, cols: dims.cols }))
        }
      }

      // Dispose previous input handlers before registering new ones
      inputDisposablesRef.current.forEach(d => d.dispose())
      inputDisposablesRef.current = []

      inputDisposablesRef.current.push(
        terminal.onData((data: string) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(data)
          }
        })
      )

      inputDisposablesRef.current.push(
        terminal.onBinary((data: string) => {
          if (ws.readyState === WebSocket.OPEN) {
            const bytes = new Uint8Array(data.length)
            for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i)
            ws.send(bytes.buffer)
          }
        })
      )

      // Start keepalive ping
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }))
        }
      }, PING_INTERVAL_MS)
    }

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data))
      } else {
        terminal.write(event.data)
      }
    }

    ws.onerror = () => {
      if (!mountedRef.current) return
      setStatus('error')
      terminal.writeln(`\n\x1b[1;31mWebSocket connection to ${wsUrlForDisplay(url)} failed. Is the kali-sandbox running?\x1b[0m`)
    }

    ws.onclose = (event: CloseEvent) => {
      if (!mountedRef.current) return

      // Clear keepalive
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current)
        pingIntervalRef.current = null
      }

      setStatus('disconnected')
      terminal.writeln(`\n\x1b[1;31m\u2717 ${disconnectLine(event.code, event.reason)}\x1b[0m`)

      // Auto-reconnect with exponential backoff
      const attempt = reconnectAttemptRef.current
      if (attempt < MAX_RECONNECT_ATTEMPTS) {
        const delay = BASE_RECONNECT_INTERVAL * Math.pow(2, attempt)
        terminal.writeln(`\x1b[2;37m  Reconnecting in ${(delay / 1000).toFixed(0)}s (attempt ${attempt + 1}/${MAX_RECONNECT_ATTEMPTS})...\x1b[0m`)
        reconnectAttemptRef.current = attempt + 1
        reconnectTimerRef.current = setTimeout(() => connect(), delay)
      } else {
        terminal.writeln('\x1b[2;37m  Max reconnect attempts reached. Click "Reconnect" to try again.\x1b[0m')
      }
    }
  }, [])

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setStatus('disconnected')
  }, [])

  const reconnect = useCallback(() => {
    reconnectAttemptRef.current = 0
    disconnect()
    reconnectTimerRef.current = setTimeout(() => connect(), 200)
  }, [disconnect, connect])

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(prev => !prev)
  }, [])

  // Auto-connect on mount
  useEffect(() => {
    mountedRef.current = true
    if (!initializedRef.current) {
      initializedRef.current = true
      connect()
    }
    return () => {
      mountedRef.current = false
    }
  }, [connect])

  // Reconnect when the active project/user changes so the sandbox shell
  // restarts with fresh REDAMON_USER_ID / REDAMON_PROJECT_ID env vars.
  // The first run is suppressed: the mount-effect above already calls connect()
  // - letting this fire on initial mount would race into disconnect+reconnect,
  // doubling banners and dropping MOTD output from the killed first shell.
  useEffect(() => {
    if (firstTenantRunRef.current) {
      firstTenantRunRef.current = false
      return
    }
    reconnectAttemptRef.current = 0
    disconnect()
    const t = setTimeout(() => connect(), 200)
    return () => clearTimeout(t)
  }, [userId, projectId, connect, disconnect])

  // Handle resize
  useEffect(() => {
    const handleResize = () => {
      if (fitAddonRef.current && terminalRef.current) {
        try {
          fitAddonRef.current.fit()
          const dims = fitAddonRef.current.proposeDimensions()
          if (dims && wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({
              type: 'resize',
              rows: dims.rows,
              cols: dims.cols,
            }))
          }
        } catch {
          // Ignore fit errors during transitions
        }
      }
    }

    const resizeObserver = new ResizeObserver(handleResize)
    if (termRef.current) {
      resizeObserver.observe(termRef.current)
    }
    window.addEventListener('resize', handleResize)

    return () => {
      resizeObserver.disconnect()
      window.removeEventListener('resize', handleResize)
    }
  }, [])

  // Refit when fullscreen toggles
  useEffect(() => {
    const timer = setTimeout(() => {
      if (fitAddonRef.current) {
        try {
          fitAddonRef.current.fit()
          const dims = fitAddonRef.current.proposeDimensions()
          if (dims && wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({
              type: 'resize',
              rows: dims.rows,
              cols: dims.cols,
            }))
          }
        } catch {
          // Ignore
        }
      }
    }, 100)
    return () => clearTimeout(timer)
  }, [isFullscreen])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      mountedRef.current = false
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current)
        pingIntervalRef.current = null
      }
      inputDisposablesRef.current.forEach(d => d.dispose())
      inputDisposablesRef.current = []
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      if (terminalRef.current) {
        terminalRef.current.dispose()
        terminalRef.current = null
      }
    }
  }, [])

  return (
    <div className={`${styles.container} ${isFullscreen ? styles.fullscreen : ''}`}>
      <div className={styles.toolbar}>
        <div className={styles.toolbarLeft}>
          <TerminalIcon size={14} className={styles.terminalIcon} />
          <span className={styles.title}>RedAmon Terminal</span>
          <span className={styles.subtitle}>kali-sandbox</span>
        </div>
        <div className={styles.toolbarRight}>
          <span className={`${styles.statusBadge} ${styles[status]}`} aria-live="polite">
            {status === 'connected' ? (
              <Wifi size={10} />
            ) : (
              <WifiOff size={10} />
            )}
            <span>{status}</span>
          </span>
          <button
            className={styles.toolbarBtn}
            onClick={reconnect}
            title="Reconnect"
            disabled={status === 'connecting'}
            aria-label="Reconnect to terminal"
          >
            <RefreshCw size={12} />
          </button>
          <button
            className={styles.toolbarBtn}
            onClick={toggleFullscreen}
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
            aria-label={isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'}
            aria-pressed={isFullscreen}
          >
            {isFullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>
      </div>
      <div className={styles.sharedNotice} role="note">{SHARED_ENVIRONMENT_NOTICE}</div>
      <div ref={termRef} className={styles.terminal} role="application" aria-label="Kali Linux terminal" />
    </div>
  )
})
