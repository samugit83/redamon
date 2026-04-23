'use client'

import { useEffect, useRef, useState, useCallback, memo } from 'react'
import { Terminal as TerminalIcon, Wifi, WifiOff, RefreshCw, Maximize2, Minimize2 } from 'lucide-react'
import type { Terminal } from '@xterm/xterm'
import type { FitAddon } from '@xterm/addon-fit'
import styles from './KaliTerminal.module.css'

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error'

const MAX_RECONNECT_ATTEMPTS = 5
const BASE_RECONNECT_INTERVAL = 2000
const PING_INTERVAL_MS = 30000

function getWsUrl(): string {
  if (process.env.NEXT_PUBLIC_AGENT_WS_URL) {
    return process.env.NEXT_PUBLIC_AGENT_WS_URL.replace(/\/ws\/agent$/, '/ws/kali-terminal')
  }
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.hostname
    return `${protocol}//${host}:8090/ws/kali-terminal`
  }
  return 'ws://localhost:8090/ws/kali-terminal'
}

export const KaliTerminal = memo(function KaliTerminal() {
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

  const connect = useCallback(async () => {
    if (!termRef.current || !mountedRef.current) return
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) return

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

    const url = getWsUrl()
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      if (!mountedRef.current) {
        ws.close()
        return
      }
      setStatus('connected')
      reconnectAttemptRef.current = 0
      terminal.writeln('\x1b[1;32m\u2713 Connected\x1b[0m\n')

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
      terminal.writeln('\n\x1b[1;31mWebSocket connection failed. Is the kali-sandbox running?\x1b[0m')
    }

    ws.onclose = () => {
      if (!mountedRef.current) return

      // Clear keepalive
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current)
        pingIntervalRef.current = null
      }

      setStatus('disconnected')
      terminal.writeln('\n\x1b[1;31m\u2717 Disconnected from kali-sandbox\x1b[0m')

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
      <div ref={termRef} className={styles.terminal} role="application" aria-label="Kali Linux terminal" />
    </div>
  )
})
