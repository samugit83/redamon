/**
 * The toolbar's tunnel badge (round 2): "Tunnel active" only once a tunnel forwards, as its `status`
 * says (mcp/servers/tunnel_manager.py: "on", "connecting", "error: <reason>", "off"). A tunnel whose
 * process merely runs (`active`) while it connects or failed is shown as connecting or failed, with
 * the reason; an answer from a sandbox image older than `status` is read by `active`, as before.
 *
 * Run: npx vitest run src/app/graph/components/GraphToolbar/GraphToolbar.tunnel.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { GraphToolbar } from './GraphToolbar'

afterEach(cleanup)

const base = {
  projectId: 'p1', is3D: false, showLabels: true, onToggle3D: () => {}, onToggleLabels: () => {},
  onStartRecon: () => {}, hasReconData: true,
}
const badge = (provider: string) => screen.queryByTestId(`tunnel-badge-${provider}`)

describe('the tunnel badge follows status, never the process alone', () => {
  test('"on": the active badge with its public endpoint', () => {
    render(<GraphToolbar {...base} tunnelStatus={{ ngrok: { active: true, status: 'on', host: '0.tcp.ngrok.example', port: 12345 }, chisel: { active: false, status: 'off' } }} />)
    expect(badge('ngrok')).toHaveTextContent(/^ngrok$/)
    expect(badge('ngrok')).toHaveAttribute('title', 'Tunnel active: 0.tcp.ngrok.example:12345')
    expect(badge('chisel')).toBeNull()
  })

  test('"connecting": the process runs, but no badge says active', () => {
    render(<GraphToolbar {...base} tunnelStatus={{ ngrok: { active: false, status: 'off' }, chisel: { active: true, status: 'connecting' } }} />)
    expect(badge('chisel')).toHaveTextContent('chisel (connecting)')
    expect(badge('chisel')).toHaveAttribute('title', 'Tunnel connecting')
    expect(document.body.innerHTML).not.toContain('Tunnel active')
  })

  test('"error: <reason>": failed, with the reason', () => {
    render(<GraphToolbar {...base} tunnelStatus={{ ngrok: { active: false, status: 'off' }, chisel: { active: true, status: 'error: server port 4444 already in use' } }} />)
    expect(badge('chisel')).toHaveTextContent('chisel (failed)')
    expect(badge('chisel')).toHaveAttribute('title', 'Tunnel failed: server port 4444 already in use')
    expect(document.body.innerHTML).not.toContain('Tunnel active')
  })

  test('"off", or no answer: no badge', () => {
    render(<GraphToolbar {...base} tunnelStatus={{ ngrok: { active: false, status: 'off' }, chisel: { active: false, status: 'off' } }} />)
    expect(badge('ngrok')).toBeNull()
    expect(badge('chisel')).toBeNull()
    cleanup()
    render(<GraphToolbar {...base} />)
    expect(badge('ngrok')).toBeNull()
  })

  test('an answer without status (an older sandbox image): read by active, as before', () => {
    render(<GraphToolbar {...base} tunnelStatus={{ ngrok: { active: true, host: 'h.example', port: 1 }, chisel: { active: false } }} />)
    expect(badge('ngrok')).toHaveAttribute('title', 'Tunnel active: h.example:1')
    expect(badge('chisel')).toBeNull()
  })
})
