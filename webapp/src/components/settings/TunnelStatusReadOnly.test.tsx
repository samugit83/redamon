/**
 * The Tunneling section's status line (round 2): "On" only for a tunnel whose `status` is "on";
 * "Connecting" and "Failed: reason" otherwise. The "Turn my tunnel off" control keeps following
 * whether a tunnel process runs (`active`) or the setting reads on, so a stop can always be sent to a
 * tunnel that connects or fails. An answer without `status` (an older sandbox image) is read by
 * `active`, as before.
 *
 * Run: npx vitest run --no-file-parallelism src/components/settings/TunnelStatusReadOnly.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { TunnelStatusReadOnly, tunnelStatusLine } from './TunnelStatusReadOnly'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function answering(body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })))
}
const offButton = () => screen.queryByRole('button', { name: 'Turn my tunnel off' })

describe('the status line follows status', () => {
  test('"on": On, with the off control', async () => {
    answering({ ngrok: { active: true, status: 'on', host: 'h', port: 1 }, chisel: { active: false, status: 'off' } })
    render(<TunnelStatusReadOnly perPerson onTurnOff={() => {}} />)
    expect(await screen.findByText('On (ngrok)')).toBeInTheDocument()
    expect(offButton()).not.toBeNull()
  })

  test('"connecting": never On, and the off control still shows (the process runs)', async () => {
    answering({ ngrok: { active: false, status: 'off' }, chisel: { active: true, status: 'connecting' } })
    render(<TunnelStatusReadOnly perPerson onTurnOff={() => {}} />)
    expect(await screen.findByText('Connecting (chisel)')).toBeInTheDocument()
    expect(screen.queryByText(/^On/)).toBeNull()
    expect(offButton()).not.toBeNull()
  })

  test('"error: <reason>": failed with the reason; the off control follows active', async () => {
    answering({ ngrok: { active: true, status: 'error: authentication failed' }, chisel: { active: false, status: 'off' } })
    render(<TunnelStatusReadOnly perPerson onTurnOff={() => {}} />)
    expect(await screen.findByText('Failed (ngrok): authentication failed')).toBeInTheDocument()
    expect(offButton()).not.toBeNull()
  })

  // tunnel_manager.py `_chisel_status`: a chisel client that exited on its error keeps the reason.
  test('a failed tunnel whose process exited, the setting off: Failed, and nothing to turn off', async () => {
    answering({ ngrok: { active: false, status: 'off' }, chisel: { active: false, status: 'error: connection refused' } })
    render(<TunnelStatusReadOnly perPerson onTurnOff={() => {}} />)
    expect(await screen.findByText('Failed (chisel): connection refused')).toBeInTheDocument()
    expect(offButton()).toBeNull()
  })

  test('both off: Off', async () => {
    answering({ ngrok: { active: false, status: 'off' }, chisel: { active: false, status: 'off' } })
    render(<TunnelStatusReadOnly perPerson onTurnOff={() => {}} />)
    expect(await screen.findByText('Off')).toBeInTheDocument()
  })

  test('an answer without status (an older sandbox image): active reads as On, as before', async () => {
    answering({ ngrok: { active: true }, chisel: { active: false } })
    render(<TunnelStatusReadOnly perPerson />)
    expect(await screen.findByText('On (ngrok)')).toBeInTheDocument()
  })

  test('several tunnels: each in its own words', () => {
    expect(tunnelStatusLine([
      { provider: 'ngrok', display: { state: 'on' } },
      { provider: 'chisel', display: { state: 'error', reason: 'x' } },
    ])).toBe('On (ngrok); Failed (chisel): x')
    expect(tunnelStatusLine([])).toBe('Off')
  })
})
