/**
 * The instance tunnel group (Global Settings → Tunneling with the identity switch on, and the
 * admin console's Instance page): unused since every person runs their own tunnel from their own
 * Kali sandbox (group 1, OQ-G1-2 A). Whoever holds platform:tunnels sees a notice saying so, with
 * no controls and no Save, whatever the switches; anyone else sees the tunnel status.
 *
 * Run: npx vitest run --no-file-parallelism src/components/settings/InstanceTunnelSection.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { ToastProvider } from '@/components/ui/Toast/Toast'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))

import { InstanceTunnelSection } from './InstanceTunnelSection'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
let canManageTunnels = true
let tunnelsPerPerson: boolean | undefined
beforeEach(() => {
  canManageTunnels = true
  tunnelsPerPerson = true
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/admin/instance-settings') {
      return new Response(JSON.stringify({ tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', canManageTunnels, tunnelsPerPerson }))
    }
    return new Response(JSON.stringify({ ngrok: { active: true } }))
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderSection(flags: typeof FLAGS_ON | null) {
  return render(
    <AuthContext.Provider value={fakeAuth(flags, ['platform:tunnels'])}>
      <ToastProvider><InstanceTunnelSection /></ToastProvider>
    </AuthContext.Provider>,
  )
}

describe('the instance tunnel is unused: tunnels are per person (group 1, OQ-G1-2 A)', () => {
  test.each([['governance on', FLAGS_GOV], ['permissions on', FLAGS_ON], ['every switch null', null]] as const)(
    'a tunnels holder sees the notice, never the controls (%s)', async (_name, flags) => {
      renderSection(flags)
      expect(await screen.findByText(/Tunnels are per person/)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Save tunnel settings' })).toBeNull()
      expect(screen.queryByLabelText('Chisel Server URL')).toBeNull()
      expect(screen.queryByText(/shared by the whole instance/)).toBeNull()
    },
  )

  test('an older answer without the per-person mark is read the same way: no controls', async () => {
    tunnelsPerPerson = undefined
    renderSection(FLAGS_GOV)
    expect(await screen.findByText(/Tunnels are per person/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save tunnel settings' })).toBeNull()
  })

  test('a person who may not change it keeps the read-only status', async () => {
    canManageTunnels = false
    renderSection(FLAGS_GOV)
    expect(await screen.findByText('On (ngrok)')).toBeInTheDocument()
    expect(screen.queryByText(/Tunnels are per person/)).toBeNull()
  })
})
