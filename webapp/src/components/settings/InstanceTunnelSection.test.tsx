/**
 * Global Settings' Tunneling section once the tunnel moves to the admin console (step 6.7, UI-04):
 * with RBAC_GOVERNANCE_ENABLED on, whoever may change the tunnel is linked to the Instance page
 * instead of the controls, a person who may not keeps the read-only status, and the Instance page
 * itself (`placement="instance"`) keeps the controls. With the switch off nothing changes (the
 * editor as in step 2.4: app/settings/page.instanceTunnel.test.tsx; governance.flags.off.test.ts).
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

import { InstanceTunnelSection, INSTANCE_PAGE_TUNNELS } from './InstanceTunnelSection'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
let canManageTunnels = true
beforeEach(() => {
  canManageTunnels = true
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/admin/instance-settings') {
      return new Response(JSON.stringify({ tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', canManageTunnels }))
    }
    return new Response(JSON.stringify({ ngrok: { active: true } }))
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderSection(flags: typeof FLAGS_ON, placement?: 'settings' | 'instance') {
  return render(
    <AuthContext.Provider value={fakeAuth(flags, ['platform:tunnels'])}>
      <ToastProvider><InstanceTunnelSection placement={placement} /></ToastProvider>
    </AuthContext.Provider>,
  )
}

describe('the Tunneling tab with RBAC_GOVERNANCE_ENABLED on', () => {
  test('whoever may change the tunnel gets the link to the Instance page, not the controls', async () => {
    renderSection(FLAGS_GOV)
    const link = await screen.findByRole('link', { name: 'Open the tunnel settings' })
    expect(link).toHaveAttribute('href', INSTANCE_PAGE_TUNNELS)
    expect(INSTANCE_PAGE_TUNNELS).toBe('/admin/instance#tunnels')
    expect(screen.queryByLabelText('Chisel Server URL')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Save tunnel settings' })).toBeNull()
  })

  test('a person who may not change it keeps the read-only status', async () => {
    canManageTunnels = false
    renderSection(FLAGS_GOV)
    expect(await screen.findByText('On (ngrok)')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open the tunnel settings' })).toBeNull()
  })

  test('on the Instance page the controls stay', async () => {
    renderSection(FLAGS_GOV, 'instance')
    expect(await screen.findByRole('button', { name: 'Save tunnel settings' })).toBeInTheDocument()
    expect(screen.getByLabelText('Chisel Server URL')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open the tunnel settings' })).toBeNull()
  })
})

describe('with RBAC_GOVERNANCE_ENABLED off', () => {
  test.each([['permissions on', FLAGS_ON], ['every switch null (outside an AuthProvider value)', null]] as const)(
    'the Tunneling tab keeps the controls (%s)', async (_name, flags) => {
      render(
        <AuthContext.Provider value={fakeAuth(flags, [])}>
          <ToastProvider><InstanceTunnelSection /></ToastProvider>
        </AuthContext.Provider>,
      )
      expect(await screen.findByRole('button', { name: 'Save tunnel settings' })).toBeInTheDocument()
      expect(screen.queryByRole('link', { name: 'Open the tunnel settings' })).toBeNull()
    },
  )
})
