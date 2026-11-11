/**
 * The Insights header names an IP-mode project's "Hostnames on target IPs"
 * mode next to the IP-mode icon (04_ui_spec §5): the dashboards count names
 * only in a recording or scanning mode, so the header says which one applies.
 *
 * Run: npx vitest run src/app/insights/components/DashboardHeader.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

const ctx = vi.hoisted(() => ({ current: null as null | { currentProject: Record<string, unknown> | null } }))
vi.mock('@/providers/ProjectProvider', () => ({ useOptionalProject: () => ctx.current }))

import { DashboardHeader } from './DashboardHeader'

afterEach(() => { cleanup(); ctx.current = null })

function header(props: Partial<React.ComponentProps<typeof DashboardHeader>> = {}) {
  render(<DashboardHeader projectName="Lab" targetDomain="2 IP targets" ipMode isLoading={false}
                          onRefresh={() => {}} {...props} />)
  return screen.queryByTestId('insights-hostname-mode')
}

describe('the hostname mode next to the IP-mode icon', () => {
  test('a passed mode reads as its card label, with the setting named for screen readers', () => {
    const chip = header({ ipHostnameMode: 'record_filter' })!
    expect(chip).toHaveTextContent('Hostnames on target IPs: Record + scan matching')
    expect(chip.title).toBe('Hostnames on target IPs')
  })

  test('without the prop it reads the current project', () => {
    ctx.current = { currentProject: { ipHostnameMode: 'record_only' } }
    expect(header()).toHaveTextContent('Record hostnames')
  })

  test('a read without the field shows no label rather than guessing IP only', () => {
    ctx.current = { currentProject: { name: 'Lab' } }
    expect(header()).toBeNull()
  })

  test('a domain project shows no label', () => {
    expect(header({ ipMode: false, ipHostnameMode: 'ip_only' })).toBeNull()
  })

  test('the summary label\'s own " · <mode>" suffix is not repeated beside the chip', () => {
    header({ ipHostnameMode: 'record_only', targetDomain: '2 IP targets · Record hostnames' })
    expect(screen.getByText('2 IP targets')).toBeInTheDocument()
    expect(screen.getAllByText(/Record hostnames/)).toHaveLength(1)
  })
})
