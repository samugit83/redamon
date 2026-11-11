/**
 * The diagram's four configurations (04_ui_spec.md §4 table, §7): which
 * elements are off or active per mode, read from the rendered semantic
 * structure, never from pixels.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/IpHostnameDiagram.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { IpHostnameDiagram } from './IpHostnameDiagram'
import { type IpHostnameMode, ipHostnameModeInfo } from './ipHostnameModes'

afterEach(() => { cleanup() })

/** The diagram as data: what §4's table describes, per element. */
function structure(mode: IpHostnameMode) {
  const { container } = render(<IpHostnameDiagram mode={mode} />)
  const el = (name: string) => container.querySelector(`[data-element="${name}"]`)
  const text = (name: string) => el(name)?.textContent?.trim() ?? null
  return {
    discover: el('discover')?.getAttribute('data-state'),
    discoverOffTag: el('discover')?.querySelector('.offTag')?.textContent === 'off',
    passiveChip: text('passive-chip'),
    decide: el('decide')?.getAttribute('data-state'),
    decideText: el('decide')?.querySelector('p')?.textContent,
    confirmedChip: text('confirmed-chip'),
    scanNames: text('scan-names'),
    graph: el('graph')?.getAttribute('data-state'),
    graphNodes: [...container.querySelectorAll('[data-element="graph"] [data-node]')].map(n => n.getAttribute('data-node')),
    graphEdges: [...container.querySelectorAll('[data-element="graph"] [data-edge]')].map(n => n.getAttribute('data-edge')),
    traffic: text('traffic'),
  }
}

describe('per mode, the elements of §4', () => {
  test('IP only: discover off, nothing to decide, no names box, IP + certificates', () => {
    expect(structure('ip_only')).toEqual({
      discover: 'off', discoverOffTag: true, passiveChip: null,
      decide: 'off', decideText: 'Nothing to decide', confirmedChip: null,
      scanNames: null,
      graph: 'ip', graphNodes: ['Certificate', 'IP'], graphEdges: ['link'],
      traffic: 'TrafficPackets → your IPs only. No hostname lookups.',
    })
  })

  test('Record hostnames: discover on, record all · scan none, grey ExternalDomains SEEN_ON the IP', () => {
    expect(structure('record_only')).toEqual({
      discover: 'active', discoverOffTag: false, passiveChip: null,
      decide: 'active', decideText: 'Record all · scan none', confirmedChip: null,
      scanNames: null,
      graph: 'recorded', graphNodes: ['Certificate', 'IP', 'ExternalDomain'], graphEdges: ['link', 'SEEN_ON'],
      traffic: 'TrafficPackets → your IPs only. + DNS/API lookups about the names → resolvers and OSINT services.',
    })
  })

  test('Record + scan matching: the passive chip, the filter decision, matching names scanned', () => {
    const s = structure('record_filter')
    expect(s).toMatchObject({
      discover: 'active', passiveChip: 'Passive search of *.filters',
      decide: 'active', decideText: 'Include − Exclude → DNS check: every address is one of your IPs → limit',
      confirmedChip: null, scanNames: 'Matching names, on your IPs',
      graph: 'scanned', graphNodes: ['Certificate', 'IP', 'ExternalDomain', 'Subdomain', 'Domain'],
      graphEdges: ['link', 'SEEN_ON', 'RESOLVES_TO', 'link'],
    })
    expect(s.traffic).toMatch(/names sent as SNI\/Host/)
    expect(s.traffic).toMatch(/passive search APIs/)
  })

  test('Record + scan all: no passive chip, the CDN-edge decision with the red "confirmed" chip', () => {
    const s = structure('scan_all')
    expect(s).toMatchObject({
      discover: 'active', passiveChip: null,
      decideText: 'All names → skip CDN edges → DNS check → limit', confirmedChip: 'confirmed',
      scanNames: 'All eligible names, on your IPs', graph: 'scanned',
    })
    expect(s.traffic).toMatch(/names sent as SNI\/Host/)
    expect(s.traffic).not.toMatch(/passive search/)
  })
})

describe('accessibility and theming', () => {
  test.each(['ip_only', 'record_only', 'record_filter', 'scan_all'] as const)(
    '%s: one image with the mode\'s summary as its label', (mode) => {
      render(<IpHostnameDiagram mode={mode} />)
      expect(screen.getByRole('img').getAttribute('aria-label')).toBe(ipHostnameModeInfo(mode).diagram.ariaLabel)
    },
  )

  test('M4 says what the spec says, word for word', () => {
    expect(ipHostnameModeInfo('record_filter').diagram.ariaLabel).toBe(
      'Hostnames are discovered from reverse DNS, certificates, passive DNS and redirects, filtered by your ' +
      'include and exclude lists, checked to point only to your IPs, then scanned on your IPs; refused names ' +
      'are saved with the reason.')
  })

  test('graph nodes are painted in the graph page\'s own colours', () => {
    const { container } = render(<IpHostnameDiagram mode="record_filter" />)
    const fill = (type: string) => (container.querySelector(`[data-node="${type}"] circle`) as SVGElement).style.fill
    // NODE_COLORS: IP teal, Subdomain royal blue, ExternalDomain stone grey.
    expect(fill('IP')).toBe('rgb(13, 148, 136)')
    expect(fill('Subdomain')).toBe('rgb(37, 99, 235)')
    expect(fill('ExternalDomain')).toBe('rgb(139, 129, 120)')
  })

  test('an off lane is drawn dashed (its own class), an active one is not', () => {
    const { container } = render(<IpHostnameDiagram mode="ip_only" />)
    expect(container.querySelector('[data-element="discover"]')!.className).toMatch(/laneOff/)
    expect(container.querySelector('[data-element="scan"]')!.className).not.toMatch(/laneOff/)
  })
})
