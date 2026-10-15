import { describe, expect, test } from 'vitest'
import { diffSnapshots, summarizeDiff, type DiffableNode } from './scanDiff'

const sub = (name: string): DiffableNode => ({ labels: ['Subdomain'], properties: { name } })
const port = (host: string, port: number): DiffableNode => ({
  labels: ['Port'],
  properties: { host, port, protocol: 'tcp' },
})
const cve = (id: string): DiffableNode => ({ labels: ['CVE'], properties: { id } })

describe('diffSnapshots', () => {
  test('identical snapshots diff to empty (tenant fields ignored)', () => {
    const a: DiffableNode[] = [
      sub('a.example.com'),
      { labels: ['Subdomain'], properties: { name: 'a.example.com', user_id: 'u1', project_id: 'p1' } },
    ]
    const d = diffSnapshots(a, [{ labels: ['Subdomain'], properties: { name: 'A.EXAMPLE.COM' } }])
    expect(d.empty).toBe(true)
  })

  test('detects new/removed subdomains, ports and CVEs', () => {
    const before: DiffableNode[] = [sub('a.example.com'), port('1.1.1.1', 80), cve('CVE-2021-44228')]
    const after: DiffableNode[] = [
      sub('a.example.com'),
      sub('b.example.com'),
      port('1.1.1.1', 80),
      port('1.1.1.1', 443),
      cve('CVE-2021-44228'),
      cve('CVE-2023-1234'),
    ]
    const d = diffSnapshots(before, after)
    expect(d.newSubdomains).toEqual(['b.example.com'])
    expect(d.removedSubdomains).toEqual([])
    expect(d.newPorts).toEqual([{ host: '1.1.1.1', port: 443, protocol: 'tcp' }])
    expect(d.newCves).toEqual(['CVE-2023-1234'])
    expect(d.empty).toBe(false)
  })

  test('counts new Vulnerability findings', () => {
    const v = (id: string): DiffableNode => ({
      labels: ['Vulnerability'],
      properties: { id, name: 'x', severity: 'high' },
    })
    const d = diffSnapshots([v('1')], [v('1'), v('2')])
    expect(d.newVulnCount).toBe(1)
  })

  test('summarizeDiff renders a badge line', () => {
    const d = diffSnapshots([sub('a.example.com')], [sub('a.example.com'), sub('b.example.com')])
    expect(summarizeDiff(d)).toContain('1 new subdomain')
    expect(summarizeDiff(diffSnapshots([], []))).toContain('No changes')
  })
})
