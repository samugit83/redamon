import { describe, expect, test } from 'vitest'
import {
  formatScanAlertText,
  isValidWebhookUrl,
  redactWebhookUrl,
} from './scanAlerts'
import type { ScanDiff } from './scanDiff'

const diff = (over: Partial<ScanDiff>): ScanDiff => ({
  newSubdomains: [],
  removedSubdomains: [],
  newPorts: [],
  removedPorts: [],
  newCves: [],
  newVulnCount: 0,
  empty: true,
  ...over,
})

describe('scanAlerts', () => {
  test('rejects non-https / malformed webhook URLs', () => {
    expect(isValidWebhookUrl('http://x/hook')).toBe(false)
    expect(isValidWebhookUrl('https://hooks.slack.com/x')).toBe(true)
    expect(isValidWebhookUrl('javascript:alert(1)')).toBe(false)
    expect(isValidWebhookUrl(123)).toBe(false)
  })

  test('redacts the webhook secret', () => {
    expect(redactWebhookUrl('https://hooks.slack.com/services/T/A/B')).toBe(
      'https://hooks.slack.com/…'
    )
  })

  test('formats a readable alert', () => {
    const text = formatScanAlertText({
      projectName: 'acme',
      diff: diff({ newSubdomains: ['b.acme.com'], newCves: ['CVE-2023-1234'], empty: false }),
    })
    expect(text).toContain('acme')
    expect(text).toContain('b.acme.com')
    expect(text).toContain('CVE-2023-1234')
  })
})
