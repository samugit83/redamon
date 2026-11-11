/**
 * The one copy behind the cards, the modals and every label of a hostname mode:
 * it lists exactly the modes the rule knows, in reach order, with the labels
 * the lib/ readers print.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/ipHostnameModes.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { IP_HOSTNAME_MODES as RULE_MODES } from '@/lib/ipHostnameFilter'
import { IP_HOSTNAME_MODE_LABELS, ipHostnameModeLabel } from '@/lib/ipHostnameModeLabels'
import { IP_HOSTNAME_COMPARISON, IP_HOSTNAME_MODES, ipHostnameModeInfo } from './ipHostnameModes'

describe('ipHostnameModes', () => {
  test('the cards list the rule\'s modes, in its reach order', () => {
    expect(IP_HOSTNAME_MODES.map(m => m.mode)).toEqual([...RULE_MODES])
  })

  test('every card label is the shared label', () => {
    for (const m of IP_HOSTNAME_MODES) expect(m.label).toBe(IP_HOSTNAME_MODE_LABELS[m.mode])
  })

  test('an unknown or absent mode reads as IP only, as recon reads it', () => {
    expect(ipHostnameModeLabel(undefined)).toBe('IP only')
    expect(ipHostnameModeLabel('scan_more')).toBe('IP only')
    expect(ipHostnameModeLabel('toString')).toBe('IP only')
    expect(ipHostnameModeInfo(null).mode).toBe('ip_only')
  })

  test('only IP only is the default, only Record + scan all needs confirming', () => {
    expect(IP_HOSTNAME_MODES.filter(m => m.badge === 'DEFAULT').map(m => m.mode)).toEqual(['ip_only'])
    expect(IP_HOSTNAME_MODES.filter(m => m.badge === 'NEEDS CONFIRM').map(m => m.mode)).toEqual(['scan_all'])
    expect(IP_HOSTNAME_MODES.filter(m => m.warning).map(m => m.mode)).toEqual(['scan_all'])
  })

  test('the comparison answers every question for every mode', () => {
    for (const row of IP_HOSTNAME_COMPARISON) expect(Object.keys(row.answers)).toEqual([...RULE_MODES])
  })

  test('no copy names a real target: documentation addresses and reserved names only', () => {
    const text = JSON.stringify(IP_HOSTNAME_MODES)
    for (const ip of text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) {
      expect(ip, ip).toMatch(/^(203\.0\.113|198\.51\.100|192\.88\.98)\./)
    }
    for (const host of text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|de|fr|org|net|io)\b/g) ?? []) {
      expect(host, host).toMatch(/(^|\.)example\.(com|de|fr|org)$/)
    }
  })
})
