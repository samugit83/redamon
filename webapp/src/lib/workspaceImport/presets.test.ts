import { describe, test, expect } from 'vitest'
import { IMPORT_PRESETS } from './presets'
import { isGithubFamilyHost } from './githubHosts'
import { FEATURED_PRESETS, TRADECRAFT_PRESETS } from '@/lib/tradecraft/presets'

describe('workspace import presets', () => {
  test('labels unique', () => {
    const labels = IMPORT_PRESETS.map((p) => p.label)
    expect(new Set(labels).size).toBe(labels.length)
    expect(IMPORT_PRESETS.length).toBeGreaterThanOrEqual(8)
    for (const p of IMPORT_PRESETS) expect(p.description.trim()).not.toBe('')
  })

  test('every URL is https on a GitHub host', () => {
    for (const p of IMPORT_PRESETS) {
      const u = new URL(p.url)
      expect(u.protocol, p.url).toBe('https:')
      expect(isGithubFamilyHost(u.hostname), p.url).toBe(true)
      expect(u.search + u.hash, p.url).toBe('')
    }
  })

  test('every URL also appears in the Tradecraft presets, except the documented subfolder preset', () => {
    const tradecraft = TRADECRAFT_PRESETS.map((p) => p.url)
    expect(tradecraft).toHaveLength(100)
    const outside = IMPORT_PRESETS.filter((p) => !tradecraft.includes(p.url))
    // The one exception is a folder of a Tradecraft repository, not a URL of its own.
    expect(outside.map((p) => p.label)).toEqual(['SecLists: Web-Content'])
    const seclists = tradecraft.find((u) => u.endsWith('/SecLists'))
    expect(seclists).toBeDefined()
    expect(outside[0].url).toBe(`${seclists}/tree/master/Discovery/Web-Content`)
  })

  test('the Featured presets are not offered for workspace import', () => {
    const featured = new Set(FEATURED_PRESETS.map((p) => p.url))
    expect(IMPORT_PRESETS.filter((p) => featured.has(p.url))).toEqual([])
  })

  test('the chips offer the same URLs as before they were read from the Tradecraft presets', () => {
    expect(IMPORT_PRESETS.map((p) => p.url)).toEqual([
      'https://github.com/danielmiessler/SecLists',
      'https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content',
      'https://github.com/swisskyrepo/PayloadsAllTheThings',
      'https://github.com/swisskyrepo/InternalAllTheThings',
      'https://github.com/OWASP/CheatSheetSeries',
      'https://github.com/OWASP/wstg',
      'https://github.com/GTFOBins/GTFOBins.github.io',
      'https://github.com/LOLBAS-Project/LOLBAS',
      'https://github.com/peass-ng/PEASS-ng',
      'https://github.com/redcanaryco/atomic-red-team',
    ])
  })
})
