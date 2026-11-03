import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { IMPORT_PRESETS } from './presets'
import { isGithubFamilyHost } from './githubHosts'

const TRADECRAFT_FORM = join(process.cwd(), 'src/components/settings/TradecraftResourceForm.tsx')

/** The URLs of QUICK_ADD_PRESETS_RAW, read from the form's source (the array is not exported). */
function tradecraftPresetUrls(): string[] {
  const src = readFileSync(TRADECRAFT_FORM, 'utf8')
  const start = src.indexOf('const QUICK_ADD_PRESETS_RAW')
  const end = src.indexOf('\n]', start)
  if (start < 0 || end < 0) throw new Error('QUICK_ADD_PRESETS_RAW not found in TradecraftResourceForm.tsx - update this test')
  return Array.from(src.slice(start, end).matchAll(/url: '([^']+)'/g), (m) => m[1])
}

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
    const tradecraft = tradecraftPresetUrls()
    expect(tradecraft.length).toBeGreaterThan(20)
    const outside = IMPORT_PRESETS.filter((p) => !tradecraft.includes(p.url))
    // The one exception is a folder of a Tradecraft repository, not a URL of its own.
    expect(outside.map((p) => p.label)).toEqual(['SecLists: Web-Content'])
    const seclists = tradecraft.find((u) => u.endsWith('/SecLists'))
    expect(seclists).toBeDefined()
    expect(outside[0].url).toBe(`${seclists}/tree/master/Discovery/Web-Content`)
  })
})
