import { describe, test, expect } from 'vitest'
import { createHash } from 'node:crypto'
import {
  ALL_PRESETS,
  ALPHABETICAL_PRESETS,
  FEATURED_PRESETS,
  TRADECRAFT_PRESETS,
  presetByKey,
  presetSettings,
  presetsWithSettings,
} from './presets'
import { SITE_TYPES } from './agentContract'
import { validateOverrides } from './settingsSpec'

describe('tradecraft presets', () => {
  test('has_105', () => {
    expect(TRADECRAFT_PRESETS).toHaveLength(100)
    expect(FEATURED_PRESETS).toHaveLength(5)
    expect(ALL_PRESETS).toHaveLength(105)
    expect(ALPHABETICAL_PRESETS).toHaveLength(100)
  })

  test('the 100 moved from the form keep their values', () => {
    // sha256 of name|url|type|description, one line each in source order, computed from
    // QUICK_ADD_PRESETS_RAW of TradecraftResourceForm.tsx before the move.
    const canon = TRADECRAFT_PRESETS.map(p => [p.name, p.url, p.type, p.description].join('|')).join('\n')
    expect(createHash('sha256').update(canon).digest('hex'))
      .toBe('e85044d9bcf2266e7969a071b9b1c0ef51f32e6f527adb5d6379cd5964e2a643')
  })

  test('featured_order_exact', () => {
    expect(FEATURED_PRESETS.map(p => [p.name, p.url])).toEqual([
      ['Web Hacking Techniques Index', 'https://webhacklist.com/?year=2026-ai'],
      ['Web Hacking Techniques archive (GitHub)', 'https://github.com/irsdl/webhacklist'],
      ['Claude-BugHunter', 'https://github.com/elementalsouls/Claude-BugHunter'],
      ['Agentic-Bug-Hunter', 'https://github.com/awarexone/Agentic-Bug-Hunter'],
      ['HexBrain payloads', 'https://hexbrainai.com/payloads'],
    ])
    expect(FEATURED_PRESETS.every(p => p.featured === true)).toBe(true)
    expect(ALL_PRESETS.slice(0, 5)).toEqual(FEATURED_PRESETS)
  })

  test('featured descriptions name their overlaps', () => {
    expect(FEATURED_PRESETS[1].description).toContain('Same archive as the website preset')
    expect(FEATURED_PRESETS[4].description).toContain('drawn from PayloadsAllTheThings')
    expect(TRADECRAFT_PRESETS.some(p => p.name === 'PayloadsAllTheThings')).toBe(true)
  })

  test('featured_not_in_alphabetical', () => {
    const featured = new Set(FEATURED_PRESETS.map(p => p.url))
    expect(ALPHABETICAL_PRESETS.filter(p => featured.has(p.url) || p.featured)).toEqual([])
    expect(TRADECRAFT_PRESETS.some(p => p.featured)).toBe(false)
  })

  test('alphabetical list is sorted by name, case-insensitively', () => {
    const names = ALPHABETICAL_PRESETS.map(p => p.name.toLowerCase())
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)))
  })

  test('no_duplicate_urls', () => {
    const urls = ALL_PRESETS.map(p => p.url)
    expect(new Set(urls).size).toBe(urls.length)
  })

  test('webhacklist_url_has_no_fragment_and_keeps_query', () => {
    const u = new URL(FEATURED_PRESETS[0].url)
    expect(u.hash).toBe('')
    expect(u.searchParams.get('year')).toBe('2026-ai')
    expect(ALL_PRESETS.filter(p => p.url.includes('#'))).toEqual([])
  })

  test('keys_unique_and_stable', () => {
    const keys = ALL_PRESETS.map(p => p.key)
    expect(new Set(keys).size).toBe(keys.length)
    for (const k of keys) expect(k).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    // A resource records the key of the preset it came from: these never change.
    expect(presetByKey('hacktricks')?.url).toBe('https://book.hacktricks.wiki')
    expect(presetByKey('payloadsallthethings')?.url).toBe('https://github.com/swisskyrepo/PayloadsAllTheThings')
    expect(presetByKey('att-ck-matrix')?.name).toBe('ATT&CK matrix')
    expect(FEATURED_PRESETS.map(p => p.key)).toEqual([
      'web-hacking-techniques-index', 'web-hacking-techniques-archive-github', 'claude-bughunter',
      'agentic-bug-hunter', 'hexbrain-payloads',
    ])
    expect(presetByKey('nope')).toBeUndefined()
  })

})

describe('carry_settings (§6.12, R-171, AC-45)', () => {
  const byKey = (k: string) => presetSettings(presetByKey(k)!)

  test('every preset key with settings exists, and every override is one the form may save', () => {
    for (const key of presetsWithSettings()) expect(presetByKey(key), key).toBeDefined()
    for (const preset of ALL_PRESETS) {
      const s = presetSettings(preset)
      if (s.forcedType) expect(SITE_TYPES).toContain(s.forcedType)
      expect(validateOverrides(s.overrides ?? {}), preset.key).toMatchObject({ ok: true })
      for (const k of s.unverified ?? []) expect(Object.keys(s.overrides ?? {}), preset.key).toContain(k)
    }
  })

  test('the type: forced for a GitHub repository and a CVE archive, Auto where the chip is only a hint', () => {
    expect(byKey('payloadsallthethings').forcedType).toBe('github-repo')
    expect(byKey('trickest-cve').forcedType).toBe('cve-poc-db')
    expect(byKey('hacktricks').forcedType).toBeUndefined()
    expect(byKey('scapy-docs').forcedType).toBeUndefined()
    for (const p of ALL_PRESETS.filter(x => x.type === 'github-repo')) {
      expect(new URL(p.url).hostname, p.key).toBe('github.com')
      expect(presetSettings(p).forcedType, p.key).toBe('github-repo')
    }
  })

  test('file types: .yml for LOLBAS and Sigma, .yar for YARA-Rules, added to the user\'s list', () => {
    expect(byKey('lolbas-source').overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'add', items: ['.yml'] } })
    expect(byKey('sigma-rules').overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'add', items: ['.yml'] } })
    expect(byKey('yara-rules').overrides).toEqual({ 'knownTypes.githubFileTypes': { mode: 'add', items: ['.yar'] } })
  })

  test('every CVE archive carries path patterns, recorded as unverified for MC-3', () => {
    for (const p of ALL_PRESETS.filter(x => x.type === 'cve-poc-db')) {
      const s = presetSettings(p)
      expect((s.overrides?.['type.cve.pathPatterns'] as string[]).length, p.key).toBeGreaterThan(0)
      expect(s.unverified, p.key).toContain('type.cve.pathPatterns')
    }
  })

  test('the Featured websites: their sitemap through Auto; HexBrain inside /payloads', () => {
    expect(byKey('web-hacking-techniques-index')).toEqual({ forcedType: 'agentic-crawl', overrides: { 'crawl.strategy': 'auto' } })
    expect(byKey('hexbrain-payloads')).toEqual({
      forcedType: 'agentic-crawl',
      overrides: { 'crawl.strategy': 'auto', 'crawl.includePaths': { mode: 'add', items: ['/payloads/*'] }, 'crawl.stayInFolder': true },
    })
    for (const k of ['web-hacking-techniques-archive-github', 'claude-bughunter', 'agentic-bug-hunter']) {
      expect(byKey(k), k).toEqual({ forcedType: 'github-repo' })
    }
  })

  test('a copy: changing what the form got never changes the preset', () => {
    const s = byKey('hexbrain-payloads')
    ;(s.overrides!['crawl.includePaths'] as { items: string[] }).items.push('/x')
    expect(byKey('hexbrain-payloads').overrides!['crawl.includePaths']).toEqual({ mode: 'add', items: ['/payloads/*'] })
  })
})
