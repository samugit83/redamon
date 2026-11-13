/**
 * T19 and T48: the settings reference cannot go stale.
 *
 * The narrative page opened by claiming "245+ configurable parameters" while the
 * model had 714. That is the failure mode of a hand-written exhaustive
 * reference: it is right on the day it is written and quietly wrong every day
 * after, and nobody notices because nobody counts.
 *
 * So the exhaustive table is generated, byte-compared here, and the narrative
 * page's own count is checked against the registry. Run
 * `npm run docs:settings` to regenerate after a registry change.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { wikiCheckoutPresent } from '@/lib/wikiCheckout.testUtils'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { fieldsWhere } from './registry'
import {
  SETTINGS_REFERENCE_PAGE,
  renderSettingsReference,
  settableFieldCount,
  totalColumnCount,
} from './settingsReference'

const WIKI_DIR = process.env.MCP_DOCS_WIKI_DIR
  || fileURLToPath(new URL('../../../../redamon.wiki/', import.meta.url))
const WRITE = process.env.MCP_DOCS_WRITE === '1'

/** A real wiki checkout; an empty one fails unless allowed (wikiCheckout.testUtils.ts). */
const hasWikiCheckout = () => wikiCheckoutPresent(WIKI_DIR)

describe('the generated page is deterministic', () => {
  test('two renders are byte-identical', () => {
    // No dates, no version strings, stable key order. A diff that changes on
    // every run is one people learn to ignore, and this page is only worth
    // having if a diff on it means something.
    expect(renderSettingsReference()).toBe(renderSettingsReference())
  })

  test('it says it is generated and where from', () => {
    const page = renderSettingsReference()
    expect(page).toContain('GENERATED')
    expect(page).toContain('recon_settings/registry.yaml')
  })

  test('every field appears exactly once', () => {
    const page = renderSettingsReference()
    const missing = fieldsWhere(() => true)
      .map(f => f.key)
      .filter(key => !page.includes(`| \`${key}\` |`))
    expect(missing).toEqual([])
  })

  test('no row breaks the markdown table', () => {
    // A meaning containing a pipe or a newline becomes two cells or two rows,
    // which silently corrupts every column after it.
    const rows = renderSettingsReference().split('\n').filter(l => l.startsWith('| `'))
    expect(rows.length).toBeGreaterThan(700)
    for (const row of rows) {
      const cells = row.split(/(?<!\\)\|/).length - 2
      expect(cells, row.slice(0, 80)).toBe(5)
    }
  })

  test('the stated count is the registry count', () => {
    expect(renderSettingsReference()).toContain(`There are **${totalColumnCount()}** parameters`)
  })

  test('the three dispositions add up to the total', () => {
    const all = fieldsWhere(() => true)
    const sum = (['settable', 'create_only', 'never'] as const)
      .map(d => all.filter(f => f.mcp === d).length)
      .reduce((a, b) => a + b, 0)
    expect(sum).toBe(all.length)
  })
})

describe('the page says the things a reader would otherwise get wrong', () => {
  test('a zero that means unlimited is flagged in its own row', () => {
    const page = renderSettingsReference()
    for (const f of fieldsWhere(s => s.zero_means === 'unlimited')) {
      const row = page.split('\n').find(l => l.startsWith(`| \`${f.key}\` |`))
      expect(row, f.key).toBeDefined()
      expect(row, f.key).toContain('0 means UNLIMITED')
    }
  })

  test('a capped rate says it is capped', () => {
    const page = renderSettingsReference()
    for (const f of fieldsWhere(s => s.roe_capped)) {
      const row = page.split('\n').find(l => l.startsWith(`| \`${f.key}\` |`))
      expect(row, f.key).toContain('engagement rate ceiling')
    }
  })

  test("a share:secret field says it stays the owner's, and only those", () => {
    const page = renderSettingsReference()
    const rows = new Map(page.split('\n').filter(l => l.startsWith('| `')).map(l => [l.split('`')[1], l]))
    for (const f of fieldsWhere(() => true)) {
      const says = rows.get(f.key)?.includes('never shown to a collaborator')
      expect(says, f.key).toBe(f.share === 'secret')
    }
  })

  test('a create-only field says it is fixed at creation', () => {
    const page = renderSettingsReference()
    const row = page.split('\n').find(l => l.startsWith('| `targetDomain` |'))
    expect(row).toContain('Fixed at project creation')
  })

  test('it teaches the two-level model', () => {
    expect(renderSettingsReference()).toContain('silent no-op')
  })

  test('it explains written versus resolved', () => {
    // The distinction an agent gets wrong: get_recon_settings echoes what was
    // written, and several values are corrected at scan start.
    expect(renderSettingsReference()).toContain('[guardrail]')
  })
})

describe('T19 the wiki page (Project-Settings-Registry.md)', () => {
  test.skipIf(!hasWikiCheckout())('P17: matches a fresh render', () => {
    const target = path.join(WIKI_DIR, SETTINGS_REFERENCE_PAGE)
    const rendered = renderSettingsReference()
    if (WRITE) {
      writeFileSync(target, rendered, 'utf8')
      return
    }
    const onDisk = existsSync(target) ? readFileSync(target, 'utf8') : ''
    expect(
      onDisk,
      `${target} is stale: run \`npm run docs:settings\` in webapp/`
    ).toBe(rendered)
  })

  test.skipIf(!hasWikiCheckout())('P17: the narrative page does not contradict the registry counts', () => {
    // It claimed "245+ configurable parameters" against a model of 714, and
    // then 714 against a model where 47 columns configure nothing anyone can
    // reach. A page that overstates the surface is the same failure as one that
    // understates it: a reader trusts the number.
    //
    // So both numbers are stated and both are checked. A reader who wants "how
    // much can I change" and a reader who wants "how much is stored" get
    // different, correct answers.
    const narrative = path.join(WIKI_DIR, 'Project-Settings-Reference.md')
    if (!existsSync(narrative)) return
    const text = readFileSync(narrative, 'utf8')

    const stored = [...text.matchAll(/\*\*(\d+)\*\* stored parameters/g)]
    expect(stored.length, 'the page must state the stored-column count').toBeGreaterThan(0)
    for (const m of stored) expect(Number(m[1])).toBe(totalColumnCount())

    const settable = [...text.matchAll(/\*\*(\d+)\*\* of (?:them|which)[^.]*MCP/g)]
    expect(settable.length, 'the page must state the settable count').toBeGreaterThan(0)
    for (const m of settable) expect(Number(m[1])).toBe(settableFieldCount())

    // The old shape must not come back under either number.
    expect(text).not.toMatch(/\d+\+? configurable parameters/)
  })
})
