/**
 * Every tool switch an AI-generated preset can carry has a readable name in the
 * review step.
 *
 * The names were a hand map that stopped at the tools of its day: tlsx, route
 * exposure, IP attribution and every later tool showed as a raw key fragment.
 * They are now read from the registry, and this file fails on a key the
 * generator accepts that the registry cannot name.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import { enabledKeyLabel } from './GeneratePresetModal'
import { reconPresetSchema } from '@/lib/recon-preset-schema'
import { field, tool } from '@/lib/reconSettings/registry'

/** The keys the review step lists as enabled or disabled. */
const ENABLED_KEYS = Object.keys(reconPresetSchema.shape).filter(k => k.endsWith('Enabled'))

describe('enabledKeyLabel', () => {
  test('the generator accepts many tool switches', () => {
    // An empty list would pass every assertion below on nothing.
    expect(ENABLED_KEYS.length).toBeGreaterThan(50)
  })

  test('every switch the generator accepts is named by a registry tool', () => {
    // Not "label differs from the key": several tools are titled by their own
    // lowercase name (tlsx, naabu). What must not happen is the raw-key fallback.
    const unnamed = ENABLED_KEYS.filter(k => {
      const spec = field(k)
      return !spec || !tool(spec.tool)
    })
    expect(unnamed).toEqual([])
  })

  test('no two switches share a name', () => {
    const byLabel = new Map<string, string[]>()
    for (const k of ENABLED_KEYS) byLabel.set(enabledKeyLabel(k), [...(byLabel.get(enabledKeyLabel(k)) ?? []), k])
    const shared = [...byLabel.entries()].filter(([, keys]) => keys.length > 1)
    expect(shared).toEqual([])
  })

  test("a tool's own switch is the tool's registry title", () => {
    expect(enabledKeyLabel('tlsxEnabled')).toBe(tool('tlsx')!.title)
    expect(enabledKeyLabel('routeExposureEnabled')).toBe(tool('route_exposure')!.title)
    expect(enabledKeyLabel('ipAttributionEnabled')).toBe(tool('ip_attribution')!.title)
    expect(enabledKeyLabel('trufflehogEnabled')).toBe(tool('trufflehog')!.title)
  })

  test('a feature toggle names its tool and the feature', () => {
    expect(enabledKeyLabel('nucleiTakeoversEnabled')).toBe(`${tool('nuclei')!.title}: Takeovers`)
    expect(enabledKeyLabel('aiSurfaceReconMcpYaraEnabled'))
      .toBe(`${tool(field('aiSurfaceReconMcpYaraEnabled')!.tool)!.title}: MCP YARA`)
  })

  test('a key the registry does not know falls back to the key', () => {
    expect(enabledKeyLabel('notAColumnEnabled')).toBe('notAColumn')
  })
})
