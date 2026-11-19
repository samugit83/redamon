/**
 * The agent's copies of the settings spec and vocabulary (D-34): the committed copies
 * equal the webapp's files, and the check reports a stale copy without writing it.
 *
 * Run: npx vitest run scripts/gen-tradecraft-spec.test.ts
 *
 * @vitest-environment node
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { COPIES, run } from './gen-tradecraft-spec.mjs'

describe('gen-tradecraft-spec', () => {
  test('--check: the committed agent copies are up to date', () => {
    expect(run({ check: true })).toEqual([])
  })

  test('a stale or missing copy is reported by --check and written by a plain run', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tc-spec-'))
    try {
      const root = join(dir, 'webapp')
      mkdirSync(join(root, 'src/lib/tradecraft'), { recursive: true })
      mkdirSync(join(dir, 'agentic/tradecraft'), { recursive: true })
      writeFileSync(join(root, 'src/lib/tradecraft/settingsSpec.json'), '{"version":1}\n')
      writeFileSync(join(root, 'src/lib/tradecraft/vocab.json'), '{"version":1}\n')
      writeFileSync(join(dir, 'agentic/tradecraft/settings_spec.json'), '{"version":0}\n')

      expect(run({ check: true, root }).sort()).toEqual(['../agentic/tradecraft/settings_spec.json', '../agentic/tradecraft/vocab.json'])
      expect(readFileSync(join(dir, 'agentic/tradecraft/settings_spec.json'), 'utf8')).toBe('{"version":0}\n')

      expect(run({ root })).toHaveLength(2)
      for (const { source, target } of COPIES) {
        expect(readFileSync(join(root, target), 'utf8')).toBe(readFileSync(join(root, source), 'utf8'))
      }
      expect(run({ check: true, root })).toEqual([])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
