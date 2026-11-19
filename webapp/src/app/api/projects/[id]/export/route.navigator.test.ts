/**
 * AI Navigator conversations and the owner's collaborator policy are private to their people and
 * never leave with a project (plan §6.2, D13): the export lists its models explicitly and names none
 * of the Navigator's, and the import reads no Navigator key, so an imported project starts with the
 * toggle off. Source-level: the bundle is built model by model, so absence there is absence in it.
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const API = join(process.cwd(), 'src/app/api/projects')

describe('export and import leave AI Navigator out', () => {
  test('the export reads no navigator table', () => {
    const src = readFileSync(join(API, '[id]/export/route.ts'), 'utf8')
    expect(src).not.toMatch(/navigator/i)
  })

  test('the import reads no navigator key and writes no navigator table', () => {
    const src = readFileSync(join(API, 'import/route.ts'), 'utf8')
    expect(src).not.toMatch(/navigator/i)
  })
})
