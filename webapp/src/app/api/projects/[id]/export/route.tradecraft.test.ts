/**
 * A project's tradecraft choices never leave with it (§3.4, R-068): they name the owner's own
 * resources, which another account or install does not have. The export reads its tables model by
 * model and the project row without relations, so a table it does not name is absent from the
 * bundle; the import writes no choice, so an imported project starts with every resource on.
 * Source-level, as the AI Navigator's export test.
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const API = join(process.cwd(), 'src/app/api/projects')

describe('export and import carry no tradecraft choice', () => {
  test('the export reads no tradecraft table and the project row without its relations', () => {
    const src = readFileSync(join(API, '[id]/export/route.ts'), 'utf8')
    expect(src).not.toMatch(/tradecraft/i)
    expect(src).toMatch(/prisma\.project\.findUnique\(\{ where: \{ id \} \}\)/)
  })

  test('the import reads no tradecraftOff key and writes no tradecraft table', () => {
    const src = readFileSync(join(API, 'import/route.ts'), 'utf8')
    expect(src).not.toMatch(/tradecraft/i)
  })
})
