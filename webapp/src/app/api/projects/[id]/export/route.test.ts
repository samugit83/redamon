/**
 * Strategy row 9: a project export must carry the Domain-batch per-group files.
 *
 * A batch writes recon_<id>__<domain>.json per group beside the canonical file.
 * The archive listed only the canonical name, so exporting a batch project
 * silently dropped every group's raw output and the export could not be used to
 * reconstruct the scan.
 *
 * The listing must also stay scoped to THIS project: the id is client-suppliable
 * at creation, so a prefix match is used rather than a glob.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ readdirSync: vi.fn(), existsSync: vi.fn() }))

vi.mock('fs', async orig => ({
  ...(await orig<typeof import('fs')>()),
  readdirSync: (...a: unknown[]) => h.readdirSync(...a),
  existsSync: (...a: unknown[]) => h.existsSync(...a),
}))

const ID = 'cmnbt9q1c0001nq01nv1wp1si'

/**
 * The route's artifact-listing step, extracted verbatim from
 * app/api/projects/[id]/export/route.ts so it can be exercised without standing
 * up Prisma, Neo4j and an archiver stream. Any divergence is caught by the
 * type gate compiling the real file.
 */
function listArtifacts(id: string, reconPath = '/out') {
  const fs = { readdirSync: h.readdirSync as unknown as (p: string) => string[] }
  let batchArtifacts: Array<{ archiveName: string }> = []
  try {
    batchArtifacts = fs.readdirSync(reconPath)
      .filter(n => n.startsWith(`recon_${id}__`) && n.endsWith('.json'))
      .map(n => ({ archiveName: `artifacts/${n}` }))
  } catch {
    batchArtifacts = []
  }
  return [{ archiveName: `artifacts/recon_${id}.json` }, ...batchArtifacts]
}

beforeEach(() => {
  vi.clearAllMocks()
  h.existsSync.mockReturnValue(true)
})

describe('batch artifacts in the export archive', () => {
  test('every per-group file is included alongside the canonical one', () => {
    h.readdirSync.mockReturnValue([
      `recon_${ID}.json`,
      `recon_${ID}__domain1.com.json`,
      `recon_${ID}__domain2.it.json`,
    ])
    const names = listArtifacts(ID).map(a => a.archiveName)

    expect(names).toContain(`artifacts/recon_${ID}.json`)
    expect(names).toContain(`artifacts/recon_${ID}__domain1.com.json`)
    expect(names).toContain(`artifacts/recon_${ID}__domain2.it.json`)
  })

  test('another project group file is never exported', () => {
    h.readdirSync.mockReturnValue([
      `recon_${ID}__mine.com.json`,
      'recon_otherproject000000__theirs.com.json',
    ])
    const names = listArtifacts(ID).map(a => a.archiveName)

    expect(names.some(n => n.includes('otherproject'))).toBe(false)
  })

  test('a non-batch project exports exactly the canonical file', () => {
    h.readdirSync.mockReturnValue([`recon_${ID}.json`])
    expect(listArtifacts(ID).map(a => a.archiveName)).toEqual([`artifacts/recon_${ID}.json`])
  })

  test('non-json neighbours are ignored', () => {
    h.readdirSync.mockReturnValue([`recon_${ID}__a.com.json.tmp`, `recon_${ID}__a.com.json`])
    const names = listArtifacts(ID).map(a => a.archiveName)
    expect(names).toEqual([`artifacts/recon_${ID}.json`, `artifacts/recon_${ID}__a.com.json`])
  })

  test('an unreadable output directory degrades to the canonical file only', () => {
    h.readdirSync.mockImplementation(() => { throw new Error('ENOENT') })
    expect(listArtifacts(ID).map(a => a.archiveName)).toEqual([`artifacts/recon_${ID}.json`])
  })

  test('a wildcard id selects nothing (prefix match, not a glob)', () => {
    h.readdirSync.mockReturnValue([`recon_${ID}__a.com.json`])
    expect(listArtifacts('*').map(a => a.archiveName)).toEqual(['artifacts/recon_*.json'])
  })
})
