/**
 * Which template entries a project may hold (HD-08): where each entry can point nuclei
 * inside the custom-templates mount, and whether the project's owner may use what it
 * points at. The mount is `/custom-templates` in the nuclei container (recon's
 * nuclei_helpers.py); a free-form `-t` value is split on commas, resolved against `/`
 * and `/root/nuclei-templates`, and globbed when it holds `*`.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/nucleiTemplateOwnership.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterAll, vi } from 'vitest'
import { mkdir, rm } from 'fs/promises'
import path from 'path'

const h = vi.hoisted(() => {
  const root = `${process.env.TMPDIR || '/tmp'}/redamon-nuclei-reach-${process.pid}-${Date.now()}`
  process.env.NUCLEI_TEMPLATES_PATH = root
  return { root }
})

import {
  mountReach, ownershipOf, templateSelectionRefusal, withoutUnselectableTemplates, type TemplateOwnerRow,
} from './nucleiTemplateOwnership'

let rows: TemplateOwnerRow[]
const reads: string[][] = []
const db = {
  nucleiTemplate: {
    findMany: async ({ where }: { where: { path: { in: string[] } } }) => {
      reads.push(where.path.in)
      return rows.filter(r => where.path.in.includes(r.path))
    },
  },
}

beforeEach(async () => {
  rows = [
    { path: 'mine.yaml', ownerUserId: 'owner' },
    { path: 'theirs.yaml', ownerUserId: 'other-member' },
    { path: 'shipped.yaml', ownerUserId: null },
    { path: 'team/theirs.yaml', ownerUserId: 'other-member' },
  ]
  reads.length = 0
  await rm(h.root, { recursive: true, force: true })
  await mkdir(path.join(h.root, 'folder.yaml'), { recursive: true })
})
afterAll(async () => { await rm(h.root, { recursive: true, force: true }) })

describe('ownershipOf', () => {
  test('no owner is the instance, the user is own, anyone else other', () => {
    expect(ownershipOf(null, 'u')).toBe('instance')
    expect(ownershipOf(undefined, 'u')).toBe('instance')
    expect(ownershipOf('u', 'u')).toBe('own')
    expect(ownershipOf('v', 'u')).toBe('other')
  })
})

describe('mountReach', () => {
  const sel = (e: string) => mountReach('nucleiSelectedCustomTemplates', e)
  const free = (e: string) => mountReach('nucleiTemplates', e)

  test('a selected entry is a file in the folder; a .yml one also reaches its .yaml sibling', () => {
    expect(sel('a.yaml')).toEqual({ kind: 'files', paths: ['a.yaml'] })
    expect(sel('./team/../a.yaml')).toEqual({ kind: 'files', paths: ['a.yaml'] })
    expect(sel('old.yml')).toEqual({ kind: 'files', paths: ['old.yml', 'old.yaml'] })
  })

  test('a selected entry that is the folder, a glob, a list or climbs out is never a template', () => {
    for (const e of ['', '.', 'team', '*', 'team/*.yaml', 'a.yaml,b.yaml', '..', '../..', 'a?.yaml']) {
      expect(sel(e).kind, e).toBe('broad')
    }
    expect(sel('../root/nuclei-templates/http/x.yaml')).toEqual({ kind: 'outside' })
  })

  test('a free-form official template path stays outside the mount', () => {
    for (const e of ['http/cves/2021/', 'http/cves/*.yaml', '/root/nuclei-templates/dns', '~/my-nuclei-templates', '/path/to/custom-templates']) {
      expect(free(e), e).toEqual({ kind: 'outside' })
    }
  })

  test('a free-form path to one file of the mount is that file, however it is spelled', () => {
    for (const e of ['/custom-templates/theirs.yaml', 'custom-templates/theirs.yaml', '../../custom-templates/theirs.yaml',
      '/custom-templates/x/../theirs.yaml', '"/custom-templates/theirs.yaml"', '~/../custom-templates/theirs.yaml']) {
      expect(free(e), e).toEqual({ kind: 'files', paths: ['theirs.yaml'] })
    }
  })

  test('a free-form value that loads the whole mount is broad: an ancestor, the mount, a folder, a glob', () => {
    for (const e of ['.', '/', '../..', '/custom-templates', '/custom-templates/', 'custom-templates/team',
      '/custom-templates/*.yaml', '/*/theirs.yaml', '/c*', '*', '/custom-templ?tes/x.yaml', '/[c]ustom-templates/x.yaml']) {
      expect(free(e).kind, e).toBe('broad')
    }
  })

  test('nuclei splits on commas: every part counts', () => {
    expect(free('http/cves/,/custom-templates/theirs.yaml')).toEqual({ kind: 'files', paths: ['theirs.yaml'] })
    expect(free('http/cves/, .').kind).toBe('broad')
    expect(free('http/, dns/')).toEqual({ kind: 'outside' })
  })
})

describe('templateSelectionRefusal', () => {
  const refusal = (data: Record<string, unknown>, stored: Record<string, unknown> = {}) =>
    templateSelectionRefusal(db, { ownerUserId: 'owner', data, stored })

  test('the owner\'s own and instance templates are selectable, as is a file with no row', async () => {
    expect(await refusal({ nucleiSelectedCustomTemplates: ['mine.yaml', 'shipped.yaml', 'host-added.yaml'] })).toBeNull()
    expect(reads).toEqual([['mine.yaml', 'shipped.yaml', 'host-added.yaml']])
  })

  test("selecting another member's template is refused, naming the entry and the field", async () => {
    const r = await refusal({ nucleiSelectedCustomTemplates: ['mine.yaml', 'theirs.yaml'] })
    expect(r).toMatchObject({ code: 'template_not_selectable', field: 'nucleiSelectedCustomTemplates', entry: 'theirs.yaml' })
    expect(r!.error).toMatch(/project owner's own templates and instance templates/)
  })

  test('a free-form path into another member\'s file is refused, in both free-form fields', async () => {
    expect(await refusal({ nucleiTemplates: ['/custom-templates/team/theirs.yaml'] }))
      .toMatchObject({ field: 'nucleiTemplates', entry: '/custom-templates/team/theirs.yaml' })
    expect(await refusal({ nucleiCustomTemplates: ['http/,../../custom-templates/theirs.yaml'] }))
      .toMatchObject({ field: 'nucleiCustomTemplates' })
  })

  test('a free-form path that loads the whole mount is refused without a read', async () => {
    expect(await refusal({ nucleiTemplates: ['.'] })).toMatchObject({ entry: '.' })
    expect(reads).toEqual([])
  })

  test('a folder named like a template is not a template', async () => {
    expect(await refusal({ nucleiSelectedCustomTemplates: ['folder.yaml'] })).toMatchObject({ entry: 'folder.yaml' })
  })

  test('free-form official templates pass without a read', async () => {
    expect(await refusal({ nucleiTemplates: ['http/cves/'], nucleiCustomTemplates: ['~/mine'] })).toBeNull()
    expect(reads).toEqual([])
  })

  test('only entries this save adds are judged: a stored one never blocks an unrelated save', async () => {
    expect(await refusal(
      { nucleiSelectedCustomTemplates: ['theirs.yaml', 'mine.yaml'] },
      { nucleiSelectedCustomTemplates: ['theirs.yaml'] },
    )).toBeNull()
    expect(await refusal({ katanaDepth: 2 })).toBeNull()
    expect(reads).toEqual([['mine.yaml']])
  })

  test('a .yml selection is refused when its .yaml sibling, which nuclei would load, is another member\'s', async () => {
    rows.push({ path: 'swap.yaml', ownerUserId: 'other-member' })
    expect(await refusal({ nucleiSelectedCustomTemplates: ['swap.yml'] })).toMatchObject({ entry: 'swap.yml' })
  })
})

describe('withoutUnselectableTemplates', () => {
  test('drops from each of the three fields what the owner may not use, and counts it', async () => {
    const project = {
      id: 'p', userId: 'owner', name: 'kept',
      nucleiSelectedCustomTemplates: ['mine.yaml', 'theirs.yaml', 'shipped.yaml'],
      nucleiTemplates: ['http/cves/', '/custom-templates/theirs.yaml', '.'],
      nucleiCustomTemplates: ['/custom-templates/mine.yaml', 'custom-templates/team/theirs.yaml'],
    }
    const { project: out, dropped } = await withoutUnselectableTemplates(db, project)
    expect(out).toEqual({
      id: 'p', userId: 'owner', name: 'kept',
      nucleiSelectedCustomTemplates: ['mine.yaml', 'shipped.yaml'],
      nucleiTemplates: ['http/cves/'],
      nucleiCustomTemplates: ['/custom-templates/mine.yaml'],
    })
    expect(dropped).toEqual({ nucleiSelectedCustomTemplates: 1, nucleiTemplates: 2, nucleiCustomTemplates: 1 })
    expect(reads).toHaveLength(1)
  })

  test('a project with nothing to judge is returned as is, without a read', async () => {
    const project = { id: 'p', userId: 'owner', nucleiTemplates: ['http/'], nucleiSelectedCustomTemplates: [] }
    const r = await withoutUnselectableTemplates(db, project)
    expect(r.project).toBe(project)
    expect(r.dropped).toEqual({})
    expect(reads).toEqual([])
  })

  test('the same entries for another owner keep that owner\'s files', async () => {
    const r = await withoutUnselectableTemplates(db, { userId: 'other-member', nucleiSelectedCustomTemplates: ['theirs.yaml', 'mine.yaml'] })
    expect(r.project.nucleiSelectedCustomTemplates).toEqual(['theirs.yaml'])
  })
})
