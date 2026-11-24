/**
 * The custom Nuclei templates a person's Kali sandbox may hold (FU-6): the person's own and the
 * instance's (a null owner, or a file with no row), never another person's, as the template routes
 * judge them (`ownershipOf`). Only paths in the orchestrator's own shape are named, no symbolic link
 * is followed, and the list is bounded. The own and null-owner templates come from their rows, so
 * another member's flood of uploads never crowds them out (round 2). Prisma is a double; the folder
 * is a real temporary one.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sandbox/customTemplates.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const h = vi.hoisted(() => ({ rows: [] as Array<{ path: string; ownerUserId: string | null }>, reads: 0, down: false }))
vi.mock('@/lib/prisma', () => ({
  default: {
    nucleiTemplate: {
      findMany: async ({ where }: { where?: { path?: { in: string[] } } } = {}) => {
        h.reads += 1
        if (h.down) throw new Error('database unreachable')
        return where?.path ? h.rows.filter(r => where.path!.in.includes(r.path)) : h.rows
      },
    },
  },
}))

import { SANDBOX_TEMPLATES_MAX, WALK_MAX_ENTRIES, isSandboxTemplatePath, sandboxCustomTemplates } from './customTemplates'

let root: string
const put = (rel: string, body = 'id: t\n') => {
  mkdirSync(path.dirname(path.join(root, rel)), { recursive: true })
  writeFileSync(path.join(root, rel), body)
}

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), 'p4-templates-'))
  vi.stubEnv('NUCLEI_TEMPLATES_PATH', root)
  h.rows = []
  h.reads = 0
  h.down = false
})
afterEach(() => {
  vi.unstubAllEnvs()
  rmSync(root, { recursive: true, force: true })
})

describe('whose templates', () => {
  beforeEach(() => {
    put('bob/mine.yaml')
    put('carol/theirs.yaml')
    put('shared/instance.yaml')
    put('loose.yml')
    put('admin/acting.yaml')
    h.rows = [
      { path: 'bob/mine.yaml', ownerUserId: 'bob' },
      { path: 'carol/theirs.yaml', ownerUserId: 'carol' },
      { path: 'shared/instance.yaml', ownerUserId: null },
      { path: 'admin/acting.yaml', ownerUserId: 'admin-x' },
    ]
  })

  test("the person's own and the instance's (a null owner, or no row), sorted; never another person's", async () => {
    expect(await sandboxCustomTemplates('bob')).toEqual(['bob/mine.yaml', 'loose.yml', 'shared/instance.yaml'])
    expect(await sandboxCustomTemplates('carol')).toEqual(['carol/theirs.yaml', 'loose.yml', 'shared/instance.yaml'])
  })

  test('a person with none of their own gets the instance templates only', async () => {
    expect(await sandboxCustomTemplates('dave')).toEqual(['loose.yml', 'shared/instance.yaml'])
  })
})

describe('the folder: never more than the orchestrator would copy, never outside it', () => {
  test('no folder: none, and no database read; an empty one: none', async () => {
    rmSync(root, { recursive: true, force: true })
    expect(await sandboxCustomTemplates('bob')).toEqual([])
    expect(h.reads).toBe(0)
    mkdirSync(root)
    h.rows = [{ path: 'gone.yaml', ownerUserId: 'bob' }]
    expect(await sandboxCustomTemplates('bob')).toEqual([])
  })

  test('a row is used only for a plain file: never a link, a file under a linked folder, or a missing one', async () => {
    const outside = mkdtempSync(path.join(tmpdir(), 'p4-outside-'))
    try {
      writeFileSync(path.join(outside, 'secret.yaml'), 'id: s\n')
      symlinkSync(path.join(outside, 'secret.yaml'), path.join(root, 'link.yaml'))
      symlinkSync(outside, path.join(root, 'linked-dir'))
      put('bob/real.yaml')
      h.rows = [
        { path: 'link.yaml', ownerUserId: 'bob' },
        { path: 'linked-dir/secret.yaml', ownerUserId: null },
        { path: 'bob/real.yaml', ownerUserId: 'bob' },
        { path: 'bob/missing.yaml', ownerUserId: 'bob' },
        { path: '../escape.yaml', ownerUserId: null },
      ]
      expect(await sandboxCustomTemplates('bob')).toEqual(['bob/real.yaml'])
    } finally {
      rmSync(outside, { recursive: true, force: true })
    }
  })

  test("another member's flood of uploads never crowds out the person's own or the instance's templates", async () => {
    // One level down, while bob's templates sit two levels down: a breadth-first walk that counted
    // these would spend its whole budget before reaching them, whatever order the folder lists in.
    const bulk = path.join(root, 'aaa-carol-bulk')
    mkdirSync(bulk, { recursive: true })
    for (let i = 0; i < WALK_MAX_ENTRIES + 10; i++) {
      const name = `t${String(i).padStart(6, '0')}.yaml`
      writeFileSync(path.join(bulk, name), 'id: c\n')
      h.rows.push({ path: `aaa-carol-bulk/${name}`, ownerUserId: 'carol' })
    }
    put('zz-bob/web/mine.yaml')
    put('zz-shared/web/instance.yaml')
    h.rows.push({ path: 'zz-bob/web/mine.yaml', ownerUserId: 'bob' }, { path: 'zz-shared/web/instance.yaml', ownerUserId: null })
    const out = await sandboxCustomTemplates('bob')
    expect(out).toEqual(['zz-bob/web/mine.yaml', 'zz-shared/web/instance.yaml'])
  }, 60_000)

  test('a database failure is the ensure\'s failure, never an empty list', async () => {
    put('a.yaml')
    h.down = true
    await expect(sandboxCustomTemplates('bob')).rejects.toThrow('database unreachable')
  })

  test('only template files of plain segments: no hidden file, no other file, no odd name, at most 8 deep', async () => {
    put('ok/a.yaml')
    put('.hidden.yaml')
    put('.git/b.yaml')
    put('notes.txt')
    put('with space/c.yaml')
    put('1/2/3/4/5/6/7/deep.yaml')
    put('1/2/3/4/5/6/7/8/too-deep.yaml')
    expect(await sandboxCustomTemplates('bob')).toEqual(['1/2/3/4/5/6/7/deep.yaml', 'ok/a.yaml'])
  })

  test('a symbolic link, to a file or a folder outside, is never followed', async () => {
    const outside = mkdtempSync(path.join(tmpdir(), 'p4-outside-'))
    try {
      writeFileSync(path.join(outside, 'secret.yaml'), 'id: s\n')
      symlinkSync(path.join(outside, 'secret.yaml'), path.join(root, 'link.yaml'))
      symlinkSync(outside, path.join(root, 'linked-dir'))
      put('real.yaml')
      expect(await sandboxCustomTemplates('bob')).toEqual(['real.yaml'])
    } finally {
      rmSync(outside, { recursive: true, force: true })
    }
  })

  test(`at most ${SANDBOX_TEMPLATES_MAX} paths`, async () => {
    for (let i = 0; i < SANDBOX_TEMPLATES_MAX + 5; i++) put(`bulk/t${String(i).padStart(5, '0')}.yaml`)
    const out = await sandboxCustomTemplates('bob')
    expect(out).toHaveLength(SANDBOX_TEMPLATES_MAX)
    expect(out[0]).toBe('bulk/t00000.yaml')
  })

  test('the path rule is the orchestrator\'s: relative, plain segments, a template file', () => {
    for (const ok of ['a.yaml', 'x/y.YML', 'a-b/c_d/e.f.yaml']) expect(isSandboxTemplatePath(ok), ok).toBe(true)
    for (const bad of ['../x.yaml', '/abs.yaml', 'a/../b.yaml', 'a/./b.yaml', 'a\\\\b.yaml', 'x.txt', '.h.yaml', 'a//b.yaml', '1/2/3/4/5/6/7/8/9.yaml', 'a b.yaml']) {
      expect(isSandboxTemplatePath(bad), bad).toBe(false)
    }
  })
})
