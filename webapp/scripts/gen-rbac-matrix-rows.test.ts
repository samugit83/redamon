/**
 * The live-row generator (scripts/gen-rbac-matrix-rows.mjs, step 3.8): its rows are only as good as
 * the route each one calls, so a representative the manifest does not back fails the run, and the
 * accounts are picked from what their built-in set holds, never by hand.
 *
 * Run: npx vitest run scripts/gen-rbac-matrix-rows.test.ts
 *
 * @vitest-environment node
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test, expect } from 'vitest'
import { ACTORS, REPRESENTATIVES, generateRows, renderRows, run } from './gen-rbac-matrix-rows.mjs'

const WEBAPP = join(__dirname, '..')
const manifest = JSON.parse(readFileSync(join(WEBAPP, 'src/lib/authz/routeManifest.json'), 'utf8'))
const catalog = JSON.parse(readFileSync(join(WEBAPP, 'src/lib/authz/permissionCatalog.json'), 'utf8'))
type Row = string[]

describe('gen-rbac-matrix-rows', () => {
  const rows: Row[] = generateRows(manifest, catalog)

  test('three rows per permission: the holder allowed, the account without it refused (switch on) and allowed (switch off)', () => {
    expect(rows).toHaveLength(Object.keys(REPRESENTATIVES).length * 3)
    for (const permission of Object.keys(REPRESENTATIVES)) {
      const [allow, deny, off] = rows.filter(r => r[0].startsWith(`p3g-${permission}-`))
      expect([allow[0], deny[0], off[0]]).toEqual([`p3g-${permission}-allow`, `p3g-${permission}-deny`, `p3g-${permission}-off`])
      expect(deny[6]).toBe(`403;has=${permission}`)
      expect(deny[7]).toMatch(/ permissions:on$/)
      expect(off[7]).toMatch(/ permissions:off$/)
      expect(allow[7]).not.toMatch(/permissions:/)
      expect([off[2], off[4], off[6]]).toEqual([deny[2], deny[4], allow[6]])
    }
  })

  test('the holder holds the permission and the other account lacks it, by their built-in sets', () => {
    const setOf = (actor: string) => new Set(catalog.sets.find((s: { id: string }) => s.id === ACTORS.find((a: { actor: string }) => a.actor === actor)!.set).permissions)
    for (const [id, , actor] of rows) {
      const permission = id.replace(/^p3g-/, '').replace(/-(allow|deny|off)$/, '')
      expect(setOf(actor).has(permission), `${id} as ${actor}`).toBe(id.endsWith('-allow'))
    }
  })

  test("each row calls a project its actor owns, or its own account, by the seed's keys", () => {
    for (const [id, , actor, , path, body] of rows) {
      const a = ACTORS.find((x: { actor: string }) => x.actor === actor)!
      const keys = [...`${path} ${body}`.matchAll(/\$\{(\w+)\}/g)].map(m => m[1])
      for (const k of keys) expect([a.project, a.tmp, a.user], `${id}: ${k}`).toContain(k)
    }
  })

  test('a member permission is proved with members, an administration or platform one with admins (step 3.9)', () => {
    for (const [id, , actor] of rows) {
      const permission = id.replace(/^p3g-/, '').replace(/-(allow|deny|off)$/, '')
      const a = ACTORS.find((x: { actor: string }) => x.actor === actor)!
      expect(a.kind, `${id} as ${actor}`).toBe(catalog.permissions[permission].kind)
    }
  })

  test('a representative the manifest gives another permission fails the run, naming it', () => {
    const moved = manifest.map((e: { path: string }) => (e.path === '/api/recon/[projectId]/start' ? { ...e, permission: 'recon:read' } : e))
    expect(() => generateRows(moved, catalog)).toThrow(/recon:scan: the manifest gives POST \/api\/recon\/\[projectId\]\/start recon:read/)
    const gone = manifest.filter((e: { path: string }) => e.path !== '/api/presets')
    expect(() => generateRows(gone, catalog)).toThrow(/self:presets: the manifest gives GET \/api\/presets no permission/)
  })

  test('a permission every seeded account holds (or none does) fails the run', () => {
    const all = { ...catalog, sets: catalog.sets.map((s: { permissions: string[] }) => ({ ...s, permissions: [...s.permissions, 'recon:scan'] })) }
    expect(() => generateRows(manifest, all)).toThrow(/recon:scan: no seeded account lacks it/)
  })

  test('--check fails on a stale file and writes nothing; a run writes it, then --check passes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'rbac-rows-'))
    try {
      mkdirSync(join(dir, 'webapp', 'src', 'lib', 'authz'), { recursive: true })
      mkdirSync(join(dir, 'tests', 'fixtures', 'rbac_matrix'), { recursive: true })
      for (const f of ['routeManifest.json', 'permissionCatalog.json']) {
        writeFileSync(join(dir, 'webapp', 'src', 'lib', 'authz', f), readFileSync(join(WEBAPP, 'src', 'lib', 'authz', f)))
      }
      const out = join(dir, 'tests', 'fixtures', 'rbac_matrix', 'p3_generated.tsv')
      writeFileSync(out, 'stale\n')
      const log: string[] = []
      expect(run(['--check'], join(dir, 'webapp'), (l: string) => log.push(l))).toBe(1)
      expect(readFileSync(out, 'utf8')).toBe('stale\n')
      expect(run([], join(dir, 'webapp'), () => {})).toBe(0)
      expect(readFileSync(out, 'utf8')).toBe(renderRows(rows))
      expect(run(['--check'], join(dir, 'webapp'), () => {})).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('the seed creates each actor on its set, owning the projects the rows call, and the runner signs it in', () => {
    const seed = readFileSync(join(WEBAPP, 'scripts', 'e2e-rbac-seed.mjs'), 'utf8')
    const runner = readFileSync(join(WEBAPP, '..', 'tests', 'rbac_matrix_live.sh'), 'utf8')
    const userKeys = /user_key\(\)[\s\S]*?\n\s*([a-z_|]+)\) echo "\$\{1\^\^\}" ;;/.exec(runner)![1].split('|')
    for (const a of ACTORS as { actor: string; kind: string; set: string; seeded: string; user: string; project: string | null; tmp: string | null }[]) {
      const key = a.actor.toUpperCase()
      const line = new RegExp(`\\{ key: '${key}',[^\\n]*`).exec(seed)?.[0] ?? ''
      expect(a.user).toBe(`${key}_ID`)
      if (a.seeded === 'sets') expect(line, `${a.actor} is seeded on ${a.set}`).toContain(`sets: ['${a.set}']`)
      if (a.seeded === 'profile') expect(line, `${a.actor} is seeded on ${a.set}`).toContain(`adminProfileId: '${a.set}'`)
      if (a.seeded === 'default') {
        // No assignment: a member resolves to Default member, an admin without a profile to Full admin.
        expect(line, `${a.actor} is seeded with no set`).not.toMatch(/sets:|adminProfileId:/)
        expect(a.set).toBe(a.kind === 'admin' ? 'builtin:full-admin' : 'builtin:default-member')
      }
      expect(line, `${a.actor} is seeded as ${a.kind === 'admin' ? 'an admin' : 'a member'}`).toContain(`role: '${a.kind === 'admin' ? 'admin' : 'standard'}'`)
      for (const p of [a.project, a.tmp].filter(Boolean) as string[]) {
        expect(seed, `${p} is owned by ${a.actor}`).toMatch(new RegExp(`key: '${p.replace(/_ID$/, '')}', owner: '${key}'`))
      }
      expect(userKeys, `the runner signs ${a.actor} in`).toContain(a.actor)
    }
  })

  test('every row has the runner\'s eight columns', () => {
    const lines = renderRows(rows).split('\n').filter((l: string) => l && !l.startsWith('#'))
    for (const l of lines) expect(l.split('\t')).toHaveLength(8)
  })
})
