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
import {
  ACTORS, READERS, REPRESENTATIVES, WRITERS, generateRows, generateSharedRows, generateWriteRows, renderRows, renderSharedRows,
  renderWriteRows, run, writeShareReaches,
} from './gen-rbac-matrix-rows.mjs'
import { parseAuthProfileInput } from '../src/lib/authProfile'
import { isValidPluginId } from '../src/lib/plugins/ids'

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
      const shared = join(dir, 'tests', 'fixtures', 'rbac_matrix', 'p4_generated.tsv')
      writeFileSync(out, 'stale\n')
      const log: string[] = []
      expect(run(['--check'], join(dir, 'webapp'), (l: string) => log.push(l))).toBe(1)
      expect(readFileSync(out, 'utf8')).toBe('stale\n')
      expect(run([], join(dir, 'webapp'), () => {})).toBe(0)
      expect(readFileSync(out, 'utf8')).toBe(renderRows(rows))
      expect(readFileSync(shared, 'utf8')).toBe(renderSharedRows(generateSharedRows(manifest, catalog)))
      expect(run(['--check'], join(dir, 'webapp'), () => {})).toBe(0)
      // --check covers the step 4.7 file too (routePermissions.test.ts runs it).
      writeFileSync(shared, 'stale\n')
      const sharedLog: string[] = []
      expect(run(['--check'], join(dir, 'webapp'), (l: string) => sharedLog.push(l))).toBe(1)
      expect(sharedLog.join('\n')).toMatch(/p4_generated\.tsv is out of date/)
      expect(readFileSync(shared, 'utf8')).toBe('stale\n')
      // ...and the step 5.2 file.
      expect(run([], join(dir, 'webapp'), () => {})).toBe(0)
      const write = join(dir, 'tests', 'fixtures', 'rbac_matrix', 'p5_generated.tsv')
      expect(readFileSync(write, 'utf8')).toBe(renderWriteRows(generateWriteRows(manifest, catalog)))
      writeFileSync(write, 'stale\n')
      const writeLog: string[] = []
      expect(run(['--check'], join(dir, 'webapp'), (l: string) => writeLog.push(l))).toBe(1)
      expect(writeLog.join('\n')).toMatch(/p5_generated\.tsv is out of date/)
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

  // A representative whose allowed request the route accepts would write (a PUT of `{}` upserts an
  // empty auth profile) or answer whatever the plugin runner says: the refusal must be the route's own.
  test("an allowed request is refused by the route's own validation, after the permission check", () => {
    const authProfile = REPRESENTATIVES['auth_profile:manage']
    expect(authProfile.allow).toBe('400;has=authType must be one of')
    expect(parseAuthProfileInput(JSON.parse(authProfile.body)).error).toMatch(/^authType must be one of /)

    const pluginLogs = REPRESENTATIVES['platform:plugins']
    const pluginId = /^\/api\/plugins\/([^/]+)\/logs$/.exec(pluginLogs.path)![1]
    expect(isValidPluginId(pluginId)).toBe(false)
    expect(pluginLogs.allow).toBe('400;has="code":"invalid_plugin_id"')
  })

  // A body naming the project under a key its route ignores reaches the guard with no project, which
  // answers 400 before the permission check: the deny row fails and the allow and off rows prove nothing.
  test('a body names its project under the key its route reads', () => {
    for (const [permission, r] of Object.entries(REPRESENTATIVES) as [string, { body: string; route: string }][]) {
      if (!r.body.includes('{P}')) continue
      const key = Object.entries(JSON.parse(r.body)).find(([, v]) => v === '{P}')![0]
      const route = readFileSync(join(WEBAPP, 'src', 'app', `${r.route}`, 'route.ts'), 'utf8')
      const reads = new RegExp(`\\bbody\\.${key}\\b`).test(route)
        || new RegExp(`const \\{[^}]*\\b${key}\\b[^}]*\\} = (parsed\\.)?body\\b`).test(route)
      expect(reads, `${permission}: ${r.route} reads ${key}`).toBe(true)
    }
  })

  // text-to-cypher refuses nothing itself after its permission check: it relays the agent, whose
  // request model requires a question, so the agent answers 422 before any model call.
  test('the assistants holder reaches the agent, which refuses the missing question', () => {
    const assistants = REPRESENTATIVES['agent:assistants']
    expect(JSON.parse(assistants.body)).not.toHaveProperty('question')
    expect(assistants.allow).toBe('422;has="upstreamStatus":422')
    const agent = readFileSync(join(WEBAPP, '..', 'agentic', 'api.py'), 'utf8')
    expect(agent).toMatch(/class TextToCypherRequest\(BaseModel\):\n(?: {4}"""[^\n]*"""\n)? {4}question: str\n/)
    const route = readFileSync(join(WEBAPP, 'src', 'app', 'api', 'agent', 'text-to-cypher', 'route.ts'), 'utf8')
    expect(route).toContain('upstreamStatus: resp.status')
  })

  describe('p4_generated.tsv: a reader at Read without Raw data (step 4.7)', () => {
    const shared: Row[] = generateSharedRows(manifest, catalog)
    type Reader = { actor: string; id: string; via: string; set: string; seeded: string; user: string; project: string }
    const readers = READERS as Reader[]
    const permissionOf = (row: Row) => row[0].replace(/^p4g-[a-z]+-/, '')
    const acting = (permission: string) => {
      const r = (REPRESENTATIVES as Record<string, { path: string; body: string }>)[permission]
      const text = r.path + r.body
      const e = catalog.permissions[permission]
      return e.kind === 'member' && e.scope === 'project' && e.level !== null && text.includes('{P}') && !/\{TMP\}|\{U\}/.test(text)
    }

    test('one row per reader and project representative: R answers as its holder, every other level 403 naming it', () => {
      const expected = Object.keys(REPRESENTATIVES).filter(acting)
      expect(shared).toHaveLength(readers.length * expected.length)
      for (const reader of readers) {
        const mine = shared.filter(r => r[0].startsWith(`p4g-${reader.id}-`))
        expect(mine.map(permissionOf)).toEqual(expected)
        for (const row of mine) {
          const permission = permissionOf(row)
          const level = catalog.permissions[permission].level
          const allow = (REPRESENTATIVES as Record<string, { allow: string }>)[permission].allow
          expect(row[6], row[0]).toBe(level === 'R' ? allow : `403;has=${permission}`)
          expect(row[2]).toBe(reader.actor)
          expect(row[1]).toBe('4.7')
          expect(row[7]).toMatch(/ probe:generated sharing:on$/)
        }
      }
    })

    // "No write route opens at read": every write level a route asks on a project has a refused row.
    test('every write-level project permission with a project representative is refused to the viewer; the rest are listed', () => {
      const writes = Object.keys(catalog.permissions).filter(p => {
        const e = catalog.permissions[p]
        return e.kind === 'member' && e.scope === 'project' && e.gatesExisting && e.level !== null && e.level !== 'R'
      })
      const refused = new Set(shared.filter(r => r[0].startsWith('p4g-viewer-') && r[6].startsWith('403;')).map(permissionOf))
      const missing = writes.filter(p => !refused.has(p)).sort()
      // Deleting uses a throwaway the viewer does not own (a refusal that failed would delete the shared
      // project); the other two representatives name no project. A permission with no representative
      // at all is listed with its reason in routePermissions.test.ts (NO_ROWS).
      expect(missing.filter(p => Object.hasOwn(REPRESENTATIVES, p))).toEqual(['agent:sessions', 'project:delete', 'scan:custom_templates'])
    })

    test("each row calls the reader's project, never its own, and the reader's set holds the permission", () => {
      for (const row of shared) {
        const reader = readers.find(r => row[0].startsWith(`p4g-${r.id}-`))!
        const keys = [...`${row[4]} ${row[5]}`.matchAll(/\$\{(\w+)\}/g)].map(m => m[1])
        expect(keys.length, row[0]).toBeGreaterThan(0)
        for (const k of keys) expect(k, row[0]).toBe(reader.project)
        const set = new Set(catalog.sets.find((s: { id: string }) => s.id === reader.set).permissions)
        expect(set.has(permissionOf(row)), row[0]).toBe(true)
      }
    })

    test('the oversight reader is the admin of the p3 rows, on the member project the baseline rows read', () => {
      const oversee = readers.find(r => r.via === 'oversight')!
      const admin = (ACTORS as { actor: string; user: string; kind: string }[]).find(a => a.actor === oversee.actor)!
      expect(admin.kind).toBe('admin')
      expect(oversee.user).toBe(admin.user)
      expect(oversee.project).toBe('PA_ID')
      expect(catalog.sets.find((s: { id: string }) => s.id === 'builtin:full-admin').permissions).toContain('projects:oversee')
    })

    // Step 4.4's seed creates the viewer with its Read share on PSHARED; until it lands the rows SKIP live
    // (sharing:on with no viewer to sign in), and this check waits for it.
    const seed = readFileSync(join(WEBAPP, 'scripts', 'e2e-rbac-seed.mjs'), 'utf8')
    test.skipIf(!seed.includes("key: 'VIEWER'"))('the seed creates the viewer with no set, sharing PSHARED read-only, and the runner signs it in', () => {
      const viewer = readers.find(r => r.via === 'share')!
      const line = new RegExp(`\\{ key: 'VIEWER',[^\\n]*`).exec(seed)?.[0] ?? ''
      expect(line).toContain("role: 'standard'")
      expect(line).not.toMatch(/sets:|adminProfileId:/)
      expect(viewer.seeded).toBe('default')
      expect(seed).toMatch(/PSHARED/)
      const runner = readFileSync(join(WEBAPP, '..', 'tests', 'rbac_matrix_live.sh'), 'utf8')
      expect(runner).toMatch(/\bviewer\b/)
    })

    test('every row has the runner\'s eight columns, and no id repeats a p3 row', () => {
      const lines = renderSharedRows(shared).split('\n').filter((l: string) => l && !l.startsWith('#'))
      for (const l of lines) expect(l.split('\t')).toHaveLength(8)
      const ids = new Set(rows.map(r => r[0]))
      for (const r of shared) expect(ids.has(r[0])).toBe(false)
      expect(new Set(shared.map(r => r[0])).size).toBe(shared.length)
    })
  })

  describe('p5_generated.tsv: the Read + Write collaborators (step 5.2)', () => {
    const written: Row[] = generateWriteRows(manifest, catalog)
    type Writer = { actor: string; id: string; set: string; user: string; project: string; toggles: Record<string, boolean>; off?: boolean }
    const writers = WRITERS as Writer[]
    const on = written.filter(r => r[7].endsWith('sharingwrite:on'))
    const off = written.filter(r => r[7].endsWith('sharingwrite:off'))
    const permissionOf = (row: Row) => row[0].replace(/^p5g-[a-z]+-(off-)?/, '')
    const levelOf = (row: Row) => catalog.permissions[permissionOf(row)].level as string
    const allowOf = (row: Row) => (REPRESENTATIVES as Record<string, { allow: string }>)[permissionOf(row)].allow

    test('editor allowed at W, viewer-like refused above it; toggle required; Manage-only refused at W; owner-only refused at M', () => {
      for (const row of on) {
        const writer = writers.find(w => row[0].startsWith(`p5g-${w.id}-`))!
        const level = levelOf(row)
        expect(row[6], row[0]).toBe(writeShareReaches(level, writer.toggles) ? allowOf(row) : `403;has=${permissionOf(row)}`)
      }
      const at = (id: string, permission: string) => on.find(r => r[0] === `p5g-${id}-${permission}`)![6]
      expect(at('editor', 'project:settings')).toMatch(/^400/)
      expect(at('editor', 'triage:mute')).toMatch(/^400/)
      expect(at('editor', 'graph:edit')).toBe('403;has=graph:edit')
      expect(at('coowner', 'graph:edit')).not.toMatch(/^403/)
      expect(at('coowner', 'project:export')).toBe('200')
      // Without the owner's consent (step 5.6) no toggle opens a run level, Manage included.
      for (const id of ['operator', 'redteamer', 'coowner']) expect(at(id, 'recon:scan')).toBe('403;has=recon:scan')
      expect(at('editor', 'recon:scan')).toBe('403;has=recon:scan')
    })

    test('the level table: R, R* and W always, M with Manage, never a run level or O without consent', () => {
      expect(['R', 'R*', 'W'].every(l => writeShareReaches(l, {}))).toBe(true)
      expect(writeShareReaches('M', {})).toBe(false)
      expect(writeShareReaches('M', { manage: true })).toBe(true)
      for (const l of ['W+S', 'W+A', 'W+X', 'O']) expect(writeShareReaches(l, { runScans: true, useAgent: true, exploit: true, manage: true })).toBe(false)
    })

    test('the switch-off rows: the editor reads as Read without Raw data, as p4\'s viewer', () => {
      const editorOff = off.filter(r => r[2] === 'editor')
      expect(editorOff.length).toBe(off.length)
      expect(editorOff.length).toBe(on.filter(r => r[2] === 'editor').length)
      for (const row of editorOff) expect(row[6], row[0]).toBe(levelOf(row) === 'R' ? allowOf(row) : `403;has=${permissionOf(row)}`)
    })

    test('every row calls PSHARED (member_c\'s), never PA or member_b, under sharing:on, with eight columns and unique ids', () => {
      for (const row of written) {
        const keys = [...`${row[4]} ${row[5]}`.matchAll(/\$\{(\w+)\}/g)].map(m => m[1])
        expect(keys.length, row[0]).toBeGreaterThan(0)
        for (const k of keys) expect(k, row[0]).toBe('PSHARED_ID')
        expect(row[7]).toMatch(/ sharing:on sharingwrite:(on|off)$/)
      }
      for (const l of renderWriteRows(written).split('\n').filter((x: string) => x && !x.startsWith('#'))) expect(l.split('\t')).toHaveLength(8)
      const ids = new Set([...rows, ...generateSharedRows(manifest, catalog)].map(r => r[0]))
      for (const r of written) expect(ids.has(r[0])).toBe(false)
      expect(new Set(written.map(r => r[0])).size).toBe(written.length)
    })

    test('the seed creates each writer with its write share and toggles on PSHARED, and the runner signs it in', () => {
      const seed = readFileSync(join(WEBAPP, 'scripts', 'e2e-rbac-seed.mjs'), 'utf8')
      const runner = readFileSync(join(WEBAPP, '..', 'tests', 'rbac_matrix_live.sh'), 'utf8')
      for (const w of writers) {
        const key = w.user.replace(/_ID$/, '')
        expect(seed, key).toMatch(new RegExp(`\\{ key: '${key}', email: 'rbac-[a-z-]+@e2e\\.local'`))
        const share = new RegExp(`\\{ project: 'PSHARED', user: '${key}', access: 'write'[^}]*\\}`).exec(seed)?.[0] ?? ''
        expect(share, key).not.toBe('')
        for (const t of ['runScans', 'useAgent', 'exploit', 'manage']) expect([key, t, share.includes(`${t}: true`)]).toEqual([key, t, w.toggles[t] === true])
        expect(runner).toMatch(new RegExp(`\\b${w.actor}\\b`))
      }
      expect(seed).not.toMatch(/ownerCredentialConsent/)
    })
  })

  test('every row has the runner\'s eight columns', () => {
    const lines = renderRows(rows).split('\n').filter((l: string) => l && !l.startsWith('#'))
    for (const l of lines) expect(l.split('\t')).toHaveLength(8)
  })
})
