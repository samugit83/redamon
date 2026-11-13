/**
 * Nuclei templates have owners (HD-08, F-07). Before, every signed-in account listed,
 * overwrote and deleted every file of the shared templates folder, so a member could
 * replace the template another member's scans run. Now a new path belongs to the
 * effective user who uploads it; a path owned by someone else, or by the instance (a
 * row with no owner, or a file with no row), answers 409 template_owned_by_other unless
 * an account that manages every template (an admin) asks to overwrite; only the owner
 * or such an account deletes; only such an account promotes a file to the instance.
 * Each of the three writes refuses a page of another site (403 cross_origin) before it
 * reads anything else, the multipart upload included: SameSite=lax alone lets a
 * same-site page post a form here.
 *
 * The route, the ownership helpers, sharedTools and the filesystem are real (a
 * throwaway folder); Prisma is an in-memory table, the session and the principal are
 * doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/nuclei-templates/route.ownership.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterAll } from 'vitest'
import { NextRequest } from 'next/server'
import { existsSync } from 'fs'
import { mkdir, readFile, rm, writeFile } from 'fs/promises'
import path from 'path'

type Row = {
  id: string; path: string; ownerUserId: string | null; sha256: string | null; sizeBytes: number | null
  promotedById: string | null; createdAt: Date; updatedAt: Date
}
type Audit = { actorId: string | null; action: string; targetType: string; targetId: string | null; before?: unknown; after?: unknown }
type Principal = { id: string; email: string; role: string; hasPassword: boolean; createdAt: Date; legacyGrants: string[] }

const h = vi.hoisted(() => {
  const root = `${process.env.TMPDIR || '/tmp'}/redamon-nuclei-owners-${process.pid}-${Date.now()}`
  process.env.NUCLEI_TEMPLATES_PATH = root
  return {
    root,
    rows: [] as Row[],
    audit: [] as Audit[],
    principals: new Map<string, Principal>(),
    session: null as { userId: string; role: string } | null,
    actingAs: null as string | null,
    beforeCreate: null as null | (() => void),
  }
})

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/session', () => ({
  requireSession: async () => {
    const { NextResponse } = await import('next/server')
    return h.session ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  },
  getEffectiveUser: async () => (h.session ? { userId: h.actingAs ?? h.session.userId } : null),
}))
vi.mock('@/lib/authz/principal', () => ({ loadPrincipal: async (id: string) => h.principals.get(id) ?? null }))
vi.mock('@/lib/prisma', async () => {
  const { Prisma } = await import('@prisma/client')
  const pick = (row: Row, select?: Record<string, boolean>) =>
    select ? Object.fromEntries(Object.keys(select).filter(k => select[k]).map(k => [k, row[k as keyof Row]])) : { ...row }
  let seq = 0
  const make = (data: Partial<Row>): Row => ({
    id: `t${++seq}`, ownerUserId: null, sha256: null, sizeBytes: null, promotedById: null,
    createdAt: new Date(), updatedAt: new Date(), path: '', ...data,
  })
  const nucleiTemplate = {
    findUnique: async ({ where, select }: { where: { path: string }; select?: Record<string, boolean> }) => {
      const row = h.rows.find(r => r.path === where.path)
      return row ? pick(row, select) : null
    },
    findMany: async ({ select }: { select?: Record<string, boolean> } = {}) => h.rows.map(r => pick(r, select)),
    create: async ({ data }: { data: Partial<Row> }) => {
      h.beforeCreate?.()
      if (h.rows.some(r => r.path === data.path)) {
        throw new Prisma.PrismaClientKnownRequestError('Unique constraint failed on the fields: (`path`)', { code: 'P2002', clientVersion: 'test' })
      }
      const row = make(data)
      h.rows.push(row)
      return { ...row }
    },
    upsert: async ({ where, create, update }: { where: { path: string }; create: Partial<Row>; update: Partial<Row> }) => {
      const row = h.rows.find(r => r.path === where.path)
      if (row) { Object.assign(row, update, { updatedAt: new Date() }); return { ...row } }
      const made = make(create)
      h.rows.push(made)
      return { ...made }
    },
    update: async ({ where, data }: { where: { path: string }; data: Partial<Row> }) => {
      const row = h.rows.find(r => r.path === where.path)
      if (!row) throw new Prisma.PrismaClientKnownRequestError('Record to update not found.', { code: 'P2025', clientVersion: 'test' })
      Object.assign(row, data, { updatedAt: new Date() })
      return { ...row }
    },
    deleteMany: async ({ where }: { where: { path: string; ownerUserId?: string } }) => {
      const before = h.rows.length
      h.rows = h.rows.filter(r => !(r.path === where.path && (where.ownerUserId === undefined || r.ownerUserId === where.ownerUserId)))
      return { count: before - h.rows.length }
    },
  }
  return {
    default: {
      nucleiTemplate,
      user: {
        findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
          [...h.principals.values()].filter(p => where.id.in.includes(p.id)).map(p => ({ id: p.id, email: p.email })),
      },
      auditLog: {
        create: async ({ data }: { data: Audit }) => { h.audit.push(data); return data },
        findFirst: async ({ where }: { where: { action: string } }) =>
          (where.action === 'system.rbac_legacy_grants_cutoff' ? { createdAt: new Date('2026-11-11T08:00:00Z') } : null),
      },
    },
  }
})

import { GET, POST, DELETE, PATCH } from './route'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

const BEFORE_UPGRADE = new Date('2026-01-01T00:00:00Z')
const AFTER_UPGRADE = new Date('2026-11-11T09:00:00Z')

function principal(id: string, role: 'admin' | 'standard', createdAt = AFTER_UPGRADE) {
  h.principals.set(id, { id, email: `${id}@e2e.local`, role, hasPassword: true, createdAt, legacyGrants: [] })
}
function signIn(id: string, actingAs: string | null = null) {
  h.session = { userId: id, role: h.principals.get(id)!.role }
  h.actingAs = actingAs
}
const template = (id: string) => `id: ${id}\ninfo:\n  name: ${id}\n  severity: low\n`

function upload(name: string, content: string, fields: Record<string, string> = {}) {
  const form = new FormData()
  form.append('file', new File([content], name))
  for (const [k, v] of Object.entries(fields)) form.append(k, v)
  return POST(new NextRequest('http://localhost/api/nuclei-templates', { method: 'POST', body: form }))
}
const del = (p: string) =>
  DELETE(new NextRequest(`http://localhost/api/nuclei-templates?path=${encodeURIComponent(p)}`, { method: 'DELETE' }))
const promote = (body: unknown) =>
  PATCH(new NextRequest('http://localhost/api/nuclei-templates', {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }))
const list = async () => (await (await GET()).json()) as { templates: { path: string; ownership: string; owner?: string | null }[]; canManageAll: boolean }
const onDisk = (p: string) => readFile(path.join(h.root, p), 'utf-8')
const rowOf = (p: string) => h.rows.find(r => r.path === p)
const actions = () => h.audit.map(a => a.action)

beforeEach(async () => {
  await rm(h.root, { recursive: true, force: true })
  await mkdir(h.root, { recursive: true })
  h.rows = []
  h.audit = []
  h.principals.clear()
  h.session = null
  h.actingAs = null
  h.beforeCreate = null
  vi.unstubAllEnvs()
  resetSharedToolsForTests()
  principal('member-a', 'standard')
  principal('member-b', 'standard')
  principal('admin-1', 'admin')
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

afterAll(async () => {
  await rm(h.root, { recursive: true, force: true })
})

describe('upload', () => {
  test('member upload new: the path becomes the member\'s template', async () => {
    signIn('member-a')
    const res = await upload('mine.yaml', template('mine'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.uploaded).toEqual({ name: 'mine.yaml', path: 'mine.yaml', id: 'mine' })
    expect(body.templates).toEqual([expect.objectContaining({ path: 'mine.yaml', ownership: 'own' })])
    expect(rowOf('mine.yaml')).toMatchObject({ ownerUserId: 'member-a', sizeBytes: template('mine').length })
    expect(rowOf('mine.yaml')!.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(h.audit).toEqual([expect.objectContaining({
      actorId: 'member-a', action: 'nuclei_template.upload', targetType: 'nuclei_template', targetId: 'mine.yaml',
      after: expect.objectContaining({ ownerUserId: 'member-a' }),
    })])
  })

  test('a template in a subfolder is keyed by its normalized relative path', async () => {
    signIn('member-a')
    const res = await upload('x.yml', template('x'), { subdir: '/team/web/' })
    expect(res.status).toBe(200)
    expect((await res.json()).uploaded.path).toBe('team/web/x.yaml')
    expect(rowOf('team/web/x.yaml')?.ownerUserId).toBe('member-a')
  })

  test('the owner replaces their own template', async () => {
    signIn('member-a')
    await upload('mine.yaml', template('v1'))
    const res = await upload('mine.yaml', template('v2'))
    expect(res.status).toBe(200)
    expect(await onDisk('mine.yaml')).toContain('id: v2')
    expect(rowOf('mine.yaml')?.ownerUserId).toBe('member-a')
    expect(h.rows).toHaveLength(1)
  })

  test("member overwrite of another's refused: 409, the file and the owner unchanged", async () => {
    signIn('member-a')
    await upload('x.yaml', template('a'))
    signIn('member-b')
    const res = await upload('x.yaml', template('b'))
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'template_owned_by_other', path: 'x.yaml', ownership: 'other' })
    expect(body.error).toMatch(/belongs to another account/)
    expect(await onDisk('x.yaml')).toContain('id: a')
    expect(rowOf('x.yaml')?.ownerUserId).toBe('member-a')
    expect(actions()).toEqual(['nuclei_template.upload'])
  })

  test('member overwrite of instance refused: a row with no owner', async () => {
    await writeFile(path.join(h.root, 'shipped.yaml'), template('shipped'))
    h.rows.push({ id: 'r1', path: 'shipped.yaml', ownerUserId: null, sha256: null, sizeBytes: null, promotedById: null, createdAt: new Date(), updatedAt: new Date() })
    signIn('member-b')
    const res = await upload('shipped.yaml', template('evil'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'template_owned_by_other', ownership: 'instance' })
    expect(await onDisk('shipped.yaml')).toContain('id: shipped')
  })

  test('member overwrite of instance refused: a file added on the host has no row and is the instance\'s', async () => {
    await writeFile(path.join(h.root, 'host.yaml'), template('host'))
    signIn('member-a')
    const res = await upload('host.yaml', template('evil'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ ownership: 'instance' })
    expect(await onDisk('host.yaml')).toContain('id: host')
    expect(h.rows).toEqual([])
  })

  test('the overwrite flag means nothing to a member', async () => {
    signIn('member-a')
    await upload('x.yaml', template('a'))
    signIn('member-b')
    expect((await upload('x.yaml', template('b'), { overwrite: 'true' })).status).toBe(409)
    expect(await onDisk('x.yaml')).toContain('id: a')
  })

  test('admin overwrite with flag: the content changes, the owner stays', async () => {
    signIn('member-a')
    await upload('x.yaml', template('a'))
    signIn('admin-1')
    expect((await upload('x.yaml', template('fixed'))).status).toBe(409)
    const res = await upload('x.yaml', template('fixed'), { overwrite: 'true' })
    expect(res.status).toBe(200)
    expect(await onDisk('x.yaml')).toContain('id: fixed')
    expect(rowOf('x.yaml')?.ownerUserId).toBe('member-a')
    expect(h.audit.at(-1)).toMatchObject({
      actorId: 'admin-1', action: 'nuclei_template.upload',
      before: { ownerUserId: 'member-a' }, after: expect.objectContaining({ ownerUserId: 'member-a', replacedAs: 'admin' }),
    })
  })

  test('admin overwrite of a host file records it as an instance template', async () => {
    await writeFile(path.join(h.root, 'host.yaml'), template('host'))
    signIn('admin-1')
    expect((await upload('host.yaml', template('v2'), { overwrite: 'true' })).status).toBe(200)
    expect(rowOf('host.yaml')).toMatchObject({ ownerUserId: null })
  })

  test('an admin acting as a member uploads as that member', async () => {
    signIn('admin-1', 'member-a')
    expect((await upload('as-a.yaml', template('as-a'))).status).toBe(200)
    expect(rowOf('as-a.yaml')?.ownerUserId).toBe('member-a')
    // The audit names the person who did it.
    expect(h.audit.at(-1)).toMatchObject({ actorId: 'admin-1', after: expect.objectContaining({ ownerUserId: 'member-a' }) })
  })

  test('two uploads of the same new path: the second claim loses and is refused', async () => {
    signIn('member-b')
    // member-a's upload claims the row between member-b's read and member-b's claim.
    h.beforeCreate = () => {
      h.beforeCreate = null
      h.rows.push({ id: 'race', path: 'race.yaml', ownerUserId: 'member-a', sha256: null, sizeBytes: null, promotedById: null, createdAt: new Date(), updatedAt: new Date() })
    }
    const res = await upload('race.yaml', template('b'))
    expect(res.status).toBe(409)
    expect(existsSync(path.join(h.root, 'race.yaml'))).toBe(false)
    expect(rowOf('race.yaml')?.ownerUserId).toBe('member-a')
  })

  test('a failed write gives the claimed path back', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('member-a')
    await writeFile(path.join(h.root, 'blocked'), 'a file where the subdirectory should be')
    const res = await upload('t.yaml', template('t'), { subdir: 'blocked' })
    expect(res.status).toBe(500)
    expect(h.rows).toEqual([])
  })

  test('the size cap and the content checks run before any row is claimed', async () => {
    signIn('member-a')
    expect((await upload('bad.yaml', 'not a template')).status).toBe(400)
    expect((await upload('bad.txt', template('t'))).status).toBe(400)
    expect(h.rows).toEqual([])
  })
})

describe('list', () => {
  async function seedThree() {
    signIn('member-a')
    await upload('a.yaml', template('a'))
    signIn('member-b')
    await upload('b.yaml', template('b'))
    await writeFile(path.join(h.root, 'host.yaml'), template('host'))
  }

  test("GET hides others' for members: own and instance only", async () => {
    await seedThree()
    signIn('member-a')
    const body = await list()
    expect(body.templates.map(t => [t.path, t.ownership])).toEqual([['a.yaml', 'own'], ['host.yaml', 'instance']])
    expect(body.templates.every(t => !('owner' in t))).toBe(true)
    expect(body.canManageAll).toBe(false)
  })

  test("an admin sees every template, others' with the owner's email", async () => {
    await seedThree()
    signIn('admin-1')
    const body = await list()
    expect(body.canManageAll).toBe(true)
    expect(body.templates.map(t => [t.path, t.ownership, t.owner])).toEqual([
      ['a.yaml', 'other', 'member-a@e2e.local'],
      ['b.yaml', 'other', 'member-b@e2e.local'],
      ['host.yaml', 'instance', undefined],
    ])
  })

  test('a template whose owner account is gone shows no owner, and stays hidden from members', async () => {
    await seedThree()
    h.principals.delete('member-b')
    signIn('admin-1')
    expect((await list()).templates.find(t => t.path === 'b.yaml')).toMatchObject({ ownership: 'other', owner: null })
    signIn('member-a')
    expect((await list()).templates.map(t => t.path)).not.toContain('b.yaml')
  })

  test('an admin acting as a member sees that member\'s templates as theirs', async () => {
    await seedThree()
    signIn('admin-1', 'member-b')
    expect((await list()).templates.find(t => t.path === 'b.yaml')?.ownership).toBe('own')
  })

  test('a pre-upgrade member under the escape hatch sees all, and the use is recorded', async () => {
    await seedThree()
    vi.stubEnv('REDAMON_SHARED_TOOLS_COMPAT', 'true')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    principal('old-member', 'standard', BEFORE_UPGRADE)
    signIn('old-member')
    const body = await list()
    expect(body.canManageAll).toBe(true)
    expect(body.templates).toHaveLength(3)
    expect(warn.mock.calls.map(c => String(c[0]))).toContain('[rbac] shared-tools compat used user=old-member tool=nuclei_templates_all')
    expect(actions()).toContain('rbac.compat_used')
  })

  test('without a session: 401 and nothing read', async () => {
    const res = await GET()
    expect(res.status).toBe(401)
  })
})

describe('delete', () => {
  test("member delete of another's refused: 403 forbidden, the file and row kept", async () => {
    signIn('member-a')
    await upload('a.yaml', template('a'))
    signIn('member-b')
    const res = await del('a.yaml')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'platform:nuclei_templates' })
    expect(existsSync(path.join(h.root, 'a.yaml'))).toBe(true)
    expect(rowOf('a.yaml')).toBeDefined()
    expect(actions()).not.toContain('nuclei_template.delete')
  })

  test('member delete of an instance template refused, with or without a row', async () => {
    await writeFile(path.join(h.root, 'host.yaml'), template('host'))
    signIn('member-a')
    const res = await del('host.yaml')
    expect(res.status).toBe(403)
    expect((await res.json()).error).toMatch(/administrator/)
    expect(existsSync(path.join(h.root, 'host.yaml'))).toBe(true)
  })

  test('the owner deletes their own: file and row gone, audited', async () => {
    signIn('member-a')
    await upload('a.yaml', template('a'), { subdir: 'mine' })
    const res = await del('mine/a.yaml')
    expect(res.status).toBe(200)
    expect(existsSync(path.join(h.root, 'mine'))).toBe(false)
    expect(h.rows).toEqual([])
    expect(h.audit.at(-1)).toMatchObject({ actorId: 'member-a', action: 'nuclei_template.delete', targetId: 'mine/a.yaml', before: { ownerUserId: 'member-a' } })
  })

  test("an admin deletes another's template and an instance template", async () => {
    signIn('member-a')
    await upload('a.yaml', template('a'))
    await writeFile(path.join(h.root, 'host.yaml'), template('host'))
    signIn('admin-1')
    expect((await del('a.yaml')).status).toBe(200)
    expect((await del('host.yaml')).status).toBe(200)
    expect(existsSync(path.join(h.root, 'a.yaml'))).toBe(false)
    expect(existsSync(path.join(h.root, 'host.yaml'))).toBe(false)
  })

  test('a path that holds nothing answers the list, as before', async () => {
    signIn('member-a')
    const res = await del('nothing.yaml')
    expect(res.status).toBe(200)
    expect(h.audit).toEqual([])
  })
})

describe('promote', () => {
  test("admin promote: the member's file becomes an instance template every member sees", async () => {
    signIn('member-a')
    await upload('a.yaml', template('a'))
    signIn('admin-1')
    const res = await promote({ path: 'a.yaml', promote: true })
    expect(res.status).toBe(200)
    expect((await res.json()).promoted).toBe(true)
    expect(rowOf('a.yaml')).toMatchObject({ ownerUserId: null, promotedById: 'admin-1' })
    expect(h.audit.at(-1)).toMatchObject({
      actorId: 'admin-1', action: 'nuclei_template.promote', targetId: 'a.yaml',
      before: { ownerUserId: 'member-a' }, after: { ownerUserId: null, promotedById: 'admin-1' },
    })
    signIn('member-b')
    expect((await list()).templates.find(t => t.path === 'a.yaml')?.ownership).toBe('instance')
    // ...and is now the instance's: its former owner can no longer replace it.
    signIn('member-a')
    expect((await upload('a.yaml', template('again'))).status).toBe(409)
  })

  test('a member cannot promote, not even their own: 403 before the body is read', async () => {
    signIn('member-a')
    await upload('a.yaml', template('a'))
    const res = await promote({ path: 'a.yaml', promote: true })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'platform:nuclei_templates' })
    expect(rowOf('a.yaml')?.ownerUserId).toBe('member-a')
    expect((await promote('not json at all')).status).toBe(403)
  })

  test('a template that does not exist is 404; one already of the instance is no change', async () => {
    signIn('admin-1')
    const missing = await promote({ path: 'nothing.yaml', promote: true })
    expect(missing.status).toBe(404)
    expect((await missing.json()).code).toBe('template_not_found')
    await writeFile(path.join(h.root, 'host.yaml'), template('host'))
    const same = await promote({ path: 'host.yaml', promote: true })
    expect(same.status).toBe(200)
    expect((await same.json()).promoted).toBe(false)
    expect(actions()).not.toContain('nuclei_template.promote')
  })

  test('a body without promote: true, or an unsafe path, is 400', async () => {
    signIn('admin-1')
    expect((await promote({ path: 'a.yaml' })).status).toBe(400)
    expect((await promote({ path: '../etc/x.yaml', promote: true })).status).toBe(400)
  })
})

describe('same origin: a page of another site cannot drive a write', () => {
  const OTHER_SITE = { Origin: 'https://rbac-other-site.example' }
  const SAME_SITE = { Origin: 'http://localhost' }
  const uploadFrom = (headers: Record<string, string>, name: string, content: string) => {
    const form = new FormData()
    form.append('file', new File([content], name))
    return POST(new NextRequest('http://localhost/api/nuclei-templates', { method: 'POST', body: form, headers }))
  }
  const deleteFrom = (headers: Record<string, string>, p: string) =>
    DELETE(new NextRequest(`http://localhost/api/nuclei-templates?path=${encodeURIComponent(p)}`, { method: 'DELETE', headers }))
  const promoteFrom = (headers: Record<string, string>, body: unknown) =>
    PATCH(new NextRequest('http://localhost/api/nuclei-templates', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
    }))
  const refusedCrossOrigin = async (res: Response) => {
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
  }

  test('a cross-origin multipart upload is 403 cross_origin: no file, no row, no audit', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    signIn('member-a')
    await refusedCrossOrigin(await uploadFrom(OTHER_SITE, 'evil.yaml', template('evil')))
    expect(existsSync(path.join(h.root, 'evil.yaml'))).toBe(false)
    expect(h.rows).toEqual([])
    expect(h.audit).toEqual([])
  })

  test('a cross-origin delete is 403 cross_origin, even by the owner: the file and the row stay', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    signIn('member-a')
    await upload('mine.yaml', template('mine'))
    h.audit = []
    await refusedCrossOrigin(await deleteFrom(OTHER_SITE, 'mine.yaml'))
    expect(await onDisk('mine.yaml')).toContain('id: mine')
    expect(rowOf('mine.yaml')?.ownerUserId).toBe('member-a')
    expect(h.audit).toEqual([])
  })

  test('a cross-origin promote is 403 cross_origin, even by an admin: the owner stays', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    signIn('member-a')
    await upload('a.yaml', template('a'))
    h.audit = []
    signIn('admin-1')
    await refusedCrossOrigin(await promoteFrom(OTHER_SITE, { path: 'a.yaml', promote: true }))
    expect(rowOf('a.yaml')?.ownerUserId).toBe('member-a')
    expect(h.audit).toEqual([])
  })

  test('an Origin that is not an origin is refused like another site', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    signIn('member-a')
    await refusedCrossOrigin(await uploadFrom({ Origin: 'null' }, 'x.yaml', template('x')))
    expect(h.rows).toEqual([])
  })

  test('the same origin is allowed for all three, the multipart upload included', async () => {
    signIn('member-a')
    const uploaded = await uploadFrom(SAME_SITE, 'mine.yaml', template('mine'))
    expect(uploaded.status).toBe(200)
    expect(rowOf('mine.yaml')?.ownerUserId).toBe('member-a')
    signIn('admin-1')
    const promoted = await promoteFrom(SAME_SITE, { path: 'mine.yaml', promote: true })
    expect(promoted.status).toBe(200)
    expect((await promoted.json()).promoted).toBe(true)
    const deleted = await deleteFrom(SAME_SITE, 'mine.yaml')
    expect(deleted.status).toBe(200)
    expect(rowOf('mine.yaml')).toBeUndefined()
    expect(actions()).toEqual(['nuclei_template.upload', 'nuclei_template.promote', 'nuclei_template.delete'])
  })

  test('without a session the answer stays 401, whatever the origin', async () => {
    expect((await uploadFrom(OTHER_SITE, 'x.yaml', template('x'))).status).toBe(401)
    expect((await deleteFrom(OTHER_SITE, 'x.yaml')).status).toBe(401)
    expect((await promoteFrom(OTHER_SITE, { path: 'x.yaml', promote: true })).status).toBe(401)
  })
})
