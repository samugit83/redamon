/**
 * The Map view of a resource (§6.10, T6.7): its live generation's entries, searched and filtered,
 * and the person's curation of them. Curation rows (`TradecraftCuration`, by URL) outlive every
 * refresh: the ingestion applies them (T6.6), the read path refuses a blocked URL from any source
 * (T1.9), and the Map view shows them at once.
 *  - pin: a URL the person typed, checked like a resource URL, on the resource's own host when it
 *    has a login; it joins the map at the next refresh;
 *  - block: chosen URLs, or every entry matching a search whose count the person confirmed (409
 *    when it changed); the stored text and sections go at once;
 *  - unblock: the page comes back at the next refresh (read live until then);
 *  - rename: shown at once, applied to the page at the next refresh;
 *  - restore: a dropped page is kept now and pinned, so the next refresh keeps it.
 * Every write runs under the resource's row lock, as the swap of a new generation does.
 */
import type { Prisma, UserTradecraftResource } from '@prisma/client'
import prisma from '@/lib/prisma'
import { hasStoredLogin } from './masking'
import { lockOwnResource } from './resourceAccess'
import { validateUrl } from './urls'

export const MAP_PAGE_SIZE = 100
export const MAP_STATUSES = ['kept', 'dropped', 'blocked'] as const
export type MapStatus = (typeof MAP_STATUSES)[number]
export const RENAME_MAX = 300
export const CURATE_URLS_MAX = 500
const QUERY_MAX = 200
const TAG_MAX = 64
const URL_MAX = 2048
const CONTROL = /[\u0000-\u001f\u007f]/

export type MapResource = Pick<UserTradecraftResource, 'id' | 'userId' | 'slug' | 'url' | 'generation' | 'hasLogin' | 'credentials'>

export interface MapEntryView {
  /** The entry row's id: a BigInt, answered as a string. Empty for a blocked URL no longer in the map. */
  id: string
  /** The page ID the agent sees (`<slug>:<n>`); empty for a blocked URL no longer in the map. */
  pageId: string
  title: string
  url: string
  topics: string[]
  kinds: string[]
  technologies: string[]
  description: string
  source: string
  status: MapStatus
  /** Why the focus dropped it. */
  reason: string
  pinned: boolean
  renamed: boolean
  /** The page's text is in the store (a Stored resource). */
  stored: boolean
}

export interface MapQuery {
  query?: string
  status?: MapStatus
  tag?: string
  cursor?: string | null
  limit?: number
}

export interface MapPage {
  entries: MapEntryView[]
  total: number
  nextCursor: string | null
}

const ENTRY_SELECT = {
  id: true, pageId: true, title: true, url: true, topics: true, kinds: true, technologies: true, description: true,
  source: true, status: true, dropReason: true, storedBytes: true,
} satisfies Prisma.TradecraftEntrySelect

type EntryRow = Prisma.TradecraftEntryGetPayload<{ select: typeof ENTRY_SELECT }>
type CurationRow = { url: string; pinned: boolean; blocked: boolean; renamedTitle: string | null }

/** The entries of the live generation a search names; blocked URLs are listed apart. */
function entryWhere(r: MapResource, q: { query?: string; status?: string; tag?: string }, blocked: string[]): Prisma.TradecraftEntryWhereInput {
  return {
    userId: r.userId,
    resourceId: r.id,
    generation: r.generation,
    status: q.status ?? 'kept',
    ...(blocked.length > 0 ? { url: { notIn: blocked } } : {}),
    AND: [
      q.query ? { OR: [{ title: { contains: q.query, mode: 'insensitive' } }, { url: { contains: q.query, mode: 'insensitive' } }] } : {},
      q.tag ? { OR: [{ topics: { has: q.tag } }, { kinds: { has: q.tag } }, { technologies: { has: q.tag } }] } : {},
    ],
  }
}

function view(r: MapResource, e: EntryRow | null, url: string, c: CurationRow | undefined, status: MapStatus): MapEntryView {
  return {
    id: e ? e.id.toString() : '',
    pageId: e ? `${r.slug}:${e.pageId}` : '',
    title: c?.renamedTitle ?? e?.title ?? '',
    url,
    topics: e?.topics ?? [],
    kinds: e?.kinds ?? [],
    technologies: e?.technologies ?? [],
    description: e?.description ?? '',
    source: e?.source ?? '',
    status,
    reason: status === 'dropped' ? e?.dropReason ?? '' : '',
    pinned: c?.pinned ?? false,
    renamed: !!c?.renamedTitle,
    stored: (e?.storedBytes ?? 0) > 0,
  }
}

const DIGITS = /^[0-9]{1,19}$/

export function isMapCursor(cursor: string): boolean {
  return DIGITS.test(cursor) || /^https?:\/\//.test(cursor)
}

export async function readMap(r: MapResource, q: MapQuery): Promise<MapPage> {
  const limit = Math.min(MAP_PAGE_SIZE, Math.max(1, q.limit ?? MAP_PAGE_SIZE))
  const status = q.status ?? 'kept'
  const curations: CurationRow[] = await prisma.tradecraftCuration.findMany({
    where: { resourceId: r.id }, select: { url: true, pinned: true, blocked: true, renamedTitle: true },
  })
  const byUrl = new Map(curations.map(c => [c.url, c]))
  const blocked = curations.filter(c => c.blocked).map(c => c.url).sort()

  if (status === 'blocked') {
    // A blocked URL may have left the map at a refresh: listed from its curation row, by URL.
    const rows = blocked.length === 0 ? [] : await prisma.tradecraftEntry.findMany({
      where: { userId: r.userId, resourceId: r.id, generation: r.generation, url: { in: blocked } }, select: ENTRY_SELECT,
    })
    const byEntryUrl = new Map(rows.map(e => [e.url, e]))
    const needle = q.query?.toLowerCase() ?? ''
    const matching = blocked.filter(url => !needle || url.toLowerCase().includes(needle) || (byEntryUrl.get(url)?.title ?? '').toLowerCase().includes(needle))
    const after = q.cursor ? matching.filter(url => url > q.cursor!) : matching
    const page = after.slice(0, limit)
    return {
      entries: page.map(url => view(r, byEntryUrl.get(url) ?? null, url, byUrl.get(url), 'blocked')),
      total: matching.length,
      nextCursor: after.length > limit ? page[page.length - 1] : null,
    }
  }

  const where = entryWhere(r, { query: q.query, status, tag: q.tag }, blocked)
  const pageWhere = q.cursor && DIGITS.test(q.cursor) ? { AND: [where, { id: { gt: BigInt(q.cursor) } }] } : where
  const [total, rows] = await Promise.all([
    prisma.tradecraftEntry.count({ where }),
    prisma.tradecraftEntry.findMany({ where: pageWhere, select: ENTRY_SELECT, orderBy: { id: 'asc' }, take: limit + 1 }),
  ])
  const page = rows.slice(0, limit)
  return {
    entries: page.map(e => view(r, e, e.url, byUrl.get(e.url), status)),
    total,
    nextCursor: rows.length > limit ? page[page.length - 1].id.toString() : null,
  }
}

// --- curation -------------------------------------------------------------------------

export type CurateResult =
  | { ok: true; op: string; count: number }
  | { ok: false; status: 400 | 404 | 409; code: string; error: string; field?: string; count?: number }

const refuse = (status: 400 | 404 | 409, code: string, error: string, extra: { field?: string; count?: number } = {}): CurateResult =>
  ({ ok: false, status, code, error, ...extra })

class Refused extends Error {
  constructor(readonly result: CurateResult) { super('refused') }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function urlList(input: unknown): string[] | CurateResult {
  if (!Array.isArray(input) || input.length === 0 || input.length > CURATE_URLS_MAX) {
    return refuse(400, 'bad_request', `Send 1 to ${CURATE_URLS_MAX} URLs`, { field: 'urls' })
  }
  if (!input.every(u => typeof u === 'string' && u.length > 0 && u.length <= URL_MAX)) return refuse(400, 'bad_request', 'A URL is text', { field: 'urls' })
  return [...new Set(input as string[])]
}

function oneUrl(input: unknown): string | CurateResult {
  return typeof input === 'string' && input.length > 0 && input.length <= URL_MAX ? input : refuse(400, 'bad_request', 'Send the page URL', { field: 'url' })
}

type Matching = { query?: string; status?: 'kept' | 'dropped'; tag?: string }

function matchingOf(input: unknown): Matching | CurateResult {
  if (!isRecord(input)) return refuse(400, 'bad_request', 'matching is {query, status, tag}', { field: 'matching' })
  const { query, status, tag } = input
  if (query !== undefined && (typeof query !== 'string' || query.length > QUERY_MAX)) return refuse(400, 'bad_request', 'Bad search', { field: 'matching.query' })
  if (status !== undefined && status !== 'kept' && status !== 'dropped') return refuse(400, 'bad_request', 'Block kept or dropped pages', { field: 'matching.status' })
  if (tag !== undefined && (typeof tag !== 'string' || tag.length > TAG_MAX)) return refuse(400, 'bad_request', 'Bad tag', { field: 'matching.tag' })
  return { query: query || undefined, status: status as Matching['status'], tag: tag || undefined }
}

/** The 400 when a typed URL may not be pinned (§6.10, D-54); null when it may. */
function pinRefusal(r: MapResource, url: string): CurateResult | null {
  const check = validateUrl(url)
  if (!check.ok) return refuse(400, check.code ?? 'bad_url', check.error, { field: 'url' })
  // A login is sent only to the resource's own host (§6.6): a pin elsewhere would read another
  // site with it, or read it outside the login's protection.
  if (hasStoredLogin(r) && new URL(url).host !== new URL(r.url).host) {
    return refuse(400, 'other_host', 'A resource with a login pins only pages of its own site', { field: 'url' })
  }
  return null
}

/** Applies one curation operation (the Map view's POST body) for `actorId`, the person signed in. */
export async function curate(r: MapResource, body: unknown, actorId: string): Promise<CurateResult> {
  if (!isRecord(body) || typeof body.op !== 'string') return refuse(400, 'bad_request', 'Send {op, ...}')
  try {
    switch (body.op) {
      case 'pin': return await pin(r, body, actorId)
      case 'block': return await block(r, body, actorId)
      case 'unblock': return await unblock(r, body)
      case 'rename': return await rename(r, body, actorId)
      case 'restore': return await restore(r, body, actorId)
      default: return refuse(400, 'bad_request', 'op is pin, block, unblock, rename or restore', { field: 'op' })
    }
  } catch (err) {
    if (err instanceof Refused) return err.result
    throw err
  }
}

/** Runs `fn` under the resource's row lock; a resource deleted meanwhile is a 404. */
async function locked<T>(r: MapResource, fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return prisma.$transaction(async (tx) => {
    if (!(await lockOwnResource(tx, r.userId, r.id))) throw new Refused(refuse(404, 'not_found', 'Resource not found'))
    return fn(tx)
  })
}

async function dropEmptyRows(tx: Prisma.TransactionClient, resourceId: string, urls: string[]): Promise<void> {
  await tx.tradecraftCuration.deleteMany({
    where: { resourceId, url: { in: urls }, pinned: false, blocked: false, renamedTitle: null, restoredFromDrop: false },
  })
}

async function pin(r: MapResource, body: Record<string, unknown>, actorId: string): Promise<CurateResult> {
  const url = oneUrl(body.url)
  if (typeof url !== 'string') return url
  const refused = pinRefusal(r, url)
  if (refused) return refused
  await locked(r, tx => tx.tradecraftCuration.upsert({
    where: { resourceId_url: { resourceId: r.id, url } },
    create: { resourceId: r.id, url, pinned: true, createdById: actorId },
    update: { pinned: true, blocked: false },
  }))
  return { ok: true, op: 'pin', count: 1 }
}

async function block(r: MapResource, body: Record<string, unknown>, actorId: string): Promise<CurateResult> {
  const byUrls = body.urls !== undefined
  const byMatching = body.matching !== undefined
  if (byUrls === byMatching) return refuse(400, 'bad_request', 'Send either urls or matching with expectedCount')
  let urls: string[] | null = null
  let matching: Matching | null = null
  if (byUrls) {
    const list = urlList(body.urls)
    if (!Array.isArray(list)) return list
    urls = list
  } else {
    const m = matchingOf(body.matching)
    if ('ok' in m) return m
    matching = m
    if (typeof body.expectedCount !== 'number' || !Number.isInteger(body.expectedCount) || body.expectedCount < 0) {
      return refuse(400, 'bad_request', 'Send the count you confirmed', { field: 'expectedCount' })
    }
  }
  const count = await locked(r, async (tx) => {
    let targets = urls
    if (matching) {
      const blocked = (await tx.tradecraftCuration.findMany({ where: { resourceId: r.id, blocked: true }, select: { url: true } })).map(c => c.url)
      const where = entryWhere(r, matching, blocked)
      // The count the person confirmed must still be the count: a refresh in between changed the map.
      const now = await tx.tradecraftEntry.count({ where })
      if (now !== body.expectedCount) {
        throw new Refused(refuse(409, 'count_changed', `The search now matches ${now} pages, not ${body.expectedCount}: check them again`, { count: now }))
      }
      targets = (await tx.tradecraftEntry.findMany({ where, select: { url: true } })).map(e => e.url)
    }
    if (!targets || targets.length === 0) return 0
    await tx.tradecraftCuration.updateMany({ where: { resourceId: r.id, url: { in: targets } }, data: { blocked: true, pinned: false } })
    await tx.tradecraftCuration.createMany({
      data: targets.map(url => ({ resourceId: r.id, url, blocked: true, createdById: actorId })), skipDuplicates: true,
    })
    // The text goes now (§6.10): in every generation the store still holds, with the sections built from it.
    const entries = await tx.tradecraftEntry.findMany({
      where: { userId: r.userId, resourceId: r.id, url: { in: targets } }, select: { id: true, generation: true, storedBytes: true },
    })
    const ids = entries.map(e => e.id)
    if (ids.length > 0) {
      await tx.tradecraftSection.deleteMany({ where: { resourceId: r.id, entryId: { in: ids } } })
      await tx.tradecraftEntry.updateMany({ where: { resourceId: r.id, id: { in: ids } }, data: { storedText: null, storedBytes: 0 } })
    }
    const live = entries.filter(e => e.generation === r.generation && e.storedBytes > 0)
    if (live.length > 0) await lowerStoredCounts(tx, r.id, live.length, live.reduce((n, e) => n + e.storedBytes, 0))
    return targets.length
  })
  return { ok: true, op: 'block', count }
}

/**
 * The report's stored counts describe the text the store holds (the stale badge reads them,
 * `staleness.ts`): what a block deleted is taken off them.
 */
async function lowerStoredCounts(tx: Prisma.TransactionClient, resourceId: string, pages: number, bytes: number): Promise<void> {
  const row = await tx.userTradecraftResource.findUnique({ where: { id: resourceId }, select: { ingestionReport: true } })
  const report = row?.ingestionReport
  if (!isRecord(report) || !isRecord(report.stored)) return
  const stored = report.stored
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
  await tx.userTradecraftResource.update({
    where: { id: resourceId },
    data: { ingestionReport: { ...report, stored: { ...stored, pages: Math.max(0, num(stored.pages) - pages), bytes: Math.max(0, num(stored.bytes) - bytes) } } },
  })
}

async function unblock(r: MapResource, body: Record<string, unknown>): Promise<CurateResult> {
  const urls = urlList(body.urls)
  if (!Array.isArray(urls)) return urls
  const count = await locked(r, async (tx) => {
    const { count } = await tx.tradecraftCuration.updateMany({ where: { resourceId: r.id, url: { in: urls }, blocked: true }, data: { blocked: false } })
    await dropEmptyRows(tx, r.id, urls)
    return count
  })
  return { ok: true, op: 'unblock', count }
}

async function rename(r: MapResource, body: Record<string, unknown>, actorId: string): Promise<CurateResult> {
  const url = oneUrl(body.url)
  if (typeof url !== 'string') return url
  if (typeof body.title !== 'string') return refuse(400, 'bad_request', 'Send the new title, or "" to clear it', { field: 'title' })
  const title = body.title.trim()
  if (title.length > RENAME_MAX || CONTROL.test(title)) {
    return refuse(400, 'bad_request', `A title holds at most ${RENAME_MAX} characters, on one line`, { field: 'title' })
  }
  await locked(r, async (tx) => {
    if (!title) {
      await tx.tradecraftCuration.updateMany({ where: { resourceId: r.id, url }, data: { renamedTitle: null } })
      await dropEmptyRows(tx, r.id, [url])
      return
    }
    const inMap = await tx.tradecraftEntry.count({ where: { userId: r.userId, resourceId: r.id, generation: r.generation, url } })
    if (inMap === 0) throw new Refused(refuse(404, 'not_in_map', 'This page is not in the map'))
    await tx.tradecraftCuration.upsert({
      where: { resourceId_url: { resourceId: r.id, url } },
      create: { resourceId: r.id, url, renamedTitle: title, createdById: actorId },
      update: { renamedTitle: title },
    })
  })
  return { ok: true, op: 'rename', count: 1 }
}

async function restore(r: MapResource, body: Record<string, unknown>, actorId: string): Promise<CurateResult> {
  const url = oneUrl(body.url)
  if (typeof url !== 'string') return url
  await locked(r, async (tx) => {
    const where = { userId: r.userId, resourceId: r.id, generation: r.generation, url }
    const dropped = await tx.tradecraftEntry.updateMany({ where: { ...where, status: 'dropped' }, data: { status: 'kept', dropReason: '' } })
    if (dropped.count === 0) {
      const there = await tx.tradecraftEntry.count({ where })
      throw new Refused(there > 0 ? refuse(409, 'not_dropped', 'This page is not dropped') : refuse(404, 'not_in_map', 'This page is not in the map'))
    }
    // A restored page is pinned, so the next refresh keeps it whatever the focus decides (AC-14).
    await tx.tradecraftCuration.upsert({
      where: { resourceId_url: { resourceId: r.id, url } },
      create: { resourceId: r.id, url, pinned: true, restoredFromDrop: true, createdById: actorId },
      update: { pinned: true, restoredFromDrop: true, blocked: false },
    })
  })
  return { ok: true, op: 'restore', count: 1 }
}
