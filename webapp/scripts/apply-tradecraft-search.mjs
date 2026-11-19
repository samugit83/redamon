/**
 * Fill the Tradecraft search vectors in Postgres itself: a function and a BEFORE INSERT OR
 * UPDATE trigger on tradecraft_entries and on tradecraft_sections.
 *
 * Prisma declares the tsvector columns and their GIN indexes (schema.prisma), and
 * `db push --accept-data-loss` keeps them; it cannot declare a function or a trigger, and
 * keeps those too once they exist (run/EX-1.md of the Tradecraft 2.0 plan). So this script
 * runs from the webapp entrypoint right after the push, at every start. It reads the
 * catalog first and changes only what differs: on a start where both triggers already
 * match, it takes no lock on either table, so a long write of the page store (an
 * ingestion's generation) never makes the webapp's start, or the reads queued behind a
 * DDL lock, wait. Neither writer (the agent's raw SQL, the webapp's Prisma) computes a
 * vector, so the weighting lives in one place.
 *
 * Weights: title A; breadcrumb and headings B; description, topics, kinds, technologies and
 * entities C. A section: heading A, text D. Input is cut before to_tsvector, which refuses a
 * vector over 1 MB: a page of unique tokens (hashes, base64) would otherwise make the INSERT
 * fail and lose the page.
 *
 * Serialized by an advisory lock (two webapp copies booting together), never fatal: when a
 * trigger must change and its table is busy, lock_timeout gives up after a few seconds and
 * the change waits for the next start; search finds fewer pages meanwhile, the webapp serves.
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

export const LOCK_KEY = 'tradecraft-search'
export const TEXT_SEARCH_CONFIG = 'english'
/** Characters of one field (or a section's text) that reach to_tsvector. */
export const VECTOR_INPUT_MAX_CHARS = 250000
/** How long a trigger change waits for its table before it gives up until the next start. */
export const LOCK_TIMEOUT = '3s'

export const ENTRY_FUNCTION = 'tradecraft_entry_search_vector'
export const SECTION_FUNCTION = 'tradecraft_section_search_vector'
export const ENTRY_TRIGGER = 'tradecraft_entries_search_vector'
export const SECTION_TRIGGER = 'tradecraft_sections_search_vector'

const cut = (expr) => `left(coalesce(${expr}, ''), ${VECTOR_INPUT_MAX_CHARS})`
const vec = (expr, weight) => `setweight(to_tsvector('${TEXT_SEARCH_CONFIG}', ${cut(expr)}), '${weight}')`

// Headings are [{ "level", "text" }]; a bare string element is read as its text too.
const HEADINGS_TEXT = `(SELECT string_agg(CASE jsonb_typeof(h) WHEN 'string' THEN h #>> '{}' ELSE h ->> 'text' END, ' ')
       FROM jsonb_array_elements(CASE jsonb_typeof(NEW.headings) WHEN 'array' THEN NEW.headings ELSE '[]'::jsonb END) AS h)`

/** Each trigger function's plpgsql body, compared with pg_proc.prosrc before any change. */
export const FUNCTIONS = [
  {
    name: ENTRY_FUNCTION,
    body: `
BEGIN
  NEW.search_vector :=
    ${vec('NEW.title', 'A')} ||
    ${vec(`array_to_string(NEW.breadcrumb, ' ') || ' ' || coalesce(${HEADINGS_TEXT}, '')`, 'B')} ||
    ${vec(`NEW.description || ' ' || array_to_string(NEW.topics, ' ') || ' ' || array_to_string(NEW.kinds, ' ') || ' ' || array_to_string(NEW.technologies, ' ') || ' ' || array_to_string(NEW.entities, ' ')`, 'C')};
  RETURN NEW;
END;
`,
  },
  {
    name: SECTION_FUNCTION,
    body: `
BEGIN
  NEW.search_vector := ${vec('NEW.heading', 'A')} || ${vec('NEW.text', 'D')};
  RETURN NEW;
END;
`,
  },
]

/** Each trigger fires only when a column its vector reads changes. */
export const TRIGGERS = [
  {
    name: ENTRY_TRIGGER, table: 'tradecraft_entries', fn: ENTRY_FUNCTION,
    columns: ['title', 'breadcrumb', 'headings', 'description', 'topics', 'kinds', 'technologies', 'entities'],
  },
  { name: SECTION_TRIGGER, table: 'tradecraft_sections', fn: SECTION_FUNCTION, columns: ['heading', 'text'] },
]

export function functionSql(f) {
  return `CREATE OR REPLACE FUNCTION ${f.name}() RETURNS trigger AS $$` + f.body + '$$ LANGUAGE plpgsql'
}

export function triggerSql(t, { replace = false } = {}) {
  return `CREATE ${replace ? 'OR REPLACE ' : ''}TRIGGER ${t.name} BEFORE INSERT OR UPDATE OF ${t.columns.join(', ')} ` +
    `ON ${t.table} FOR EACH ROW EXECUTE FUNCTION ${t.fn}()`
}

/** pg_get_triggerdef's text without the schema it adds to the table (and to a function off the search path). */
export function normalizeTriggerDef(def) {
  return def.replace(/\s+/g, ' ')
    .replace(/ ON (?:"?[A-Za-z_][\w$]*"?\.)/, ' ON ')
    .replace(/ FUNCTION (?:"?[A-Za-z_][\w$]*"?\.)/, ' FUNCTION ')
    .trim()
}

/**
 * Brings the functions and triggers to this file's definitions, in one transaction under the
 * advisory lock, changing only what differs. Returns the names it created or replaced (none
 * on an ordinary start). Throws on failure, a busy table's lock_timeout included.
 */
export async function applyTradecraftSearch(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`
    // After the advisory lock: another copy running this script is waited for, a busy table is not.
    await tx.$executeRawUnsafe(`SET LOCAL lock_timeout = '${LOCK_TIMEOUT}'`)
    const changed = []
    for (const f of FUNCTIONS) {
      const rows = await tx.$queryRaw`
        SELECT prosrc FROM pg_proc WHERE proname = ${f.name} AND pronamespace = current_schema()::text::regnamespace`
      if (rows.length === 1 && rows[0].prosrc === f.body) continue
      await tx.$executeRawUnsafe(functionSql(f))
      changed.push(f.name)
    }
    for (const t of TRIGGERS) {
      const rows = await tx.$queryRaw`
        SELECT pg_get_triggerdef(t.oid) AS def FROM pg_trigger t
        WHERE t.tgrelid = to_regclass(${t.table}) AND t.tgname = ${t.name} AND NOT t.tgisinternal`
      if (rows.length === 1 && normalizeTriggerDef(rows[0].def) === normalizeTriggerDef(triggerSql(t))) continue
      // CREATE OR REPLACE TRIGGER (Postgres 14+) takes SHARE ROW EXCLUSIVE, which reads pass; a
      // DROP would take ACCESS EXCLUSIVE and queue every reader behind it.
      await tx.$executeRawUnsafe(triggerSql(t, { replace: true }))
      changed.push(t.name)
    }
    return changed
  }, { maxWait: 10_000, timeout: 30_000 })
}

async function main() {
  const prisma = new PrismaClient()
  try {
    const changed = await applyTradecraftSearch(prisma)
    console.log(changed.length
      ? `[tradecraft-search] applied: ${changed.join(', ')}`
      : '[tradecraft-search] search vector triggers up to date')
  } catch (e) {
    // Never block the webapp's start: the change is tried again at the next start.
    console.warn('[tradecraft-search] not applied (continuing; retried at the next start):', e?.code || e?.name || 'error')
  } finally {
    await prisma.$disconnect()
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) await main()
