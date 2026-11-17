/**
 * Every Tradecraft table goes with its resource and/or its user, by the database itself
 * (§7.1, R-205, AC-44): a model added later without an `onDelete: Cascade` link fails here.
 * The page store carries both links. Also the columns later cards build against (phase 1
 * "Data model") and their defaults, which make an existing resource read as a 1.x resource.
 * The real cascade runs in schema.pg.integration.test.ts.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/tradecraft/schemaCascade.test.ts
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from 'vitest'
import { baseType, parsePrismaModels, type SchemaModel } from '../authz/__testing__/prismaSchema'

const WEBAPP = path.resolve(__dirname, '../../..')
const now = parsePrismaModels(readFileSync(path.join(WEBAPP, 'prisma/schema.prisma'), 'utf8'))

const CASCADE_TARGETS = new Set(['User', 'UserTradecraftResource', 'TradecraftEntry', 'Project'])
const TRADECRAFT_MODELS = Object.keys(now).filter(n => n.startsWith('Tradecraft') || n === 'UserTradecraftResource')

function cascadeLinks(model: SchemaModel): string[] {
  return Object.values(model.fields)
    .filter(f => CASCADE_TARGETS.has(baseType(f.type)) && /@relation\([^)]*onDelete:\s*Cascade/.test(f.line))
    .map(f => baseType(f.type))
}

describe('every tradecraft table cascades', () => {
  test('the models of phase 1 exist, with their tables', () => {
    expect(Object.fromEntries(TRADECRAFT_MODELS.map(n => [n, now[n].table]))).toEqual({
      UserTradecraftResource: 'user_tradecraft_resources',
      TradecraftUserSettings: 'tradecraft_user_settings',
      TradecraftIngestionJob: 'tradecraft_ingestion_jobs',
      TradecraftPageId: 'tradecraft_page_ids',
      TradecraftEntry: 'tradecraft_entries',
      TradecraftSection: 'tradecraft_sections',
      TradecraftTreeNode: 'tradecraft_tree_nodes',
      TradecraftCuration: 'tradecraft_curations',
      TradecraftProjectChoice: 'tradecraft_project_choices',
    })
  })

  test.each(TRADECRAFT_MODELS)('%s has an onDelete: Cascade link to its user, resource, entry or project', (name) => {
    expect(cascadeLinks(now[name]).length, `${name}: add a relation with onDelete: Cascade`).toBeGreaterThan(0)
  })

  test('no tradecraft relation uses another delete rule, so no delete is ever blocked or leaves a row behind', () => {
    for (const name of TRADECRAFT_MODELS) {
      for (const [field, f] of Object.entries(now[name].fields)) {
        if (!f.line.includes('@relation(')) continue
        expect(f.line, `${name}.${field}`).toMatch(/onDelete:\s*Cascade/)
      }
    }
  })

  test('the page store carries both links: its user and its resource', () => {
    expect(cascadeLinks(now.TradecraftEntry).sort()).toEqual(['User', 'UserTradecraftResource'])
  })

  test('the project choices go with the project and with the resource', () => {
    expect(cascadeLinks(now.TradecraftProjectChoice).sort()).toEqual(['Project', 'UserTradecraftResource'])
    expect(now.Project.fields.tradecraftChoices?.type).toBe('TradecraftProjectChoice[]')
  })

  test('the claim and the people of a job are plain ids, never foreign keys', () => {
    expect(now.UserTradecraftResource.fields.activeJobId).toMatchObject({ type: 'String?', column: 'active_job_id' })
    for (const plain of ['actorUserId', 'realActorUserId']) {
      expect(now.TradecraftIngestionJob.fields[plain].line, plain).not.toContain('@relation')
    }
    expect(now.TradecraftSection.fields.userId.line).not.toContain('@relation')
    expect(now.TradecraftTreeNode.fields.userId.line).not.toContain('@relation')
  })

  test('a model that would fail the rule is caught (the check is not vacuous)', () => {
    const bad = parsePrismaModels(`model TradecraftOrphan {
  id         String @id
  resourceId String @map("resource_id")
  resource   UserTradecraftResource @relation(fields: [resourceId], references: [id], onDelete: SetNull)
}
model UserTradecraftResource {
  id String @id
}`)
    expect(cascadeLinks(bad.TradecraftOrphan)).toEqual([])
  })
})

describe('the 2.0 columns of UserTradecraftResource (existing rows read as 1.x, Live)', () => {
  test.each([
    ['storageMode', 'String', 'storage_mode', '@default("live")'],
    ['forcedType', 'String', 'forced_type', '@default("")'],
    ['overrides', 'Json', 'overrides', '@default("{}")'],
    ['typeOptions', 'Json', 'type_options', '@default("{}")'],
    ['focus', 'Json', 'focus', '@default("{}")'],
    ['credentials', 'Json', 'credentials', '@default("{}")'],
    ['hasLogin', 'Boolean', 'has_login', '@default(false)'],
    ['summarySource', 'String', 'summary_source', '@default("generated")'],
    ['summaryLocked', 'Boolean', 'summary_locked', '@default(false)'],
    ['settingsSnapshot', 'Json', 'settings_snapshot', '@default("{}")'],
    ['settingsHash', 'String', 'settings_hash', '@default("")'],
    ['ingestionReport', 'Json', 'ingestion_report', '@default("{}")'],
    ['mapVersion', 'Int', 'map_version', '@default(1)'],
    ['legacyMapHash', 'String', 'legacy_map_hash', '@default("")'],
    ['generation', 'Int', 'generation', '@default(0)'],
    ['priority', 'String', 'priority', '@default("normal")'],
    ['presetKey', 'String', 'preset_key', '@default("")'],
  ])('%s is %s in %s with %s', (name, type, column, def) => {
    const f = now.UserTradecraftResource.fields[name]
    expect(f).toMatchObject({ type, column })
    expect(f.line).toContain(def)
  })

  test('the 1.x columns stay (R-218): the cache lifetime and sitemap', () => {
    // Found by its column: the field's name is left to the schema alone (tests/tradecraft_no_cache_names_test.sh).
    const lifetime = Object.values(now.UserTradecraftResource.fields).find(f => f.column === 'cache_ttl_sec')
    expect(lifetime).toMatchObject({ type: 'Int', column: 'cache_ttl_sec' })
    expect(now.UserTradecraftResource.fields.sitemap).toMatchObject({ type: 'Json', column: 'sitemap' })
  })
})

describe('the page store and its search objects (EX-1)', () => {
  test('search vectors are declared, so db push keeps them and their GIN indexes', () => {
    expect(now.TradecraftEntry.fields.searchVector).toMatchObject({ type: 'Unsupported("tsvector")?', column: 'search_vector' })
    expect(now.TradecraftSection.fields.searchVector).toMatchObject({ type: 'Unsupported("tsvector")?', column: 'search_vector' })
    expect(now.TradecraftEntry.blockAttributes).toEqual(expect.arrayContaining([
      '@@index([searchVector], type: Gin)',
      '@@index([title(ops: raw("gin_trgm_ops"))], type: Gin)',
      '@@index([topics], type: Gin)',
      '@@index([entities], type: Gin)',
      '@@unique([resourceId, generation, pageId])',
      '@@index([userId, resourceId, generation])',
    ]))
    expect(now.TradecraftSection.blockAttributes).toContain('@@index([searchVector], type: Gin)')
  })

  test('pg_trgm is declared, so a fresh install can create the trigram index', () => {
    const text = readFileSync(path.join(WEBAPP, 'prisma/schema.prisma'), 'utf8')
    expect(text).toMatch(/previewFeatures\s*=\s*\[[^\]]*"postgresqlExtensions"/)
    expect(text).toMatch(/extensions\s*=\s*\[[^\]]*pg_trgm/)
  })

  test('page IDs are unique per resource and URL, with a global autoincrement id (TD-4)', () => {
    expect(now.TradecraftPageId.fields.id.line).toMatch(/Int\s+@id\s+@default\(autoincrement\(\)\)/)
    expect(now.TradecraftPageId.blockAttributes).toContain('@@unique([resourceId, url])')
  })

  test('the tables the agent writes with raw SQL carry a database default for updated_at', () => {
    for (const name of ['TradecraftEntry', 'TradecraftIngestionJob', 'TradecraftCuration']) {
      expect(now[name].fields.updatedAt.line, name).toMatch(/@default\(now\(\)\)\s+@updatedAt/)
    }
  })

  test('every foreign key column of a cascade has an index that starts with it', () => {
    for (const name of TRADECRAFT_MODELS) {
      const model = now[name]
      for (const f of Object.values(model.fields)) {
        const m = f.line.match(/@relation\(fields:\s*\[(\w+)\]/)
        if (!m) continue
        const key = m[1]
        const leading = model.blockAttributes.some(a => new RegExp(`^@@(index|unique|id)\\(\\[${key}\\b`).test(a))
          || /@unique\b|@id\b/.test(model.fields[key].line)
        expect(leading, `${name}.${key}: a cascade without an index scans the table once per deleted row`).toBe(true)
      }
    }
  })
})
