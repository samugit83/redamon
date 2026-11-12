/**
 * A small reader of `schema.prisma` text for the schema tests: models, their table,
 * their fields with the declared type and column, and their raw lines. It covers the
 * shapes this schema uses (no enums, no composite types, one field per line) and
 * throws on a model it cannot read, so a new shape fails a test instead of being
 * skipped.
 */

export interface SchemaField {
  /** The declared type with its modifier, as written: `String`, `String?`, `String[]`. */
  type: string
  /** The database column: the `@map` name, or the field name when it has none. */
  column: string
  /** The field's line without its trailing comment. */
  line: string
}

export interface SchemaModel {
  /** The `@@map` table name, or the model name when it has none. */
  table: string
  fields: Record<string, SchemaField>
  /** The `@@` lines (indexes, uniques, map), comments removed. */
  blockAttributes: string[]
}

/** The line up to its `//` comment, ignoring `//` inside a quoted string (a URL default). */
function withoutComment(line: string): string {
  let quoted = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === '\\' && quoted) { i++; continue }
    if (c === '"') quoted = !quoted
    else if (!quoted && c === '/' && line[i + 1] === '/') return line.slice(0, i)
  }
  return line
}

const FIELD = /^(\w+)\s+(\w+(?:\[\])?\??)(?:\s|$)/

export function parsePrismaModels(text: string): Record<string, SchemaModel> {
  const models: Record<string, SchemaModel> = {}
  for (const m of text.matchAll(/^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
    const [, name, body] = m
    const model: SchemaModel = { table: name, fields: {}, blockAttributes: [] }
    for (const raw of body.split('\n')) {
      const line = withoutComment(raw).trim()
      if (!line) continue
      if (line.startsWith('@@')) {
        model.blockAttributes.push(line)
        const map = line.match(/^@@map\(\s*"([^"]+)"\s*\)/)
        if (map) model.table = map[1]
        continue
      }
      const f = line.match(FIELD)
      if (!f) throw new Error(`schema.prisma: cannot read a line of model ${name}: ${raw.trim()}`)
      const map = line.match(/@map\(\s*"([^"]+)"\s*\)/)
      model.fields[f[1]] = { type: f[2], column: map ? map[1] : f[1], line }
    }
    models[name] = model
  }
  return models
}

/** The type without its `?` / `[]` modifier. */
export function baseType(type: string): string {
  return type.replace(/\[\]$|\?$/, '')
}
