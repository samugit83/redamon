/**
 * Validates a tool's arguments against the same JSON schema the model is shown, so the two cannot
 * drift: only `string` (maxLength, enum, pattern), `integer` (minimum, maximum) and `boolean`
 * properties, required keys, and no unknown key (`additionalProperties: false` always).
 */
export interface PropSchema {
  type: 'string' | 'integer' | 'boolean'
  description?: string
  maxLength?: number
  enum?: readonly string[]
  pattern?: string
  minimum?: number
  maximum?: number
}

export interface ArgsSchema {
  type: 'object'
  properties: Record<string, PropSchema>
  required?: readonly string[]
  additionalProperties: false
}

export type Validated = { ok: true; args: Record<string, string | number | boolean> } | { ok: false; message: string }

const MAX_STRING = 4000

export function validateArgs(schema: ArgsSchema, raw: unknown): Validated {
  const input = raw === undefined || raw === null ? {} : raw
  if (typeof input !== 'object' || Array.isArray(input)) return { ok: false, message: 'Arguments must be an object.' }
  const args: Record<string, string | number | boolean> = {}
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    const prop = schema.properties[key]
    if (!prop) return { ok: false, message: `Unknown argument "${key.slice(0, 40)}".` }
    if (value === null || value === undefined) continue
    if (prop.type === 'string') {
      if (typeof value !== 'string') return { ok: false, message: `"${key}" must be a string.` }
      if (value.length > (prop.maxLength ?? MAX_STRING)) return { ok: false, message: `"${key}" is too long.` }
      if (prop.enum && !prop.enum.includes(value)) return { ok: false, message: `"${key}" must be one of: ${prop.enum.join(', ')}.` }
      if (prop.pattern && !new RegExp(prop.pattern).test(value)) return { ok: false, message: `"${key}" has the wrong shape.` }
      args[key] = value
    } else if (prop.type === 'integer') {
      if (typeof value !== 'number' || !Number.isInteger(value)) return { ok: false, message: `"${key}" must be an integer.` }
      if (prop.minimum !== undefined && value < prop.minimum) return { ok: false, message: `"${key}" is below ${prop.minimum}.` }
      if (prop.maximum !== undefined && value > prop.maximum) return { ok: false, message: `"${key}" is above ${prop.maximum}.` }
      args[key] = value
    } else {
      if (typeof value !== 'boolean') return { ok: false, message: `"${key}" must be true or false.` }
      args[key] = value
    }
  }
  for (const key of schema.required ?? []) {
    if (!(key in args)) return { ok: false, message: `"${key}" is required.` }
  }
  return { ok: true, args }
}
