/**
 * Unit tests for server-side Fireteam settings validation.
 *
 * Mirrors the six Core settings from FIRETEAM.md §31. Verifies both the
 * Zod schema ranges and the cross-field invariant (max_concurrent <= max_members).
 *
 * Run: cd webapp && npx vitest src/lib/validation/fireteamSettings.test.ts
 */

import { describe, it, expect } from 'vitest'
import { FireteamSettingsSchema, validateFireteamSettings } from './fireteamSettings'

describe('FireteamSettingsSchema', () => {
  it('accepts a full valid payload', () => {
    const result = FireteamSettingsSchema.safeParse({
      fireteamEnabled: true,
      fireteamMaxConcurrent: 3,
      fireteamMaxMembers: 5,
      fireteamMemberMaxIterations: 15,
      fireteamTimeoutSec: 1800,
      fireteamAllowedPhases: ['informational'],
    })
    expect(result.success).toBe(true)
  })

  it('accepts a partial update (only one field)', () => {
    const result = FireteamSettingsSchema.safeParse({
      fireteamEnabled: true,
    })
    expect(result.success).toBe(true)
  })

  it('rejects fireteamMaxConcurrent below 1', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamMaxConcurrent: 0 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamMaxConcurrent above 8', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamMaxConcurrent: 9 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamMaxMembers below 2', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamMaxMembers: 1 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamMaxMembers above 8', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamMaxMembers: 9 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamMemberMaxIterations below 5', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamMemberMaxIterations: 4 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamMemberMaxIterations above 50', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamMemberMaxIterations: 51 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamTimeoutSec below 60', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamTimeoutSec: 30 })
    expect(result.success).toBe(false)
  })

  it('rejects fireteamTimeoutSec above 7200', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamTimeoutSec: 7201 })
    expect(result.success).toBe(false)
  })

  it('rejects empty fireteamAllowedPhases', () => {
    const result = FireteamSettingsSchema.safeParse({ fireteamAllowedPhases: [] })
    expect(result.success).toBe(false)
  })

  it('rejects unknown phase in fireteamAllowedPhases', () => {
    const result = FireteamSettingsSchema.safeParse({
      fireteamAllowedPhases: ['informational', 'totally_bogus'],
    })
    expect(result.success).toBe(false)
  })

  it('accepts all three valid phases', () => {
    const result = FireteamSettingsSchema.safeParse({
      fireteamAllowedPhases: ['informational', 'exploitation', 'post_exploitation'],
    })
    expect(result.success).toBe(true)
  })
})

describe('validateFireteamSettings cross-field', () => {
  it('returns null for a valid payload', () => {
    const err = validateFireteamSettings({
      fireteamEnabled: true,
      fireteamMaxConcurrent: 3,
      fireteamMaxMembers: 5,
    })
    expect(err).toBeNull()
  })

  it('rejects max_concurrent > max_members', () => {
    const err = validateFireteamSettings({
      fireteamMaxConcurrent: 8,
      fireteamMaxMembers: 3,
    })
    expect(err).toBeTruthy()
    expect(err).toMatch(/cannot exceed/i)
  })

  it('allows max_concurrent == max_members (boundary)', () => {
    const err = validateFireteamSettings({
      fireteamMaxConcurrent: 5,
      fireteamMaxMembers: 5,
    })
    expect(err).toBeNull()
  })

  it('returns Zod error text when a field is out of range', () => {
    const err = validateFireteamSettings({ fireteamMaxConcurrent: 99 })
    expect(err).toBeTruthy()
    expect(err).toMatch(/fireteamMaxConcurrent/)
  })

  it('ignores non-fireteam fields', () => {
    const err = validateFireteamSettings({
      name: 'unrelated',
      fireteamEnabled: true,
    })
    expect(err).toBeNull()
  })
})
