/**
 * The resource URL check and the slug helpers, shared by the 1.x and 2.0 resource routes.
 *
 * The address check is the webapp's first filter only: the agent checks the resolved address of
 * every hop again (fetch_guard.py), so a name that resolves to a private address is refused there.
 */
import prisma from '@/lib/prisma'

/**
 * A login in the URL (`user:pass@host`) would be shown on every card, logged, and sent to the
 * model as part of the URL; the agent refuses it too (net.py `userinfo_refused`).
 */
export const USERINFO_REFUSED = "Put a site login in the resource's Access settings, not in its URL"

export type UrlCheck = { ok: true } | { ok: false; error: string; code?: 'userinfo_refused' }

export { slugify } from './slug'

export async function uniqueSlug(userId: string, base: string): Promise<string> {
  let slug = base
  let suffix = 2
  while (true) {
    const existing = await prisma.userTradecraftResource.findUnique({
      where: { userId_slug: { userId, slug } },
    })
    if (!existing) return slug
    slug = `${base}-${suffix}`
    suffix++
  }
}

export function isPrivateHost(hostname: string): boolean {
  if (!hostname) return true
  const lc = hostname.toLowerCase()
  if (lc === 'localhost' || lc.endsWith('.local') || lc.endsWith('.internal')) return true
  const m = lc.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  if (m) {
    const o = m.slice(1).map(Number)
    if (o[0] === 10) return true
    if (o[0] === 127) return true
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true
    if (o[0] === 192 && o[1] === 168) return true
    if (o[0] === 169 && o[1] === 254) return true
    if (o[0] === 0) return true
  }
  if (lc === '::1' || lc.startsWith('fe80:') || lc.startsWith('fc') || lc.startsWith('fd')) return true
  return false
}

export function validateUrl(raw: unknown): UrlCheck {
  try {
    const u = new URL(String(raw))
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { ok: false, error: 'Only http(s) URLs are allowed' }
    }
    if (u.username || u.password) {
      return { ok: false, error: USERINFO_REFUSED, code: 'userinfo_refused' }
    }
    if (isPrivateHost(u.hostname)) {
      return { ok: false, error: 'private address blocked' }
    }
    return { ok: true }
  } catch {
    return { ok: false, error: 'Invalid URL' }
  }
}

/** Whether a URL string carries a user name or password (the 1.x edit, which checks nothing else). */
export function hasUserinfo(raw: unknown): boolean {
  try {
    const u = new URL(String(raw))
    return Boolean(u.username || u.password)
  } catch {
    return false
  }
}
