import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginAllowedFor } from '@/lib/plugins/accessRules'
import { isValidPluginId } from '@/lib/plugins/ids'
import { viewerIsAdmin } from '@/lib/plugins/pageModel'
import { loadPluginIcon } from '@/lib/plugins/pluginIcon'
import { getSession } from '@/lib/session'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/[pluginId]/icon: the plugin's avatar for any signed-in user, served from this
 * origin after its sha256 matched the signed catalog (lib/plugins/pluginIcon.ts). A 404 lets the
 * card fall back to its placeholder, as it does for a plugin the Plugins page hides from the viewer.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/** The Plugins page shows the plugin: available to the effective user, or the person manages plugins. */
async function shownTo(userId: string, pluginId: string): Promise<boolean> {
  if (await pluginAllowedFor(userId, pluginId)) return true
  const session = await getSession()
  return !!session && (await viewerIsAdmin(session.userId))
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ pluginId: string }> }) {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const user = await requireEffectiveUser()
  if (user instanceof NextResponse) return user
  const { pluginId } = await params
  const icon = isValidPluginId(pluginId) && (await shownTo(user.userId, pluginId)) ? await loadPluginIcon(pluginId) : null
  const v = request.nextUrl.searchParams.get('v')
  // An old page's URL names an image the catalog replaced; serving the new one under it would
  // break the immutable caching below.
  if (!icon || (v !== null && !icon.sha256.startsWith(v))) {
    return new NextResponse(null, { status: 404, headers: { 'Cache-Control': 'no-store' } })
  }
  return new NextResponse(new Uint8Array(icon.bytes), {
    headers: {
      'Content-Type': icon.type,
      'Content-Length': String(icon.bytes.length),
      'Cache-Control': 'private, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    },
  })
}
