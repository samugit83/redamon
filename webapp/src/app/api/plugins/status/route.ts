import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { PLUGIN_PLATFORM_VERSION } from '@/lib/plugins/platformVersion'
import { RunnerError, RunnerUnavailableError, runnerHealth } from '@/lib/plugins/runnerClient'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/status: this webapp's platform version and what the plugin runner
 * reports, for the Plugins page's runner banner. A runner that is down, misconfigured
 * or out of date is a state to show, never a 5xx: nothing else depends on it (D-21).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('status', 'The plugin status could not be read; see the webapp log.', async (request: NextRequest) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const user = await requireEffectiveUser()
  if (user instanceof NextResponse) return user

  let runner: Record<string, unknown>
  try {
    const h = await runnerHealth()
    runner = { reachable: true, platformVersion: h.platformVersion, state: h.state, workers: h.workers.length }
  } catch (e) {
    // The reason and the proxy's code tell a timeout from a refused connection or a full
    // proxy; a runner that answered with an error carries its status.
    if (e instanceof RunnerUnavailableError) {
      runner = {
        reachable: false,
        error: e.reason === 'not_configured' ? 'runner_not_configured' : e.code,
        reason: e.reason,
        ...(e.proxyCode ? { proxyCode: e.proxyCode } : {}),
      }
    } else if (e instanceof RunnerError) {
      runner = { reachable: false, error: e.code, upstreamStatus: e.status }
    } else {
      throw e
    }
    console.warn(`[plugins] status: runner not reachable (${runner.error})`)
  }
  return NextResponse.json(
    { platformVersion: PLUGIN_PLATFORM_VERSION, runner },
    { headers: { 'Cache-Control': 'no-store' } },
  )
})
