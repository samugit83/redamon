import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { budgetFor, parseUsageReport, recordUsage } from '@/lib/instanceProviders/budget'
import { instanceProvidersInForce } from '@/lib/instanceProviders/entitlement'

/**
 * The agent's side of the daily budget on instance LLM providers (step 6.11, GV-12;
 * agentic/llm_budget.py). Master key only (the scanner key is not accepted: a scan container never
 * reads or spends a budget).
 *
 * GET ?userId=: `{limit, used}`, the person's `llmDailyCalls` quota (null = unlimited) and the calls
 * stored for today (UTC).
 * POST `{counts: [{userId, day, count}]}`: adds a minute's counts, each for the person who ran the
 * calls; a day is today or yesterday. With RBAC_GOVERNANCE_ENABLED off no instance provider is used:
 * GET answers unlimited and POST records nothing, reading nothing.
 */
const unauthorized = () => NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

export const GET = withRouteErrors('Could not read the LLM budget', async (request: NextRequest) => {
  if (!isInternalRequest(request)) return unauthorized()
  const userId = request.nextUrl.searchParams.get('userId') ?? ''
  if (!userId || userId.length > 128) return NextResponse.json({ error: 'userId is required', code: 'invalid_user' }, { status: 400 })
  return NextResponse.json(await budgetFor(userId), { headers: { 'Cache-Control': 'no-store' } })
})

export const POST = withRouteErrors('Could not record the LLM usage', async (request: NextRequest) => {
  if (!isInternalRequest(request)) return unauthorized()
  const body = await request.json().catch(() => null)
  const entries = parseUsageReport(body)
  if (typeof entries === 'string') return NextResponse.json({ error: entries, code: 'invalid_usage' }, { status: 400 })
  if (!instanceProvidersInForce()) return NextResponse.json({ recorded: 0 })
  return NextResponse.json({ recorded: await recordUsage(entries) })
})
