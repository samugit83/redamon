import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { activeRecordingBlock } from '@/lib/recordingConfig'

export const runtime = 'nodejs'

// GET /api/internal/capture-config - internal-only.
//
// Returns the GLOBAL TrafficMind capture-proxy config (egress guard + body-storage
// policy) as the exact JSON shape the capture proxy's config file uses. The DB
// (UserSettings) is the SINGLE SOURCE OF TRUTH. The orchestrator polls this endpoint
// and materialises the result to `/spool/.capture-config.json` on the shared volume;
// the credential-free, target-facing proxy hot-reloads that file and never touches
// the DB itself.
//
// "Global" = the admin operator's UserSettings row. Capture config is an admin-only,
// single-shared-proxy setting; the UI writes the acting admin's row, so the most
// recently updated admin row is authoritative ("last admin save wins").
export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  try {
    const admins = await prisma.user.findMany({ where: { role: 'admin' }, select: { id: true } })
    const adminIds = admins.map((a) => a.id)
    const s = adminIds.length
      ? await prisma.userSettings.findFirst({
          where: { userId: { in: adminIds } },
          orderBy: { updatedAt: 'desc' },
        })
      : null

    // Fail-safe default: with no configured row, hand back the block-EVERYTHING
    // egress posture so the proxy stays locked down until an operator configures it.
    const b = (v: boolean | null | undefined, d = true) => (v === null || v === undefined ? d : v)

    const egress = {
      block_empty_host: b(s?.captureEgressBlockEmptyHost),
      block_hard_guardrail: b(s?.captureEgressBlockHardGuardrail),
      fail_closed_on_error: b(s?.captureEgressFailClosed),
      block_unresolvable: b(s?.captureEgressBlockUnresolvable),
      block_private: b(s?.captureEgressBlockPrivate),
      block_loopback: b(s?.captureEgressBlockLoopback),
      block_link_local: b(s?.captureEgressBlockLinkLocal),
      block_cgnat: b(s?.captureEgressBlockCgnat),
      block_reserved: b(s?.captureEgressBlockReserved),
      block_multicast: b(s?.captureEgressBlockMulticast),
      block_unspecified: b(s?.captureEgressBlockUnspecified),
    }

    const body = {
      store_bodies: b(s?.captureProxyStoreBodies),
      store_req_bodies: b(s?.captureProxyStoreReqBodies),
      store_resp_bodies: b(s?.captureProxyStoreRespBodies),
      max_body_kb: s?.captureProxyMaxBodyKb ?? 64,
      max_store_mb: s?.captureProxyMaxStoreMb ?? 5,
      // captureProxyBodyRules is a Json column -> already an object; the proxy's
      // parse_body_rules() accepts a dict and merges it over the safe defaults.
      body_rules: (s?.captureProxyBodyRules as Record<string, unknown>) ?? {},
      // NOTE: the RedAmon-service IP denylist (CAPTURE_BLOCKED_IPS) is a security
      // invariant sourced ONLY from env in the proxy; it is deliberately NOT here.
    }

    // Operator-recording window (Phase 2). Derived live from the newest
    // unexpired RecordingSession whose project still exists and has capture on,
    // and only while the GLOBAL proxy is enabled. Omitted otherwise, so the
    // reconciler drops the injected tag within one poll of stop/expiry (fail
    // closed — no manual clearing). The pre-signed operator tag is minted here.
    const globalEnabled = b(s?.captureProxyEnabled)
    const active_recording = globalEnabled ? await activeRecordingBlock() : null

    return NextResponse.json({
      egress,
      body,
      enabled: globalEnabled,
      ...(active_recording ? { active_recording } : {}),
      // A1: the ignore list for the supply-chain incident match. The Python
      // ingest worker cannot SELECT it (its role is INSERT-only on one table),
      // so it rides this config the way the egress policy already does. Empty
      // means "use the shipped provider list" on both sides.
      sca_intel_ignore_suffixes: s?.scaIntelIgnoreSuffixes ?? '',
      source: s ? 'db' : 'default-block',
    })
  } catch {
    // On a DB/read error, DO NOT return a relaxed policy. Signal failure so the
    // orchestrator keeps the last-good file instead of opening the guard.
    return NextResponse.json({ error: 'capture-config unavailable' }, { status: 503 })
  }
}
