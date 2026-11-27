import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import type { RequestOptions } from 'node:http'
import { isAllowedAddress, safeLookup, type Resolver, type Transport } from '@/lib/plugins/fetchRemote'
import type { DeltaAlertChannelType } from './types'

const DEFAULT_TIMEOUT_MS = 10_000
const MAX_RESPONSE_BYTES = 4096

export type DeltaAlertEgressCode =
  | 'bad_url'
  | 'not_https'
  | 'address_not_public'
  | 'dns_no_address'
  | 'redirect_refused'
  | 'timeout'
  | 'network_error'

export class DeltaAlertEgressError extends Error {
  constructor(
    readonly code: DeltaAlertEgressCode,
    message: string,
  ) {
    super(message)
    this.name = 'DeltaAlertEgressError'
  }
}

export interface PostWebhookOptions {
  resolve?: Resolver
  request?: Transport
  timeoutMs?: number
}

export interface PostWebhookResult {
  statusCode: number
  body: string
}

const systemResolver: Resolver = async (hostname) => {
  const out = await dns.promises.lookup(hostname, { all: true, verbatim: true })
  return out.map((a) => ({ address: a.address, family: a.family }))
}

function stripIpBrackets(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, '')
}

/**
 * Formats only scheme + host for error messages so secret path tokens
 * (such as Slack incoming webhook tokens) never appear in logs or outbox errors.
 */
function redactTarget(u: URL): string {
  return `${u.protocol}//${u.host}`
}

/**
 * Validates syntax, scheme, absence of embedded credentials, and literal IP
 * publicness for an alert webhook endpoint.
 */
export function validateAlertWebhookUrl(rawUrl: string, type: DeltaAlertChannelType): URL {
  let u: URL
  try {
    u = new URL(rawUrl.trim())
  } catch {
    throw new DeltaAlertEgressError('bad_url', 'Webhook URL is not a valid URL.')
  }

  if (type === 'slack') {
    if (u.protocol !== 'https:') {
      throw new DeltaAlertEgressError('not_https', 'Slack webhook URLs must use https.')
    }
  } else if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new DeltaAlertEgressError('bad_url', 'Webhook URLs must use http or https.')
  }

  if (u.username || u.password) {
    throw new DeltaAlertEgressError('bad_url', 'Webhook URLs must not contain embedded credentials.')
  }

  const host = stripIpBrackets(u.hostname)
  if (!host) {
    throw new DeltaAlertEgressError('bad_url', 'Webhook URL is missing a host.')
  }

  if (net.isIP(host) !== 0 && !isAllowedAddress(host)) {
    throw new DeltaAlertEgressError(
      'address_not_public',
      `Webhook host ${redactTarget(u)} is not a public IP address.`,
    )
  }

  return u
}

/**
 * Validates the URL and checks that every resolved DNS address is public
 * via the shared `fetchRemote.isAllowedAddress` guard.
 */
export async function assertWebhookEgressAllowed(
  rawUrl: string,
  type: DeltaAlertChannelType,
  resolve: Resolver = systemResolver,
): Promise<URL> {
  const u = validateAlertWebhookUrl(rawUrl, type)
  const host = stripIpBrackets(u.hostname)
  if (net.isIP(host) !== 0) {
    return u
  }

  let addrs
  try {
    addrs = await resolve(host)
  } catch {
    throw new DeltaAlertEgressError(
      'dns_no_address',
      `Could not resolve host for ${redactTarget(u)}.`,
    )
  }

  if (!addrs.length) {
    throw new DeltaAlertEgressError(
      'dns_no_address',
      `Host for ${redactTarget(u)} returned no DNS addresses.`,
    )
  }

  if (addrs.some((a) => !isAllowedAddress(a.address))) {
    throw new DeltaAlertEgressError(
      'address_not_public',
      `Webhook host ${redactTarget(u)} resolved to a non-public address.`,
    )
  }

  return u
}

/**
 * Sends a single outbound POST without connection pooling, with socket-level
 * DNS re-validation (`safeLookup`), a 10s timeout, a 4 KiB response cap,
 * and strict 3xx redirect refusal.
 */
export async function postWebhookSafe(
  rawUrl: string,
  type: DeltaAlertChannelType,
  body: string,
  headers: Record<string, string>,
  opts: PostWebhookOptions = {},
): Promise<PostWebhookResult> {
  const resolve = opts.resolve ?? systemResolver
  const u = await assertWebhookEgressAllowed(rawUrl, type, resolve)
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const lookup = safeLookup(resolve)

  const transport: Transport =
    opts.request ??
    ((reqOpts, cb) => (u.protocol === 'https:' ? https.request(reqOpts, cb) : http.request(reqOpts, cb)))

  const payloadBytes = Buffer.from(body, 'utf8')
  const reqOpts: RequestOptions = {
    protocol: u.protocol,
    hostname: stripIpBrackets(u.hostname),
    port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
    path: `${u.pathname}${u.search}`,
    method: 'POST',
    agent: false,
    // safeLookup checks every answer at socket connect time to prevent DNS rebinding.
    lookup: lookup as unknown as RequestOptions['lookup'],
    headers: {
      ...headers,
      'Content-Length': String(payloadBytes.length),
    },
  }

  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false
    const finishErr = (err: DeltaAlertEgressError) => {
      if (settled) return
      settled = true
      rejectPromise(err)
    }
    const finishOk = (res: PostWebhookResult) => {
      if (settled) return
      settled = true
      resolvePromise(res)
    }

    const req = transport(reqOpts, (res) => {
      const status = res.statusCode ?? 0
      if (status >= 300 && status < 400) {
        res.destroy()
        return finishErr(
          new DeltaAlertEgressError(
            'redirect_refused',
            `Webhook endpoint ${redactTarget(u)} returned redirect HTTP ${status}, which is refused.`,
          ),
        )
      }

      const chunks: Buffer[] = []
      let total = 0
      res.on('data', (chunk: Buffer) => {
        if (total >= MAX_RESPONSE_BYTES) return
        const remaining = MAX_RESPONSE_BYTES - total
        const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
        chunks.push(slice)
        total += slice.length
        if (total >= MAX_RESPONSE_BYTES) {
          res.destroy()
        }
      })
      res.on('end', () => {
        finishOk({
          statusCode: status,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
      res.on('close', () => {
        finishOk({
          statusCode: status,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
      res.on('error', () => {
        finishErr(
          new DeltaAlertEgressError(
            'network_error',
            `Webhook response stream failed for ${redactTarget(u)}.`,
          ),
        )
      })
    })

    req.setTimeout(timeoutMs, () => {
      req.destroy()
      finishErr(
        new DeltaAlertEgressError(
          'timeout',
          `Webhook request to ${redactTarget(u)} timed out after ${timeoutMs}ms.`,
        ),
      )
    })

    req.on('error', (err: NodeJS.ErrnoException) => {
      if (err?.code === 'ERR_PLUGIN_ADDRESS_NOT_PUBLIC') {
        return finishErr(
          new DeltaAlertEgressError(
            'address_not_public',
            `Webhook host ${redactTarget(u)} resolved to a non-public address.`,
          ),
        )
      }
      finishErr(
        new DeltaAlertEgressError(
          'network_error',
          `Webhook request to ${redactTarget(u)} failed (${err?.code || 'network error'}).`,
        ),
      )
    })

    req.write(payloadBytes)
    req.end()
  })
}

export function formatSafeEgressError(err: unknown): string {
  if (err instanceof DeltaAlertEgressError) return err.message
  if (err instanceof Error) return err.name || 'Delivery failed'
  return 'Delivery failed'
}
