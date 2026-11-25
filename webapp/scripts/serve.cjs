'use strict'
// The webapp's production start (the entrypoint's last step, webapp/Dockerfile): the Next.js
// standalone server behind the pre-authentication body guard (D9, lib/preauthBodyGuard.cjs).
// The guard must be installed before server.js runs, since Next.js creates its HTTP server
// while server.js loads.

const { installPreauthBodyGuard, guardedServerCount } = require('./lib/preauthBodyGuard.cjs')

installPreauthBodyGuard()
// server.js keeps an idle keep-alive socket Node's default 5 s, the same 5 s after which httpx
// (the agent's client) gives one up: a request sent on a socket the server was closing failed
// with a reset ("socket hang up"). Longer than any client's idle expiry, so the client always
// lets a socket go first. Set here, not in compose, so the services' environment stays pinned
// (tests/tradecraft_no_new_env_test.sh); KEEP_ALIVE_TIMEOUT still overrides it.
process.env.KEEP_ALIVE_TIMEOUT ??= '65000'
require('../server.js')

// The guard wraps the listener Next.js passes to http.createServer. A Next.js release that
// created its server another way would leave it inert, so say so instead of running unguarded
// in silence (scripts/lib/preauthBodyGuard.test.ts pins the current way).
setTimeout(() => {
  if (guardedServerCount() === 0) {
    console.error('[preauth-guard] NOT ACTIVE: Next.js created no server through http.createServer, so request bodies from callers with no credential reach Next.js unchecked (D9)')
  }
}, 30_000).unref()
