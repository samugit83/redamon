# ============================================
# RedAmon Web Application - Production Dockerfile
# Multi-stage build for optimized production image
# ============================================

# Stage 1: Dependencies
FROM node:22-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY package.json package-lock.json* ./
COPY prisma ./prisma
# Same retry/timeout tuning as the runner stage (npm config is per-stage: it
# writes /root/.npmrc, which does not carry across FROM). This is the heaviest
# download in the build, so it is the layer most likely to hit ECONNRESET.
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 180000 && \
    npm config set fetch-timeout 900000 && \
    npm ci --no-audit --no-fund && npm cache clean --force

# Stage 2: Builder
FROM node:22-slim AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . ./

ARG REDAMON_VERSION=0.0.0
ENV NEXT_PUBLIC_REDAMON_VERSION=$REDAMON_VERSION
# Single-origin deploy: bake the same-origin agent WebSocket URL so the browser
# never targets a public :8090. NEXT_PUBLIC_* is inlined by Next.js at build time,
# so this MUST be set before `npm run build`. Empty by default => runtime auto-detect
# (local dev falls back to ws://localhost:8090); the single-host deploy overlay sets
# it to wss://<host>/ws/agent so the chat WebSocket works behind nginx.
ARG NEXT_PUBLIC_AGENT_WS_URL=
ENV NEXT_PUBLIC_AGENT_WS_URL=$NEXT_PUBLIC_AGENT_WS_URL
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
# Dummy DATABASE_URL for Prisma client generation at build time (not used at runtime)
ENV DATABASE_URL="postgresql://build:build@localhost:5432/build"
ENV NODE_OPTIONS=--max-old-space-size=4096

RUN npm run build

# Stage 3: Runner (Production)
FROM node:22-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 nodejs
RUN useradd --system --uid 1001 --gid nodejs --no-create-home nextjs

COPY --from=builder /app/public ./public

RUN mkdir .next
RUN chown nextjs:nodejs .next

# Pre-create data dirs so named volumes inherit correct ownership
RUN mkdir -p /data/reports && chown nextjs:nodejs /data/reports
RUN mkdir -p /data/js-recon-uploads && chown nextjs:nodejs /data/js-recon-uploads
RUN mkdir -p /data/js-recon-custom && chown nextjs:nodejs /data/js-recon-custom
# Supply-Chain (L1) SBOM/lockfile uploads. Missing here, the named volume was
# created by Docker as root:root and the webapp (uid 1001 nextjs) could not
# mkdir the per-project subdir - every upload failed with
#   EACCES: permission denied, mkdir '/data/supply-chain-uploads/<project>'
# surfaced to the operator only as "Failed to upload file".
RUN mkdir -p /data/supply-chain-uploads && chown nextjs:nodejs /data/supply-chain-uploads
# Installed plugins (docker-compose.plugins.yml mounts the `plugins` volume here). The
# runner image pre-creates its /plugins for uid 1001 too: Docker copies the first mounting
# image's ownership onto an empty volume, and either service may mount it first.
RUN mkdir -p /data/plugins && chown nextjs:nodejs /data/plugins

# Leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# CLI utility scripts (admin setup, password reset) and the RoE text extractor
COPY --from=builder --chown=nextjs:nodejs /app/scripts ./scripts
# The extractor runs as a child process, so its parsers reach the standalone
# output only through next.config.ts outputFileTracingIncludes. Prove they did.
RUN node scripts/roe-extract.mjs --self-test

# Prisma schema + CLI for automatic migration on startup
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/prisma/package.json /tmp/prisma-pkg.json
# npm retry/timeout tuning: this layer pulls the Prisma query-engine binaries
# (~100MB), and on a slow or flaky link the default single-shot fetch dies with
#   npm error code ECONNRESET / npm error network aborted
# killing the whole build. Retry with backoff instead of failing on one reset.
RUN PRISMA_VER=$(node -p "require('/tmp/prisma-pkg.json').version") && \
    npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 180000 && \
    npm config set fetch-timeout 900000 && \
    npm install --no-save "prisma@${PRISMA_VER}" bcryptjs && \
    npm cache clean --force && rm /tmp/prisma-pkg.json

# Entrypoint: migrate, sync schema to PostgreSQL, then start server.
#
# Order matters in BOTH directions around `db push`:
#   BEFORE  — the push carries --accept-data-loss and DROPS columns no longer in
#             schema.prisma. Anything that needs to read a dropped column has to
#             run first; the TruffleHog profile migration does, and it exits
#             non-zero on failure so the push never destroys the source data.
#             So does a column whose default is meant for new rows only: it is
#             added first with the value existing rows must keep, because the
#             push would fill them with the new default (the JS Recon TruffleHog
#             switch, off in the projects that predate it).
#   AFTER   — the push would also drop the FTS objects, the ingest role and the
#             engagement append-only trigger, so those are re-applied
#             immediately afterwards (§6.3). The trigger is what makes "an
#             authorization record cannot be rewritten" enforcement rather than
#             a model comment. The plugin tables' one-active index and CHECK
#             constraints are re-checked here too (never fatal: the stores
#             enforce the same rules). Row fix-ups that need the pushed columns
#             (clamp-triage-review-budget, the one-time user-skill toggle,
#             Jev provider selection, RBAC legacy-grant, Nuclei template
#             owner and instance settings backfills, the boot's Root
#             choice) run here too.
# The push itself is fatal: a webapp serving without the columns its code
# expects fails on every request that touches them, which is worse than a
# restart. compose restarts it (unless-stopped) once Postgres answers.
RUN printf '#!/bin/sh\nnode scripts/migrate-trufflehog-profiles.mjs 2>&1 || exit 1\nnode scripts/add-js-recon-trufflehog-column.mjs 2>&1 || exit 1\necho "Syncing Prisma schema..."\nnode scripts/db-push-locked.mjs db push --skip-generate --accept-data-loss --schema ./prisma/schema.prisma 2>&1 || exit 1\nnode scripts/apply-ingest-role.mjs 2>&1\nnode scripts/apply-traffic-fts.mjs 2>&1\nnode scripts/apply-engagement-immutability.mjs 2>&1\nnode scripts/apply-plugin-constraints.mjs 2>&1 || echo "[plugins] constraint script failed"\nnode scripts/clamp-triage-review-budget.mjs 2>&1\nnode scripts/backfill-user-skill-toggles.mjs 2>&1\nnode scripts/backfill-jev-provider-selection.mjs 2>&1\nnode scripts/backfill-rbac-legacy-grants.mjs 2>&1\nnode scripts/backfill-nuclei-template-owners.mjs 2>&1\nnode scripts/backfill-rbac-instance-settings.mjs 2>&1\nnode scripts/backfill-rbac-root.mjs 2>&1\nexec node server.js\n' > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["/app/entrypoint.sh"]
