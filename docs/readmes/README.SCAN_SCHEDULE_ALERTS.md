# Scheduled Scans — Diff Detection & Alerts

Closes the help-wanted gap: the scheduler engine (`ScanSchedule` model,
`scan_scheduler.py` worker, `ScanScheduleTable` UI) already ran recurring full
recon, but there was no baseline diff, no alerting, and no change timeline.
This adds all three.

## What was built

- **Baseline diff** — `webapp/src/lib/scanDiff.ts` (+ `scanDiff.test.ts`).
  Diffs two frozen `ScanVersion` snapshots for new/removed subdomains, open
  ports, CVEs and new `Vulnerability` findings. Pure functions; tenant fields
  (`user_id`, `project_id`) and timestamps are ignored so an identical rescan
  diffs to empty.
- **Baseline storage** — Prisma `ScanChange` (one row per completed run:
  `newSubdomains`, `removedSubdomains`, `newPorts`, `removedPorts`, `newCves`,
  `newVulnCount`), computed best-effort in `scanChangeTracker.ts`, hooked into
  `reconcileScanJobStatus` in `scanTimeline.ts`. First-ever scan stores an
  empty baseline row. Never throws into the status poll.
- **Alerts** — `webapp/src/lib/scanAlerts.ts` (+ `scanAlerts.test.ts`):
  Slack incoming-webhook + generic JSON webhook POSTs (10s timeout,
  https-only URL validation, `{ ok, error }` instead of throwing, URLs never
  logged). Preferences in Prisma `ScanAlertConfig`; send outcomes in
  `ScanAlert` for the timeline.
- **Timeline + config UI** — `ScanScheduleTable.tsx`: new `Changes` column in
  run history and a *Change alerts* panel (write-only URL fields, New-only /
  New+removed / Paused selector). New routes:
  `GET|PUT /api/projects/[id]/alert-config`,
  `GET /api/projects/[id]/scans/[jobId]/changes` (BOLA-guarded, cross-project
  ids report 404 per anti-enumeration convention). The schedules `GET` now
  includes each job's change summary.

## Setup

1. Apply the schema (repo convention is `db push`, not `migrate`):
   `docker compose exec webapp npx prisma db push`
2. No new env vars, no new dependencies. Restart `webapp`; the
   `recon-orchestrator` needs no change (the tick already works).

## Usage

1. Scans tab → add an `interval`/`cron` schedule (full recon only, as before).
2. *Change alerts* → paste a Slack or generic webhook URL → Save.
3. When a scheduled run completes, the next status poll diffs it, stores the
   `ScanChange`, and posts a summary
   (`:radar: RedAmon scheduled scan — <project> …`) with the new items listed
   (capped at 10 per field, counts beyond that).

## Deliberate limitations

- **No SMTP email.** The webapp has no mail dependency; operators who want
  email point the generic webhook at their mailer (or a Slack email
  integration). The payload uses `event: 'scan.changes'` for this.
- **Webhook URLs are secrets.** `GET alert-config` returns only
  `{ slackConfigured, webhookConfigured }`, never the URLs. They are stored
  on their own relation (not Project columns, which `GET /api/projects/[id]`
  spreads to the browser) and excluded from project export/import.
- **Scheduler DoS guards unchanged** (`scanSchedule.ts` min-interval + RAM
  feasibility still gate creation; admission ledger still gates execution).
- **Not yet verified here:** `npm run type-check`, `lint`, and `vitest` were
  not run in the author's environment — let CI run them before merge.
