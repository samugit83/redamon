/**
 * Words for the transfers panel. A failed job reports only a code; these are
 * the agent's sentences for the codes a workspace upload or import job ends
 * with (agentic/workspace_import/errors.py), shortened for a narrow panel.
 * The code always stays in the text so a screenshot names the cause.
 */

const JOB_FAILURES: Record<string, string> = {
  unsafe_path: 'The archive holds a path that leaves its folder',
  too_deep: 'The archive nests folders more than 64 levels deep',
  name_too_long: 'The archive holds a name or path that is too long',
  too_many_entries: 'The upload holds more files and folders than the server allows',
  too_large: 'The content is larger than the server allows',
  conflicting_entries: 'The archive holds a file and a folder with the same path',
  unsupported_archive: 'The file is not a zip, tar, tar.gz, tar.bz2, tar.xz or gz archive',
  corrupt_archive: 'The archive is damaged or truncated',
  empty_archive: 'The archive holds nothing to extract',
  insufficient_storage: 'Not enough free disk space on the server',
  protected_path: 'That folder is part of the workspace layout and cannot be replaced',
  conflict_type: 'A file and a folder cannot replace each other',
  name_exhausted: 'Too many entries with that name already exist in the folder',
  exists: 'An entry with that name already exists in the folder',
  destination_missing: 'The destination folder no longer exists',
  busy: 'A running import is replacing that folder. Retry when it finishes',
  project_deleted: 'The project was deleted',
  settings_unavailable: 'The project could not be checked with the web app. Retry shortly',
  interrupted: 'The agent restarted before the transfer finished',
  internal_error: 'Something went wrong on the server. Check the agent log',
  import_disabled: 'URL import is turned off on this server',
  invalid_url: 'The link is not a valid URL',
  unsupported_scheme: 'Only http and https links can be imported',
  credentials_in_url: 'The link holds a user name or password',
  kind_not_supported: 'This page cannot be imported',
  blocked_address: 'The link points at a private, internal or metadata address',
  dns_failed: "The link's host name does not resolve",
  timeout: 'The source did not answer in time',
  network_error: 'The source could not be reached',
  too_many_redirects: 'The link redirects more than 5 times',
  redirect_refused: 'The git server redirected the clone, which is not allowed',
  upstream_status: 'The source answered with an error',
  unexpected_html: 'The link answered with a web page, not a file or an archive',
  not_found: 'The source was not found. A private repository needs a token that can read it',
  rate_limited: "GitHub's hourly rate limit for this server is used up",
  auth_failed: 'GitHub refused the token: it may be expired or revoked',
  ref_not_found: 'The branch, tag or commit in the link does not exist',
  invalid_subpath: 'The folder in the link does not exist in that branch',
  git_failed: 'The git clone failed',
  invalid_option: 'An import option has the wrong type or value',
  hard_blocked: 'Government, military, education and intergovernmental sites are never fetched',
  roe_excluded: "The project's Rules of Engagement exclude this host",
  roe_outside_window: "The project's Rules of Engagement do not allow requests to this target now",
  robots_disallowed: "The site's robots.txt disallows this page",
  robots_unavailable: "The site's robots.txt could not be read, so nothing was fetched",
  nothing_saved: 'The mirror saved nothing: every page was refused, skipped or failed',
}

const CODE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/

export function jobFailureMessage(code: string | null | undefined): string {
  if (!code || !CODE.test(code)) return 'The transfer failed on the server (no error code)'
  return `${JOB_FAILURES[code] ?? 'The transfer failed on the server'} (${code})`
}

const PHASES: Record<string, string> = {
  queued: 'Starting',
  resolving: 'Resolving',
  downloading: 'Downloading',
  crawling: 'Crawling',
  extracting: 'Extracting',
  placing: 'Placing',
  done: 'Finishing',
}

export function phaseLabel(phase: string | undefined): string {
  return (phase && PHASES[phase]) || 'Processing'
}

const STOP_REASONS: Record<string, string> = {
  max_pages: 'Stopped at the page limit',
  max_depth: 'Stopped at the depth limit',
  max_bytes: 'Stopped at the size limit',
  time_budget: 'Stopped at the 30-minute limit',
  roe_window: 'Stopped when the Rules of Engagement window closed',
}

/** Why a website mirror ended before it ran out of pages, or '' when it did not. */
export function stopReasonLabel(reason: string | undefined): string {
  return (reason && STOP_REASONS[reason]) || ''
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}M`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}G`
}
