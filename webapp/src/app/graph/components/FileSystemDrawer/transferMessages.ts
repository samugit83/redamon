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
  too_many_entries: 'The archive holds more entries than the server allows',
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
  project_deleted: 'The project was deleted',
  interrupted: 'The agent restarted before the transfer finished',
  internal_error: 'Something went wrong on the server. Check the agent log',
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
  extracting: 'Extracting',
  placing: 'Placing',
  done: 'Finishing',
}

export function phaseLabel(phase: string | undefined): string {
  return (phase && PHASES[phase]) || 'Processing'
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}M`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}G`
}
