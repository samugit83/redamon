/**
 * What an audit action means to a person (step 4.13, UI-08, AU-09; read by the project activity feed
 * and, from step 6.6, by the admin audit viewer): one short sentence and the group a screen filters
 * by, for every action the webapp writes to `audit_log`. The action stays the stored, searchable name
 * (never renamed, lib/plugins/audit.ts); this table only says it in words.
 *
 * auditLabels.test.ts reads every action the code writes (literal names, the ternaries and constants
 * that choose one, and the template families) and fails on one without a label here. An action
 * written with a variable part (`mcp.<tool>`) is labelled by its family prefix.
 *
 * Pure data, no server import: the feed's page imports it too.
 */

export const AUDIT_GROUPS = Object.freeze({
  sharing: 'Sharing',
  oversight: 'Oversight and break-glass',
  acting: 'Acting as',
  project: 'Project settings',
  scans: 'Scans and versions',
  findings: 'Findings and triage',
  agent: 'Agent and workspace',
  mcp: 'MCP clients',
  accounts: 'Accounts and sign-in',
  platform: 'Instance and plugins',
  system: 'System records',
} as const)

export type AuditGroup = keyof typeof AUDIT_GROUPS

export const AUDIT_GROUP_IDS = Object.freeze(Object.keys(AUDIT_GROUPS) as AuditGroup[])

export interface AuditLabel {
  label: string
  group: AuditGroup
}

const g = (group: AuditGroup, entries: Record<string, string>): Record<string, AuditLabel> =>
  Object.fromEntries(Object.entries(entries).map(([action, label]) => [action, { label, group }]))

export const AUDIT_ACTION_LABELS: Readonly<Record<string, Readonly<AuditLabel>>> = Object.freeze({
  ...g('sharing', {
    'project.share.grant': 'Shared the project',
    'project.share.update': 'Changed a share',
    'project.share.revoke': 'Revoked a share',
    'project.share.leave': 'Left the project (gave up a share)',
    'project.share.expired': 'A share expired',
    'project.share.lookup': 'Looked up an account to share with',
  }),
  // Written by step 4.14 (oversight reads and Root's break-glass); labelled now so the owner's feed
  // names them from the first row.
  ...g('oversight', {
    'project.oversee': 'Read the project by oversight',
    'project.breakglass': 'Opened break-glass access',
  }),
  ...g('acting', {
    'act_as.start': 'Started acting as an account',
    'act_as.end': 'Stopped acting as an account',
    'act_as.refused': 'Refused while acting as an account',
  }),
  ...g('project', {
    'project.update': 'Changed the project settings',
    'project.roe.download': 'Downloaded the Rules of Engagement document',
    'project.roe.replace': 'Replaced the Rules of Engagement',
    'project.roe.remove': 'Removed the Rules of Engagement',
    'roe.parse': 'Parsed a Rules of Engagement document',
    'node_filters.saved': 'Saved the node filters',
    'node_filters.mode_changed': 'Changed the node filter mode',
    'node_filters.armed': 'Armed the node filters',
    'node_filters.disarmed': 'Disarmed the node filters',
    'node_filters.applied': 'Applied the node filters',
    'node_filters.apply_finished': 'A node filter run finished',
    'node_filters.exemptions_cleared': 'Cleared the node filter exemptions',
  }),
  ...g('scans', {
    'scan-version.save-current': 'Saved the current graph as a version',
    'scan-version.activate': 'Activated a scan version',
    'scan-version.update': 'Changed a scan version',
    'scan-version.overwrite': 'Overwrote a scan version',
    'scan-version.delete': 'Deleted a scan version',
    'scan-schedule.create': 'Created a scan schedule',
    'scan-schedule.update': 'Changed a scan schedule',
    'scan-schedule.delete': 'Deleted a scan schedule',
    'scan_schedule.skipped': 'A scheduled scan was skipped',
    'scan_schedule.paused': 'A scan schedule was paused: the person it runs as lost access',
    'schedule.paused': 'A scan schedule was paused',
    'scan-job.history-clear': 'Cleared the scan history',
    'job_queue.cancelled': 'A queued job was cancelled',
  }),
  ...g('findings', {
    'triage.start': 'Started a triage run',
    'triage.finish': 'A triage run finished',
    'triage.finish.late': 'A triage run finished after it was stopped',
    'triage.review': 'Reviewed a finding',
    'triage.verdict': 'Set a finding verdict',
    'muted_nodes.muted': 'Muted a finding',
    'muted_nodes.multi_muted': 'Muted several findings',
    'muted_nodes.unmuted': 'Unmuted a finding',
  }),
  ...g('agent', {
    'agent.approval': 'Answered an agent phase approval',
    'agent.tool_confirmation': 'Answered an agent tool confirmation',
    'agent.emergency_stop': 'Pressed the emergency stop',
    'agent.session_interact': 'Sent input to an agent session',
    'agent.session_kill': 'Stopped an agent session',
    'agent.job_kill': 'Stopped an agent job',
    'agent.terminal_opened': 'Opened the Kali terminal',
    'workspace.upload': 'Uploaded files to the workspace',
    'workspace.import': 'Imported a link into the workspace',
    'workspace.resync': 'Refreshed a workspace import',
  }),
  ...g('mcp', {
    'mcp.auth.denied': 'An MCP request was refused at sign-in',
    'mcp.create_project': 'Created a project through MCP',
    'mcp.update_project_scope': 'Changed the project scope through MCP',
    'mcp.update_recon_settings': 'Changed recon settings through MCP',
    'mcp.attach_authorization': 'Attached an authorization document through MCP',
    'mcp.start_recon': 'Started a recon scan through MCP',
    'mcp.start_recon.refused': 'A recon start through MCP was refused',
    'mcp.stop_recon': 'Stopped a recon scan through MCP',
    'mcp.set_finding_verdict': 'Set a finding verdict through MCP',
    'mcp.apply_recon_preset': 'Applied a recon preset through MCP',
    'mcp.create_recon_preset': 'Created a recon preset through MCP',
    'mcp.update_recon_preset': 'Changed a recon preset through MCP',
    'mcp.delete_recon_preset': 'Deleted a recon preset through MCP',
    'mcp.kali_exec': 'Ran a Kali command through MCP',
    'mcp.kali_exec.refused': 'A Kali command through MCP was refused',
    'mcp.kali_cancel': 'Cancelled a Kali command through MCP',
  }),
  ...g('accounts', {
    'auth.login.success': 'Signed in',
    'auth.login.failure': 'A sign-in failed',
    'auth.login.disabled': 'A disabled account tried to sign in',
    'auth.login.lockout': 'Sign-in locked after failed attempts',
    'auth.login.after_reset': 'First sign-in after a reset',
    'auth.logout': 'Signed out',
    'user.create': 'Created an account',
    'user.update': 'Changed an account',
    'user.delete': 'Deleted an account',
    'user.delete_failed': 'An account deletion failed',
    'user.disable': 'Disabled an account',
    'user.enable': 'Enabled an account',
    'user.enabled_by_host': 'The host enabled an account',
    'user.email_changed': 'Changed a sign-in email',
    'user.role_changed': "Changed an account's type",
    'user.permissions_changed': "Changed an account's permissions",
    'user.override_expired': 'A permission override expired',
    'user.credentials_reset': "Reset an account's password",
    'user.password_changed': 'Changed their own password',
    'user.password_change_required': 'Asked for a new password at the next sign-in',
    'user.sessions_revoked': 'Signed an account out everywhere',
    'user.invite': 'Invited an account',
    'user.invite_resent': 'Sent an invitation again',
    'user.invite_cancelled': 'Cancelled an invitation',
    'user.invite_locked': 'An invitation was locked after failed attempts',
    'user.invite_accepted': 'Accepted an invitation',
    'user.reset_link_used': 'Used a password reset link',
    'root.transfer_offered': 'Offered Root to an admin',
    'root.transfer': 'Root moved to another admin',
    'root.transfer_cancelled': 'Withdrew a Root offer',
    'root.transfer_declined': 'Declined a Root offer',
    'root.set_by_host': 'The host set the Root',
    'root.confirmed_by_host': 'The host confirmed the Root',
    'mcp-token.create': 'Created an MCP token',
    'mcp-token.update': 'Changed an MCP token',
    'mcp-token.rename': 'Renamed an MCP token',
    'mcp-token.delete': 'Revoked an MCP token',
    'mcp-token.revoke-all': "Revoked every MCP token of an account",
    'user_attack_skill.create': 'Created an attack skill',
    'user_attack_skill.update': 'Changed an attack skill',
    'user_attack_skill.delete': 'Deleted an attack skill',
    'user_attack_skill.import': 'Imported a community attack skill',
    'user_attack_skill.ai_metadata': "Drafted an attack skill's details with AI",
    'user_attack_skill.quarantine': 'Quarantined an attack skill',
    'user_attack_skill.release': 'Released an attack skill from quarantine',
    'user_settings.feature_models': 'Changed the models used by features',
    'settings.tunnel_changed': 'Changed the tunnel settings',
    'api-usage.check': 'Checked the API keys usage',
  }),
  ...g('platform', {
    'instance.settings_changed': 'Changed the instance settings',
    'instance.default_member_set_changed': "Changed the new members' permission set",
    'permission_set.created': 'Created a permission set',
    'permission_set.updated': 'Changed a permission set',
    'permission_set.deleted': 'Deleted a permission set',
    'admin_profile.created': 'Created an admin profile',
    'admin_profile.updated': 'Changed an admin profile',
    'admin_profile.deleted': 'Deleted an admin profile',
    'rbac.root_protected_refused': 'A change to the Root account was refused',
    'rbac.compat_used': 'A shared tool was used in compatibility mode',
    'rbac.legacy_grant.keep': 'Kept a legacy grant',
    'rbac.legacy_grant.remove': 'Removed a legacy grant',
    'rbac.whats_new_dismissed': "Dismissed What's new",
    'nuclei_template.upload': 'Uploaded a Nuclei template',
    'nuclei_template.promote': 'Made a Nuclei template an instance template',
    'nuclei_template.delete': 'Deleted a Nuclei template',
    'mcp_server.stdio_refused': 'A user MCP server over stdio was refused',
    'plugin.install': 'Installed a plugin',
    'plugin.install_failed': 'A plugin install failed',
    'plugin.enable': 'Enabled a plugin',
    'plugin.disable': 'Disabled a plugin',
    'plugin.update': 'Updated a plugin',
    'plugin.rollback': 'Rolled a plugin back',
    'plugin.uninstall': 'Uninstalled a plugin',
    'plugin.purge': "Deleted a plugin's data",
    'plugin.export': "Exported a plugin's data",
    'plugin.permissions_granted': 'Granted a plugin its permissions',
    'plugin.revoked': 'A plugin was revoked',
    'plugin.access_rules_changed': "Changed a plugin's access rules",
    'plugin.override.propose': 'A plugin proposed a change',
    'plugin.override.withdraw': 'A plugin change was withdrawn',
    'plugin.override.approve': 'Approved a plugin change',
    'plugin.override.reject': 'Rejected a plugin change',
    'plugin.override.reset': 'Reset the plugin changes',
    'plugin.override.delete': 'Deleted a plugin change',
    'plugin.override.stale': 'A plugin change went stale',
    'plugin.override.adopt': 'Adopted a plugin change as your own',
  }),
  ...g('system', {
    'system.rbac_root_assigned': 'The Root was chosen automatically',
    'system.rbac_instance_settings_backfill': 'Instance settings created at the upgrade',
    'system.rbac_legacy_grants_cutoff': 'Legacy grants cut-off recorded',
    'system.rbac_legacy_grants_backfill': 'Legacy grants recorded at the upgrade',
    'system.rbac_legacy_overrides_backfill': 'Legacy grants turned into overrides',
    'system.nuclei_template_owners_backfill': 'Nuclei template owners recorded at the upgrade',
    'system.user_skill_toggles_cutoff': 'Attack skill toggles cut-off recorded',
    'system.user_skill_toggles_backfill': 'Attack skill toggles set at the upgrade',
    'system.jev_provider_selection_cutoff': 'Model provider choice cut-off recorded',
    'system.jev_provider_selection_backfill': 'Model provider choices set at the upgrade',
  }),
})

/**
 * Actions written with a variable part, labelled by prefix: `mcp.<tool>` is one row per MCP tool call
 * (lib/mcp/server.ts). An exact entry above wins over its family.
 */
export const AUDIT_ACTION_FAMILIES: ReadonlyArray<Readonly<AuditLabel & { prefix: string }>> = Object.freeze([
  { prefix: 'mcp.', label: 'MCP tool call', group: 'mcp' },
])

/**
 * The words and group of an action. An unknown one (written by a newer or an older version) keeps
 * its stored name as the label, with no group (`known: false`): a screen still shows the row.
 */
export function auditActionLabel(action: string): { label: string; group: AuditGroup | null; known: boolean } {
  const exact = AUDIT_ACTION_LABELS[action]
  if (exact) return { label: exact.label, group: exact.group, known: true }
  const family = AUDIT_ACTION_FAMILIES
    .filter(f => action.startsWith(f.prefix) && action.length > f.prefix.length)
    .sort((a, b) => b.prefix.length - a.prefix.length)[0]
  if (family) return { label: `${family.label}: ${action.slice(family.prefix.length).replace(/[_.]/g, ' ')}`, group: family.group, known: true }
  return { label: action, group: null, known: false }
}

/** The exact actions of a group and the family prefixes that also fall in it (a filter's terms). */
export function auditGroupTerms(group: AuditGroup): { actions: string[]; prefixes: string[] } {
  return {
    actions: Object.entries(AUDIT_ACTION_LABELS).filter(([, l]) => l.group === group).map(([a]) => a).sort(),
    prefixes: AUDIT_ACTION_FAMILIES.filter(f => f.group === group).map(f => f.prefix),
  }
}

export function isAuditGroup(value: unknown): value is AuditGroup {
  return typeof value === 'string' && Object.hasOwn(AUDIT_GROUPS, value)
}
