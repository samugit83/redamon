-- What the upgrade adds by design, checked by tests/rbac_upgrade_live.sh after every
-- startup-list run (never on a fixture: these read columns 7.7.x does not have). Its
-- output follows checks.sql's, and both are diffed against expected/<scenario>.after.out.
-- A step that changes the upgrade by design appends its queries here and its lines to
-- every .after.out; audit rows it adds are listed in UPGRADE_AUDIT_ACTIONS of the harness.

\echo == legacy grants (email, grants) [step 1.8]
SELECT email, array_to_string(legacy_grants, ',')
  FROM users ORDER BY created_at, email;

\echo == legacy grants marker (holders of kali_terminal, shell_sessions, tunnels), one line per marker row
SELECT after->>'kali_terminal', after->>'shell_sessions', after->>'tunnels'
  FROM audit_log WHERE action = 'system.rbac_legacy_grants_backfill' ORDER BY created_at;

\echo == accounts created after the legacy grants cutoff
SELECT count(*) FROM users
 WHERE created_at > (SELECT min(created_at) FROM audit_log WHERE action = 'system.rbac_legacy_grants_cutoff');

-- The harness mounts no templates folder and the image has no /data/nuclei-templates, so
-- the backfill finds no file: one final marker that recorded 0 files, and no row.
\echo == nuclei template owners marker (files found, rows written), one line per marker row [step 1.12]
SELECT after->>'files', after->>'rowsCreated'
  FROM audit_log WHERE action = 'system.nuclei_template_owners_backfill' ORDER BY created_at;

\echo == nuclei templates (rows, instance rows)
SELECT count(*), count(*) FILTER (WHERE owner_user_id IS NULL) FROM nuclei_templates;

-- The identity columns arrive with the defaults that mean "as before": every account
-- active, version 0, no forced change, nothing on hold, no notices; one instance row, the
-- instance settings backfill's (step 2.4), and no invite until an admin writes one; no
-- audit row gains a value.
\echo == identity columns (email, status, session version, must change, last login set, admin profile set, password on hold, notices) [step 2.1]
SELECT email, status, session_version, must_change_password, last_login_at IS NOT NULL,
       admin_profile_id IS NOT NULL, password_on_hold <> '', pending_notices::text
  FROM users ORDER BY created_at, email;

\echo == identity tables (instance settings rows, invite rows)
SELECT (SELECT count(*) FROM instance_settings), (SELECT count(*) FROM user_invites);

\echo == audit columns set (on behalf of, project, permission, actor email, act-as reason, duration, ended by)
SELECT (SELECT count(*) FROM audit_log WHERE on_behalf_of_user_id IS NOT NULL),
       (SELECT count(*) FROM audit_log WHERE project_id IS NOT NULL),
       (SELECT count(*) FROM audit_log WHERE permission IS NOT NULL),
       (SELECT count(*) FROM audit_log WHERE actor_email IS NOT NULL),
       (SELECT count(*) FROM act_as_audit WHERE reason IS NOT NULL),
       (SELECT count(*) FROM act_as_audit WHERE duration_minutes IS NOT NULL),
       (SELECT count(*) FROM act_as_audit WHERE ended_by IS NOT NULL);

-- The instance settings row holds the values the readers pick in the user rows: the tunnel
-- row enabled first, then saved last, then the lowest id; the capture settings of the admin
-- row saved last; each group's source account; no admin wrote it. The harness runs with the
-- identity switch off: one marker, and a second run that changes nothing writes none.
\echo == instance settings (tunnels, ngrok token, chisel url, chisel auth, tunnel source, capture on, retention, store bodies, capture source, written by an admin) [step 2.4]
SELECT i.tunnels_enabled, i.ngrok_authtoken, i.chisel_server_url, i.chisel_auth,
       (SELECT email FROM users WHERE id = i.tunnel_source_user_id),
       i.capture_proxy_enabled, i.capture_proxy_retention_days, i.capture_proxy_store_bodies,
       (SELECT email FROM users WHERE id = i.capture_source_user_id), i.updated_by_id IS NOT NULL
  FROM instance_settings i;

\echo == instance settings marker (identity, wrote, tunnel source, capture source, tunnel candidates, capture candidates), one line per marker row
SELECT after->>'identity', after->>'wrote', after->>'tunnelSourceUserId', after->>'captureSourceUserId',
       after->'tunnelCandidates', after->'captureCandidates'
  FROM audit_log WHERE action = 'system.rbac_instance_settings_backfill' ORDER BY created_at;

-- The boot recognises the Root (step 2.5): the only admin with a password, or the oldest of
-- several (created_at, then id), automatic and unconfirmed until the host confirms it; no Root
-- when no admin has a password (the row stays as the instance settings backfill wrote it). One
-- marker records the choice, and a second run, or a second copy, changes nothing.
\echo == root (email, confirmed, assigned by, transfer pending) [step 2.5]
SELECT (SELECT email FROM users WHERE id = i.root_user_id), i.root_confirmed_at IS NOT NULL,
       i.root_assigned_by, i.pending_root_transfer_to IS NOT NULL
  FROM instance_settings i;

\echo == root marker (user, rule, candidates, previous root), one line per marker row
SELECT target_id, after->>'rule', after->>'candidateCount', after->>'previousRootUserId'
  FROM audit_log WHERE action = 'system.rbac_root_assigned' ORDER BY created_at;

-- The permission tables arrive empty (step 3.3): no custom set, no assignment, no override,
-- so every account resolves to its account type's default, as before the upgrade.
\echo == permission tables (sets, set assignments, overrides) [step 3.3]
SELECT (SELECT count(*) FROM permission_sets), (SELECT count(*) FROM user_permission_sets),
       (SELECT count(*) FROM user_permission_overrides);

-- The legacy-grant conversion (step 3.15) runs only with RBAC_PERMISSIONS_ENABLED on: with it
-- off no marker (and no override, the line above). With it on, one marker: the fixtures hold
-- no Keep decision (7.7.x had no review), so every grant a member holds lapses, no override is
-- written, and a second run, or a second copy, writes nothing (expected/*.after.permissions.out).
\echo == legacy grants conversion marker (converted, lapsed, already overridden, changed since, past their days), one line per marker row [step 3.15]
SELECT after->>'converted', after->>'lapsed', after->>'overridden', after->>'superseded', after->>'expired'
  FROM audit_log WHERE action = 'system.rbac_legacy_overrides_backfill' ORDER BY created_at;

-- The sharing tables arrive empty and every MCP token keeps reaching only its owner's projects
-- (step 4.2): no share, no break-glass row, no token opted in or narrowed. The fixtures hold no
-- token, so the two token columns' defaults are checked too: an existing token reads as before.
-- The sharing policy stays the column default {}, which reads as sharing off until Root turns it on.
\echo == sharing tables (collaborators, break-glass rows, tokens opted in, tokens with an allowlist) [step 4.2]
SELECT (SELECT count(*) FROM project_collaborators), (SELECT count(*) FROM project_break_glass),
       (SELECT count(*) FROM mcp_access_tokens WHERE include_shared_projects),
       (SELECT count(*) FROM mcp_access_tokens WHERE cardinality(project_allowlist) > 0);

\echo == token sharing columns (column, default, nullable)
SELECT column_name, column_default, is_nullable FROM information_schema.columns
 WHERE table_schema = 'public' AND table_name = 'mcp_access_tokens'
   AND column_name IN ('include_shared_projects', 'project_allowlist')
 ORDER BY column_name;

\echo == sharing policy (stored)
SELECT sharing_policy::text FROM instance_settings;

-- The plugin allowlist table arrives empty (step 6.9): no plugin has a rule, so every plugin stays
-- available to everyone holding plugins:use, whatever RBAC_GOVERNANCE_ENABLED says.
\echo == plugin access rules [step 6.9]
SELECT count(*) FROM plugin_access_rules;

-- Device sessions arrive empty (step 6.10): a row is written only at a sign-in with
-- RBAC_GOVERNANCE_ENABLED on, and a login token without `sid` stays valid, so every existing session
-- goes on as before.
\echo == user sessions [step 6.10]
SELECT count(*) FROM user_sessions;

-- Instance LLM providers arrive empty and the policy off (step 6.11): no provider is offered, no
-- assignment exists, no usage is counted, and every account keeps its own providers.
\echo == instance llm providers, assignments, usage, byo policy [step 6.11]
SELECT (SELECT count(*) FROM instance_llm_providers) || '|' || (SELECT count(*) FROM permission_set_providers)
  || '|' || (SELECT count(*) FROM quota_usage) || '|' || coalesce((SELECT byo_llm_forbidden::text FROM instance_settings), 'no row');

-- Schedules gain a nullable pause reason (step 5.5): every existing schedule reads null, so none
-- counts as paused for lost access and each keeps its enabled state and its actor.
\echo == scan schedule pause reason column, schedules paused for access [step 5.5]
SELECT (SELECT count(*) FROM information_schema.columns
        WHERE table_name = 'scan_schedules' AND column_name = 'paused_reason')
  || '|' || (SELECT count(*) FROM scan_schedules WHERE paused_reason IS NOT NULL);

-- Projects gain an access policy table (step 5.6): it arrives empty, so no project's owner has
-- consented to collaborators spending its credentials and every collaborator's run toggle stays off.
\echo == project access policies, consents to spend owner credentials [step 5.6]
SELECT (SELECT count(*) FROM information_schema.tables WHERE table_name = 'project_access_policies')
  || '|' || (SELECT count(*) FROM project_access_policies WHERE owner_credential_consent_at IS NOT NULL);
