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
