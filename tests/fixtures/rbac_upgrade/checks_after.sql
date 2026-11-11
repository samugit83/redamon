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
