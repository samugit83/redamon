-- Scenario assertions of tests/rbac_upgrade_live.sh: run through psql (-At, '|' between
-- fields) after every startup-list run and diffed against expected/<scenario>.out.
-- They describe the population each fixture holds, so a run that changes who is
-- admin, who has a password, whose settings are in force, who owns which project or
-- which one-time backfills are marked done shows up as a diff. A later phase that
-- changes these by design appends its own queries and expected lines.

\echo == users (email, role, password state, created, updated)
SELECT email, role,
       CASE WHEN password = '' THEN 'passwordless' ELSE 'password' END,
       created_at, updated_at
  FROM users ORDER BY created_at, email;

\echo == settings (email, tunnels, ngrok token, chisel url, chisel auth, capture on, retention, store bodies, mcp servers, updated)
SELECT u.email, s.tunnels_enabled, s.ngrok_authtoken, s.chisel_server_url, s.chisel_auth,
       s.capture_proxy_enabled, s.capture_proxy_retention_days, s.capture_proxy_store_bodies,
       jsonb_array_length(s.mcp_servers), s.updated_at
  FROM user_settings s JOIN users u ON u.id = s.user_id ORDER BY u.email;

\echo == capture settings in force (the admin row saved last)
SELECT u.email, s.capture_proxy_enabled
  FROM user_settings s JOIN users u ON u.id = s.user_id
 WHERE u.role = 'admin' ORDER BY s.updated_at DESC LIMIT 1;

\echo == tunnel credentials in force (first configured row, no ORDER BY, as GET /api/global/tunnel-config)
SELECT (SELECT email FROM users WHERE id = t.user_id), t.ngrok_authtoken, t.chisel_server_url
  FROM (SELECT user_id, ngrok_authtoken, chisel_server_url FROM user_settings
         WHERE ngrok_authtoken <> '' OR chisel_server_url <> '' LIMIT 1) t;

\echo == projects (name, owner, target)
SELECT p.name, u.email, p.target_domain
  FROM projects p JOIN users u ON u.id = p.user_id ORDER BY p.name;

\echo == one-time markers (action, rows)
SELECT action, count(*) FROM audit_log WHERE source = 'system' GROUP BY action ORDER BY action;
