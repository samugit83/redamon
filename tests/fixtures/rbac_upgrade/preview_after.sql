-- What the startup list wrote, in the lines tests/rbac_upgrade_live.sh preview makes of the
-- upgrade preview (webapp/scripts/rbac-upgrade-preview.mjs) printed before it. Run after the
-- list only; one `<section>|<fact>` per line, sorted and diffed by the harness. Each query
-- names the preview section it answers.

-- review|yes when the preview must ask (its REVIEW_EXIT, 10), by its sections' `affects`: a
-- member who can sign in (member_changes; also every legacy grant), a member's stdio server,
-- an MCP bearer read from the agent's environment, a member's tunnel row or more than one
-- tunnel row. The harness passes SCANNER_API_KEY, so scanner_key never asks. With review|no
-- the harness compares only the two sections printed always (root, instance_settings).
CREATE TEMP VIEW harness_mcp AS
SELECT u.email, u.role, coalesce(nullif(srv->>'name', ''), srv->>'id', '') AS label,
       srv->>'transport' AS transport, coalesce(srv->>'enabled', 'true') <> 'false' AS enabled,
       coalesce(srv->'auth'->>'token_env_var', '') AS token_env_var,
       coalesce(srv->'auth'->>'token', '') <> '' AS has_token
  FROM user_settings s JOIN users u ON u.id = s.user_id
 CROSS JOIN LATERAL jsonb_array_elements(
       CASE WHEN jsonb_typeof(s.mcp_servers) = 'array' THEN s.mcp_servers ELSE '[]'::jsonb END) AS srv
 WHERE jsonb_typeof(srv) = 'object';

CREATE TEMP VIEW harness_tunnels AS
SELECT u.email, CASE WHEN u.role = 'admin' THEN 'admin' ELSE 'member' END AS role,
       concat_ws('+', CASE WHEN s.ngrok_authtoken <> '' THEN 'ngrok' END,
                      CASE WHEN s.chisel_server_url <> '' THEN 'chisel' END) AS kinds,
       CASE WHEN s.tunnels_enabled THEN 'enabled' ELSE 'disabled' END AS state
  FROM user_settings s JOIN users u ON u.id = s.user_id
 WHERE s.ngrok_authtoken <> '' OR s.chisel_server_url <> '';

SELECT 'review|' || CASE WHEN
       EXISTS (SELECT 1 FROM users WHERE role <> 'admin' AND password <> '')
    OR EXISTS (SELECT 1 FROM harness_mcp WHERE transport = 'stdio' AND role <> 'admin')
    OR EXISTS (SELECT 1 FROM harness_mcp WHERE token_env_var <> '' AND NOT has_token)
    OR EXISTS (SELECT 1 FROM harness_tunnels WHERE role = 'member')
    OR (SELECT count(*) FROM harness_tunnels) > 1
  THEN 'yes' ELSE 'no' END;

-- root: the Root the boot chose, its rule and candidate count (its marker); none without one.
SELECT 'root|' || coalesce((
         SELECT u.email || '|' || (a.after->>'rule') || '|' || (a.after->>'candidateCount')
           FROM users u JOIN audit_log a ON a.action = 'system.rbac_root_assigned' AND a.target_id = u.id
          WHERE u.id = i.root_user_id ORDER BY a.created_at DESC LIMIT 1), 'none')
  FROM instance_settings i;

-- legacy_grants: the grants members keep. Until the conversion (RBAC_PERMISSIONS_ENABLED on) that
-- is the column the legacy grants backfill wrote; after it, only the grants kept as overrides
-- (none in any fixture: 7.7.x had no review, so every grant lapses at that boot).
SELECT 'legacy_grants|' || email || '|' || (SELECT string_agg(g, ',' ORDER BY g) FROM unnest(legacy_grants) AS g)
  FROM users
 WHERE cardinality(legacy_grants) > 0
   AND NOT EXISTS (SELECT 1 FROM audit_log WHERE action = 'system.rbac_legacy_overrides_backfill');
SELECT 'legacy_grants|' || u.email || '|' || string_agg(replace(o.permission, 'platform:', ''), ',' ORDER BY o.permission)
  FROM user_permission_overrides o JOIN users u ON u.id = o.user_id
 WHERE o.effect = 'grant' AND o.reason = 'kept from 7.7.x'
   AND EXISTS (SELECT 1 FROM audit_log WHERE action = 'system.rbac_legacy_overrides_backfill')
 GROUP BY u.email;

-- tunnel_rows: every row holding a tunnel credential, and the one the instance settings took.
SELECT 'tunnel_rows|' || email || '|' || role || '|' || kinds || '|' || state FROM harness_tunnels;
SELECT 'tunnel_pick|' || u.email FROM instance_settings i JOIN users u ON u.id = i.tunnel_source_user_id;

-- instance_settings: each group's source account and how many rows were candidates (its marker).
SELECT 'instance_settings|tunnel|' || coalesce(u.email || '|' || jsonb_array_length(m.after->'tunnelCandidates'), 'none')
  FROM instance_settings i
  LEFT JOIN users u ON u.id = i.tunnel_source_user_id
  LEFT JOIN LATERAL (SELECT after FROM audit_log WHERE action = 'system.rbac_instance_settings_backfill'
                      ORDER BY created_at DESC LIMIT 1) AS m ON true;
SELECT 'instance_settings|capture|' || coalesce(u.email || '|' || jsonb_array_length(m.after->'captureCandidates'), 'none')
  FROM instance_settings i
  LEFT JOIN users u ON u.id = i.capture_source_user_id
  LEFT JOIN LATERAL (SELECT after FROM audit_log WHERE action = 'system.rbac_instance_settings_backfill'
                      ORDER BY created_at DESC LIMIT 1) AS m ON true;

-- stdio_mcp: the members' stdio servers, still saved in their accounts (the agent stops loading them).
SELECT 'stdio_mcp|' || email || '|' || label || CASE WHEN enabled THEN '' ELSE ' (disabled)' END
  FROM harness_mcp WHERE transport = 'stdio' AND role <> 'admin';

-- mcp_token_env_var: servers that name an environment variable for their bearer and hold none.
SELECT 'mcp_token_env_var|' || email || '|' || label || '|' || token_env_var
  FROM harness_mcp WHERE token_env_var <> '' AND NOT has_token;
