-- SYNTHETIC RBAC state of tests/rbac_upgrade_live.sh downgrade: no real user, host or secret.
-- Loaded after the new image's startup list (every switch on), before the downgrade to 7.7.2.
-- It writes a row in every table the RBAC release adds and a value in every column it adds to a
-- 7.7.2 table, around its own dg-*@e2e.local accounts. psql variable: pw, the bcrypt hash of the
-- fixtures' shared password. A table or column the image under test lacks is skipped here; the
-- harness compares what the downgrade report lists with what the old image's db push drops.

SELECT to_regclass('public.conversation_shares') IS NOT NULL AS has_conversation_shares,
       to_regclass('public.project_transfers') IS NOT NULL AS has_project_transfers,
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'conversations'
                AND column_name = 'former_author_id') AS has_former_author,
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'instance_settings'
                AND column_name = 'audit_retention_pending') AS has_retention_pending
\gset

-- dg-admin is the oldest account, so the Root backfill picks it on every boot.
INSERT INTO users (id, name, email, password, role, status, password_on_hold, session_version,
                   must_change_password, pending_notices, admin_profile_id, default_agent_model, created_at, updated_at)
VALUES
  ('dg-admin',    'dg admin',    'dg-admin@e2e.local',    :'pw', 'admin',    'active',   '',    0, false, '[]', NULL, NULL, '2000-01-01', now()),
  ('dg-usermgr',  'dg usermgr',  'dg-usermgr@e2e.local',  :'pw', 'admin',    'active',   '',    0, false, '[]', 'builtin:user-manager', NULL, now(), now()),
  ('dg-owner',    'dg owner',    'dg-owner@e2e.local',    :'pw', 'standard', 'active',   '',    0, false, '[]', NULL, 'instance/dg-prov/gpt-dg', now(), now()),
  ('dg-collab',   'dg collab',   'dg-collab@e2e.local',   :'pw', 'standard', 'active',   '',    0, false, '[]', NULL, NULL, now(), now()),
  ('dg-noaccess', 'dg noaccess', 'dg-noaccess@e2e.local', :'pw', 'standard', 'active',   '',    0, false, '[]', NULL, NULL, now(), now()),
  ('dg-custom',   'dg custom',   'dg-custom@e2e.local',   :'pw', 'standard', 'active',   '',    0, true,  '[{"kind":"dg-notice"}]', NULL, NULL, now(), now()),
  ('dg-member',   'dg member',   'dg-member@e2e.local',   :'pw', 'standard', 'active',   '',    0, false, '[]', NULL, NULL, now(), now()),
  ('dg-disabled', 'dg disabled', 'dg-disabled@e2e.local', '',    'standard', 'disabled', :'pw', 1, false, '[]', NULL, NULL, now(), now()),
  ('dg-invited',  'dg invited',  'dg-invited@e2e.local',  '',    'standard', 'invited',  '',    0, false, '[]', NULL, NULL, now(), now());

UPDATE instance_settings
   SET root_user_id = 'dg-admin', root_confirmed_at = now(), root_assigned_by = 'host',
       sharing_policy = '{"enabled":true,"maxLevel":"write"}', quotas = '{"agentRunsPerDay":50}',
       audit_retention_days = 365, updated_by_id = 'dg-admin'
 WHERE id = 'instance';
\if :has_retention_pending
UPDATE instance_settings
   SET audit_retention_pending = jsonb_build_object('days', 30, 'requestedAt', now(), 'effectiveAt', now() + interval '7 days', 'requestedById', 'dg-admin')
 WHERE id = 'instance';
\endif

INSERT INTO user_invites (id, user_id, kind, token_hash, expires_at, created_by_id)
VALUES ('dg-invite', 'dg-invited', 'invite', 'dg-fake-token-hash', now() + interval '7 days', 'dg-admin');

INSERT INTO permission_sets (id, kind, name, permissions, created_by_id, updated_at)
VALUES ('dg-set', 'member', 'dg scanners only', ARRAY['project:read', 'recon:start'], 'dg-admin', now());
INSERT INTO user_permission_sets (user_id, set_id)
VALUES ('dg-noaccess', 'builtin:no-access'), ('dg-custom', 'dg-set');
INSERT INTO user_permission_overrides (user_id, permission, effect, granted_by_id)
VALUES ('dg-custom', 'agent:chat', 'deny', 'dg-admin');

-- ownership_token's default (uuid()) is the Prisma client's, not the column's.
INSERT INTO projects (id, name, user_id, ownership_token, agent_openai_model, ip_hostname_mode, naabu_run_timeout, updated_at)
VALUES ('dg-p1', 'dg shared project', 'dg-owner', gen_random_uuid()::text, 'instance/dg-prov/gpt-dg', 'record_only', 900, now());
INSERT INTO project_collaborators (project_id, user_id, access, run_scans, granted_by_id, updated_at)
VALUES ('dg-p1', 'dg-collab', 'write', true, 'dg-owner', now());
INSERT INTO project_access_policies (project_id, owner_credential_consent_at, owner_credential_consent_by_id, updated_at)
VALUES ('dg-p1', now(), 'dg-owner', now());
INSERT INTO project_break_glass (id, project_id, user_id, reason, expires_at)
VALUES ('dg-bg', 'dg-p1', 'dg-admin', 'dg incident', now() + interval '1 hour');

INSERT INTO conversations (id, project_id, user_id, session_id, updated_at)
VALUES ('dg-c1', 'dg-p1', 'dg-owner', 'dg-session-1', now());
\if :has_former_author
UPDATE conversations SET former_author_id = 'dg-gone', former_author_label = 'dg-gone@e2e.local' WHERE id = 'dg-c1';
\endif
\if :has_conversation_shares
INSERT INTO conversation_shares (id, conversation_id, shared_by_id) VALUES ('dg-cs', 'dg-c1', 'dg-owner');
\endif
\if :has_project_transfers
INSERT INTO project_transfers (id, project_id, from_user_id, to_user_id, old_owner_role, status)
VALUES ('dg-tr', 'dg-p1', 'dg-owner', 'dg-collab', 'co-owner', 'pending');
\endif

INSERT INTO scan_schedules (id, project_id, user_id, enabled, paused_reason, updated_at)
VALUES ('dg-sch', 'dg-p1', 'dg-collab', false, 'actor_no_access', now());
INSERT INTO mcp_access_tokens (id, user_id, name, token_prefix, token_hash, include_shared_projects, project_allowlist)
VALUES ('dg-tok', 'dg-collab', 'dg token', 'dg_fake', 'dg-fake-mcp-hash', true, ARRAY['dg-p1']);
INSERT INTO user_project_presets (id, user_id, name, settings, updated_at)
VALUES ('dg-preset', 'dg-owner', 'dg preset', '{"agentOpenaiModel":"instance/dg-prov/gpt-dg"}', now());

INSERT INTO instance_llm_providers (id, provider_type, name, api_key, updated_at)
VALUES ('dg-prov', 'openai_compatible', 'dg provider', 'dg-fake-provider-key', now());
INSERT INTO permission_set_providers (set_id, provider_id) VALUES ('dg-set', 'dg-prov');
INSERT INTO quota_usage (user_id, day, kind, count, updated_at) VALUES ('dg-owner', current_date, 'agent_runs', 3, now());
INSERT INTO plugin_access_rules (plugin_id, set_id, created_by_id) VALUES ('dg-plugin', 'dg-set', 'dg-admin');
INSERT INTO nuclei_templates (id, path, owner_user_id, updated_at) VALUES ('dg-tpl', 'dg/dg-template.yaml', 'dg-owner', now());

INSERT INTO audit_log (id, action, target_type, target_id, actor_id, on_behalf_of_user_id, project_id, permission, actor_email, source)
VALUES ('dg-audit', 'dg.synthetic', 'project', 'dg-p1', 'dg-admin', 'dg-owner', 'dg-p1', 'project:read', 'dg-admin@e2e.local', 'api');
INSERT INTO act_as_audit (id, admin_id, target_user_id, event, reason, duration_minutes, ended_by)
VALUES ('dg-actas', 'dg-admin', 'dg-owner', 'end', 'dg support', 30, 'dg-admin');
