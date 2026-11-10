-- SYNTHETIC seed for the tunnel_rows upgrade scenario: no real user, host or secret.
-- Two members hold tunnel credentials (an ngrok token; a chisel URL with no auth, which
-- chisel accepts). Two admins hold different capture settings: in 7.7.x the admin
-- settings row saved last (updated_at) is the one in force, here admin B's.
-- The member rows are inserted first: GET /api/global/tunnel-config takes the first
-- configured row with no ORDER BY.
-- Password of every account with one: rbac-upgrade-pass-0001 (bcrypt, 12 rounds).

INSERT INTO users (id, name, email, password, role, created_at, updated_at) VALUES
  ('upg-admin-a', 'Upg Admin A', 'upg-admin-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-01-05 09:00:00', '2026-01-05 09:00:00'),
  ('upg-admin-b', 'Upg Admin B', 'upg-admin-b@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-02-10 09:00:00', '2026-02-10 09:00:00'),
  ('upg-member-a', 'Upg Member A', 'upg-member-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-03-01 09:00:00', '2026-03-01 09:00:00'),
  ('upg-member-b', 'Upg Member B', 'upg-member-b@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-03-02 09:00:00', '2026-03-02 09:00:00');

INSERT INTO user_settings (id, user_id, tunnels_enabled, ngrok_authtoken, chisel_server_url, chisel_auth, updated_at) VALUES
  ('upg-set-member-a', 'upg-member-a', true, 'upg-fake-ngrok-token-0001', '', '', '2026-03-10 09:00:00'),
  ('upg-set-member-b', 'upg-member-b', true, '', 'https://chisel.upg.test:8443', '', '2026-03-20 09:00:00');

INSERT INTO user_settings (id, user_id, capture_proxy_enabled, capture_proxy_retention_days,
                           capture_proxy_store_bodies, updated_at) VALUES
  ('upg-set-admin-a', 'upg-admin-a', true, 14, true, '2026-03-01 09:00:00'),
  ('upg-set-admin-b', 'upg-admin-b', false, 30, false, '2026-04-01 09:00:00');

INSERT INTO projects (id, user_id, name, target_domain, created_at, updated_at) VALUES
  ('upg-p-a', 'upg-member-a', 'upg-PA', 'upg-a.test', '2026-03-03 09:00:00', '2026-03-03 09:00:00');
