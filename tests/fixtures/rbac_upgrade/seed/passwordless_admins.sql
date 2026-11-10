-- SYNTHETIC seed for the passwordless_admins upgrade scenario: no real user, host or secret.
-- Every admin is passwordless (password '', the column default: an account that can
-- never sign in). One standard member with a password and a project, one passwordless
-- standard member.
-- Password of every account with one: rbac-upgrade-pass-0001 (bcrypt, 12 rounds).

INSERT INTO users (id, name, email, password, role, created_at, updated_at) VALUES
  ('upg-admin-a', 'Upg Admin A', 'upg-admin-a@e2e.local', '', 'admin',
   '2026-01-05 09:00:00', '2026-01-05 09:00:00'),
  ('upg-admin-b', 'Upg Admin B', 'upg-admin-b@e2e.local', '', 'admin',
   '2026-02-10 09:00:00', '2026-02-10 09:00:00'),
  ('upg-member-a', 'Upg Member A', 'upg-member-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-03-01 09:00:00', '2026-03-01 09:00:00'),
  ('upg-member-b', 'Upg Member B', 'upg-member-b@e2e.local', '', 'standard',
   '2026-03-02 09:00:00', '2026-03-02 09:00:00');

INSERT INTO projects (id, user_id, name, target_domain, created_at, updated_at) VALUES
  ('upg-p-a', 'upg-member-a', 'upg-PA', 'upg-a.test', '2026-03-03 09:00:00', '2026-03-03 09:00:00');
