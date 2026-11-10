-- SYNTHETIC seed for the several_admins upgrade scenario: no real user, host or secret.
-- Three admins whose id order (a < b < c) is the reverse of their creation order
-- (c oldest, a newest), so a rule that picks "the oldest admin" cannot pass by
-- reading the first id. One standard member with a project.
-- Password of every account with one: rbac-upgrade-pass-0001 (bcrypt, 12 rounds).

INSERT INTO users (id, name, email, password, role, created_at, updated_at) VALUES
  ('upg-admin-a', 'Upg Admin A', 'upg-admin-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-03-15 09:00:00', '2026-03-15 09:00:00'),
  ('upg-admin-b', 'Upg Admin B', 'upg-admin-b@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-02-10 09:00:00', '2026-02-10 09:00:00'),
  ('upg-admin-c', 'Upg Admin C', 'upg-admin-c@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-01-05 09:00:00', '2026-01-05 09:00:00'),
  ('upg-member-a', 'Upg Member A', 'upg-member-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-04-01 09:00:00', '2026-04-01 09:00:00');

INSERT INTO projects (id, user_id, name, target_domain, created_at, updated_at) VALUES
  ('upg-p-adm', 'upg-admin-c', 'upg-PADM', 'upg-adm.test', '2026-01-06 09:00:00', '2026-01-06 09:00:00'),
  ('upg-p-a', 'upg-member-a', 'upg-PA', 'upg-a.test', '2026-04-02 09:00:00', '2026-04-02 09:00:00');
