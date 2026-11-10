-- SYNTHETIC seed for the no_admin upgrade scenario: no real user, host or secret.
-- Two standard members with passwords and a project each, and no admin at all.
-- Password of every account with one: rbac-upgrade-pass-0001 (bcrypt, 12 rounds).

INSERT INTO users (id, name, email, password, role, created_at, updated_at) VALUES
  ('upg-member-a', 'Upg Member A', 'upg-member-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-01-05 09:00:00', '2026-01-05 09:00:00'),
  ('upg-member-b', 'Upg Member B', 'upg-member-b@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-02-10 09:00:00', '2026-02-10 09:00:00');

INSERT INTO projects (id, user_id, name, target_domain, created_at, updated_at) VALUES
  ('upg-p-a', 'upg-member-a', 'upg-PA', 'upg-a.test', '2026-01-06 09:00:00', '2026-01-06 09:00:00'),
  ('upg-p-b', 'upg-member-b', 'upg-PB', 'upg-b.test', '2026-02-11 09:00:00', '2026-02-11 09:00:00');
