-- SYNTHETIC seed for the one_admin upgrade scenario: no real user, host or secret.
-- One admin and one standard member, each with a project. Applied on top of the
-- schema the redamon-webapp:rbac-7.7.2 startup list creates (`rbac_upgrade_live.sh regen`).
-- Password of every account with one: rbac-upgrade-pass-0001 (bcrypt, 12 rounds).

INSERT INTO users (id, name, email, password, role, created_at, updated_at) VALUES
  ('upg-admin-a', 'Upg Admin A', 'upg-admin-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-01-05 09:00:00', '2026-01-05 09:00:00'),
  ('upg-member-a', 'Upg Member A', 'upg-member-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-02-01 09:00:00', '2026-02-01 09:00:00');

INSERT INTO projects (id, user_id, name, target_domain, created_at, updated_at) VALUES
  ('upg-p-adm', 'upg-admin-a', 'upg-PADM', 'upg-adm.test', '2026-01-06 09:00:00', '2026-01-06 09:00:00'),
  ('upg-p-a', 'upg-member-a', 'upg-PA', 'upg-a.test', '2026-02-02 09:00:00', '2026-02-02 09:00:00');
