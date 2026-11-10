-- SYNTHETIC seed for the members_with_tools upgrade scenario: no real user, host or secret.
-- Standard members with and without passwords next to one admin. In 7.7.x every
-- signed-in account reaches the instance-wide tools (Kali terminal, shell sessions,
-- tunnels, the MCP manifest); a passwordless account never signs in. Member A also
-- keeps a stdio MCP server in its settings (a harmless command).
-- Password of every account with one: rbac-upgrade-pass-0001 (bcrypt, 12 rounds).

INSERT INTO users (id, name, email, password, role, created_at, updated_at) VALUES
  ('upg-admin-a', 'Upg Admin A', 'upg-admin-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'admin',
   '2026-01-05 09:00:00', '2026-01-05 09:00:00'),
  ('upg-member-a', 'Upg Member A', 'upg-member-a@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-02-01 09:00:00', '2026-02-01 09:00:00'),
  ('upg-member-b', 'Upg Member B', 'upg-member-b@e2e.local',
   '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42', 'standard',
   '2026-02-02 09:00:00', '2026-02-02 09:00:00'),
  ('upg-member-c', 'Upg Member C', 'upg-member-c@e2e.local', '', 'standard',
   '2026-02-03 09:00:00', '2026-02-03 09:00:00'),
  ('upg-member-d', 'Upg Member D', 'upg-member-d@e2e.local', '', 'standard',
   '2026-02-04 09:00:00', '2026-02-04 09:00:00');

INSERT INTO user_settings (id, user_id, tavily_api_key, mcp_servers, updated_at) VALUES
  ('upg-set-member-a', 'upg-member-a', 'upg-fake-tavily-key-0001',
   '[{"id": "upg_stdio", "name": "upg stdio", "description": "", "enabled": true, "transport": "stdio", "default_phases": ["informational"], "tags": [], "headers": {}, "connect_timeout": 60, "read_timeout": 600, "command": "true", "args": [], "env": {}, "cwd": "", "encoding": "utf-8", "tools": []}]',
   '2026-02-05 09:00:00');

INSERT INTO projects (id, user_id, name, target_domain, created_at, updated_at) VALUES
  ('upg-p-a', 'upg-member-a', 'upg-PA', 'upg-a.test', '2026-02-06 09:00:00', '2026-02-06 09:00:00'),
  ('upg-p-c', 'upg-member-c', 'upg-PC', 'upg-c.test', '2026-02-07 09:00:00', '2026-02-07 09:00:00');
