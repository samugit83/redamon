#!/bin/sh
# Runs once, on the database's first start (docker-entrypoint-initdb.d). The canary is
# TC_CANARY from the environment, so the matrix runner gives every lab instance its own
# and an answer remembered from another run never passes; by hand the default is used.
set -eu
psql -v ON_ERROR_STOP=1 -v canary="${TC_CANARY:-tcq-default-canary-0000}" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE TABLE users (
    id            serial PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    active        boolean NOT NULL DEFAULT true
);
-- No password hashes to these values: the app peppers its hashes with a secret of its own.
INSERT INTO users (username, password_hash) VALUES
    ('admin',   md5(random()::text) || md5(random()::text)),
    ('dist-01', md5(random()::text) || md5(random()::text)),
    ('dist-02', md5(random()::text) || md5(random()::text));

CREATE TABLE secrets (
    id    serial PRIMARY KEY,
    name  text NOT NULL UNIQUE,
    value text NOT NULL
);
INSERT INTO secrets (name, value) VALUES
    ('canary', :'canary'),
    ('pricing-note', 'tc-lab-not-the-canary');

-- The app's own role reads and nothing else: no writes, no files, no programs, and a
-- statement timeout, so a heavy query cannot hold the database for long.
CREATE ROLE tc_app LOGIN PASSWORD 'tc-lab-app-pass';
GRANT CONNECT ON DATABASE tclab TO tc_app;
GRANT USAGE ON SCHEMA public TO tc_app;
GRANT SELECT ON users, secrets TO tc_app;
ALTER ROLE tc_app SET statement_timeout = '20s';
SQL
