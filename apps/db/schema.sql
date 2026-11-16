-- Database for the sensor portal (db-01 of each site). Run once: psql -d ssle -f schema.sql

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL            -- never the password itself (werkzeug pbkdf2 hash)
);

CREATE TABLE IF NOT EXISTS readings (
    id     BIGSERIAL PRIMARY KEY,
    sensor TEXT             NOT NULL,
    value  DOUBLE PRECISION NOT NULL,
    ts     TIMESTAMPTZ      NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS readings_sensor_ts ON readings (sensor, ts DESC);

-- Two database roles, least privilege (see docs/architecture.md):
--   api        reads/writes users and readings
--   analytics  read-only, so a compromised analytics-01 can't change data
-- Passwords are set by the build script, not stored here (no secrets in git).
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api')       THEN CREATE ROLE api LOGIN;       END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'analytics') THEN CREATE ROLE analytics LOGIN; END IF;
END $$;

GRANT SELECT, INSERT                 ON users, readings TO api;
GRANT USAGE                          ON SEQUENCE readings_id_seq TO api;
GRANT SELECT                         ON readings TO analytics;
