-- Suspicious Login Detection — PostgreSQL schema.
-- Mirrors the SQLAlchemy models in backend/app/models/*.py exactly.
-- The backend also works against sqlite:///./dev_fallback.db (via
-- Base.metadata.create_all at startup) — this file is for the Postgres
-- path described in README section 10.

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) NOT NULL UNIQUE,
    email           VARCHAR(120) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);

CREATE TABLE IF NOT EXISTS login_attempts (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER REFERENCES users(id),
    username_attempted      VARCHAR(50) NOT NULL,
    network_context         VARCHAR(30),
    security_action         VARCHAR(20),
    evaluated_login_hour    INTEGER,
    ml_features_json        TEXT,
    ip_address              VARCHAR(45) NOT NULL,
    location                VARCHAR(100),
    latitude                DOUBLE PRECISION,
    longitude               DOUBLE PRECISION,
    is_simulated_location   BOOLEAN DEFAULT TRUE,
    device                  VARCHAR(100),
    browser                 VARCHAR(100),
    operating_system        VARCHAR(100),
    login_timestamp         TIMESTAMPTZ DEFAULT now(),
    authentication_result   VARCHAR(20) NOT NULL,      -- success | failure | pending | blocked
    failed_attempt_count    INTEGER DEFAULT 0,
    risk_score              DOUBLE PRECISION DEFAULT 0,
    risk_level              VARCHAR(10) DEFAULT 'LOW',  -- LOW | MEDIUM | HIGH
    is_suspicious           BOOLEAN DEFAULT FALSE,
    detection_reasons       TEXT,                       -- JSON-encoded list of strings
    ml_anomaly_score        DOUBLE PRECISION,
    ml_is_anomaly           BOOLEAN,
    otp_required            BOOLEAN DEFAULT FALSE,
    otp_verified            BOOLEAN DEFAULT FALSE,
    otp_code_hash           VARCHAR(255),
    otp_expires_at          TIMESTAMPTZ,
    otp_attempts            INTEGER DEFAULT 0,
    created_at              TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_login_attempts_user_id ON login_attempts (user_id);
CREATE INDEX IF NOT EXISTS ix_login_attempts_username_attempted ON login_attempts (username_attempted);
CREATE INDEX IF NOT EXISTS ix_login_attempts_login_timestamp ON login_attempts (login_timestamp);
CREATE INDEX IF NOT EXISTS ix_login_attempts_risk_level ON login_attempts (risk_level);
CREATE INDEX IF NOT EXISTS ix_login_attempts_is_suspicious ON login_attempts (is_suspicious);

CREATE TABLE IF NOT EXISTS security_alerts (
    id                  SERIAL PRIMARY KEY,
    login_attempt_id    INTEGER NOT NULL REFERENCES login_attempts(id),
    user_id             INTEGER REFERENCES users(id),
    alert_type          VARCHAR(50) NOT NULL,   -- HIGH_RISK_LOGIN | UNUSUAL_ACTIVITY
    severity            VARCHAR(10) NOT NULL,   -- LOW | MEDIUM | HIGH
    message             TEXT NOT NULL,
    status              VARCHAR(20) DEFAULT 'OPEN',  -- OPEN | RESOLVED
    created_at          TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_security_alerts_login_attempt_id ON security_alerts (login_attempt_id);
CREATE INDEX IF NOT EXISTS ix_security_alerts_user_id ON security_alerts (user_id);
CREATE INDEX IF NOT EXISTS ix_security_alerts_severity ON security_alerts (severity);
CREATE INDEX IF NOT EXISTS ix_security_alerts_status ON security_alerts (status);

CREATE TABLE IF NOT EXISTS user_behavior_profiles (
    id                          SERIAL PRIMARY KEY,
    user_id                     INTEGER NOT NULL UNIQUE REFERENCES users(id),
    known_locations             TEXT DEFAULT '[]',  -- JSON list of strings
    known_devices               TEXT DEFAULT '[]',
    known_browsers              TEXT DEFAULT '[]',
    known_ips                   TEXT DEFAULT '[]',
    known_os                    TEXT DEFAULT '[]',
    usual_login_hour_start      INTEGER DEFAULT 8,
    usual_login_hour_end        INTEGER DEFAULT 22,
    average_failed_attempts     DOUBLE PRECISION DEFAULT 0,
    total_logins                INTEGER DEFAULT 0,
    successful_logins           INTEGER DEFAULT 0,
    last_login_at               TIMESTAMPTZ,
    updated_at                  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_user_behavior_profiles_user_id ON user_behavior_profiles (user_id);
