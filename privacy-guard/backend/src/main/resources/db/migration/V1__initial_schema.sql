-- V1__initial_schema.sql
-- PrivacyGuard initial database schema

CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    email       VARCHAR(255) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    full_name   VARCHAR(255),
    role        VARCHAR(20)  NOT NULL DEFAULT 'USER',
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE scans (
    id                    BIGSERIAL PRIMARY KEY,
    url                   VARCHAR(2048) NOT NULL,
    scan_date             TIMESTAMP     NOT NULL DEFAULT NOW(),
    overall_score         INTEGER,
    gdpr_score            INTEGER,
    ccpa_score            INTEGER,
    coppa_score           INTEGER,
    https_enabled         BOOLEAN,
    ssl_valid             BOOLEAN,
    ssl_expiry_days       INTEGER,
    privacy_policy_found  BOOLEAN,
    cookie_policy_found   BOOLEAN,
    cookie_consent_found  BOOLEAN,
    scan_status           VARCHAR(20)   NOT NULL DEFAULT 'PENDING',
    error_message         TEXT,
    user_id               BIGINT REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_score_range CHECK (overall_score BETWEEN 0 AND 100)
);

CREATE TABLE findings (
    id               BIGSERIAL PRIMARY KEY,
    scan_id          BIGINT       NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category         VARCHAR(50)  NOT NULL,
    severity         VARCHAR(20)  NOT NULL,
    title            VARCHAR(500) NOT NULL,
    description      TEXT         NOT NULL,
    recommendation   TEXT,
    evidence         VARCHAR(2048),
    created_at       TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_scans_user_id    ON scans(user_id);
CREATE INDEX idx_scans_scan_date  ON scans(scan_date DESC);
CREATE INDEX idx_scans_url        ON scans(url);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);

-- Rate limiting table (per-IP scan tracking)
CREATE TABLE rate_limits (
    id          BIGSERIAL PRIMARY KEY,
    ip_address  VARCHAR(45) NOT NULL,
    scan_count  INTEGER     NOT NULL DEFAULT 1,
    window_start TIMESTAMP  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rate_limits_ip ON rate_limits(ip_address, window_start);
