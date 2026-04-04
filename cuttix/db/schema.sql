PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS hosts (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    vendor      TEXT,
    hostname    TEXT,
    os_guess    TEXT,
    os_confidence REAL DEFAULT 0.0,
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    session_count INTEGER DEFAULT 1,
    is_gateway  INTEGER DEFAULT 0,
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);

CREATE TABLE IF NOT EXISTS ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_mac    TEXT NOT NULL REFERENCES hosts(mac) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL DEFAULT 'open',
    service     TEXT,
    banner      TEXT,
    version     TEXT,
    scanned_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host_mac, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_mac);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type   TEXT NOT NULL,
    severity     TEXT NOT NULL DEFAULT 'medium',
    source_ip    TEXT,
    source_mac   TEXT,
    target_ip    TEXT,
    target_mac   TEXT,
    description  TEXT NOT NULL,
    raw_data     TEXT,
    acknowledged INTEGER DEFAULT 0,
    false_positive INTEGER DEFAULT 0,
    correlation_id TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS spoof_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    action       TEXT NOT NULL,
    target_ip    TEXT NOT NULL,
    target_mac   TEXT NOT NULL,
    operator_ip  TEXT NOT NULL,
    auto_restore_minutes INTEGER DEFAULT 0,
    started_at   TEXT,
    ended_at     TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_mac    TEXT NOT NULL REFERENCES hosts(mac) ON DELETE CASCADE,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    packets_in  INTEGER NOT NULL DEFAULT 0,
    packets_out INTEGER NOT NULL DEFAULT 0,
    sample_period_seconds INTEGER NOT NULL DEFAULT 60,
    sampled_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_bw_host ON bandwidth_samples(host_mac);
CREATE INDEX IF NOT EXISTS idx_bw_time ON bandwidth_samples(sampled_at);

CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_mac    TEXT NOT NULL REFERENCES hosts(mac) ON DELETE CASCADE,
    domain      TEXT NOT NULL,
    query_type  TEXT NOT NULL DEFAULT 'A',
    response_ip TEXT,
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    query_count INTEGER DEFAULT 1,
    UNIQUE(host_mac, domain, query_type)
);

CREATE INDEX IF NOT EXISTS idx_dns_host ON dns_queries(host_mac);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(domain);

CREATE TABLE IF NOT EXISTS config_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO config_state (key, value) VALUES
    ('schema_version', '1'),
    ('disclaimer_accepted', '0');
