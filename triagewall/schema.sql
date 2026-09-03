CREATE TABLE IF NOT EXISTS triage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    flow_id INTEGER,                         -- nullable: decoder alerts have no flow
    src_ip TEXT,                             -- nullable
    src_port INTEGER,                        -- nullable
    dest_ip TEXT,                            -- nullable
    dest_port INTEGER,                       -- nullable
    proto TEXT,                              -- nullable
    in_iface TEXT,                           -- you have this consistently
    pkt_src TEXT,                            -- you have this consistently
    
    signature_id INTEGER NOT NULL,           -- always present
    signature TEXT NOT NULL,                 -- always present
    category TEXT,
    severity INTEGER,
    action TEXT,                             -- allowed/blocked
    
    raw_alert TEXT NOT NULL,                 -- full JSON for re-processing
    raw_alert_bytes INTEGER,                 -- UTF-8 byte length of raw_alert

    -- Agent verdict
    verdict TEXT,                            -- 'real' | 'false_positive' | 'uncertain' | NULL until processed
    confidence REAL,
    reasoning TEXT,
    model_used TEXT,
    processed_at TEXT,
    src_asset_snapshot_id INTEGER,
    dest_asset_snapshot_id INTEGER,
    config_generation INTEGER,
    prefilter_revision TEXT,
    asset_revision TEXT,
    
    -- Human feedback
    human_verdict TEXT,
    human_notes TEXT,
    agreed BOOLEAN,
    reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_triage_dup_check ON triage_events(flow_id, signature_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_model_processed_at ON triage_events(model_used, processed_at);

CREATE INDEX IF NOT EXISTS idx_triage_timestamp ON triage_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_triage_signature_id ON triage_events(signature_id);
CREATE INDEX IF NOT EXISTS idx_triage_verdict ON triage_events(verdict);
CREATE INDEX IF NOT EXISTS idx_triage_processed ON triage_events(processed_at);
CREATE INDEX IF NOT EXISTS idx_triage_src_asset_snapshot
ON triage_events(src_asset_snapshot_id)
WHERE src_asset_snapshot_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_triage_dest_asset_snapshot
ON triage_events(dest_asset_snapshot_id)
WHERE dest_asset_snapshot_id IS NOT NULL;

-- Complete input records that cannot be triaged are retained before the
-- ingest checkpoint advances, so malformed or unsupported input is not lost.
CREATE TABLE IF NOT EXISTS ingest_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL DEFAULT 'suricata',
    raw_line TEXT NOT NULL,
    error TEXT NOT NULL,
    failed_at TEXT NOT NULL
);

-- Canonical operator context used for a verdict. Each JSON document contains
-- the full inventory revision so later inventory edits cannot rewrite history.
CREATE TABLE IF NOT EXISTS asset_snapshots (
    id INTEGER PRIMARY KEY,
    snapshot_hash TEXT NOT NULL UNIQUE,
    asset_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Source provenance is kept in a companion table so existing triage_events
-- databases do not require a backfill or table rewrite.
CREATE TABLE IF NOT EXISTS sensor_event_context (
    triage_event_id INTEGER PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_instance TEXT,
    source_event_id TEXT,
    agent_id TEXT,
    agent_name TEXT,
    FOREIGN KEY (triage_event_id) REFERENCES triage_events(id) ON DELETE CASCADE,
    UNIQUE (source_type, source_instance, source_event_id)
);

-- SQLite treats NULL values as distinct inside a UNIQUE table constraint.
-- Normalize the optional instance for events that do carry a stable source ID
-- so adapters cannot persist the same instance-less event more than once.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sensor_event_source_identity
ON sensor_event_context (
    source_type,
    COALESCE(source_instance, ''),
    source_event_id
)
WHERE source_event_id IS NOT NULL;

-- Optional Zeek evidence and the policy decision that led to its lookup are
-- retained separately from the core event. Rows exist only when enrichment
-- was enabled for that ingest decision; absence means "not evaluated".
CREATE TABLE IF NOT EXISTS zeek_alert_enrichment (
    triage_event_id INTEGER PRIMARY KEY,
    eligibility_reason TEXT NOT NULL CHECK (eligibility_reason IN (
        'eligible', 'prefilter_resolved', 'unsupported_source',
        'missing_endpoint', 'unsupported_protocol', 'missing_port'
    )),
    lookup_status TEXT NOT NULL CHECK (lookup_status IN (
        'disabled', 'matched', 'no_match', 'ambiguous', 'unavailable',
        'invalid_response'
    )),
    source_instance TEXT CHECK (
        source_instance IS NULL OR length(source_instance) BETWEEN 1 AND 128
    ),
    match_strategy TEXT CHECK (
        match_strategy IS NULL OR length(match_strategy) BETWEEN 1 AND 128
    ),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 32),
    candidate_count INTEGER NOT NULL CHECK (candidate_count BETWEEN 0 AND 33),
    truncated INTEGER NOT NULL CHECK (truncated IN (0, 1)),
    context_json TEXT CHECK (
        context_json IS NULL OR length(CAST(context_json AS BLOB)) <= 65536
    ),
    recorded_at TEXT NOT NULL,
    CHECK (eligibility_reason = 'eligible' OR lookup_status = 'disabled'),
    CHECK (
        (
            lookup_status = 'matched'
            AND context_json IS NOT NULL
            AND record_count >= 1
            AND candidate_count = 1
        ) OR (
            lookup_status = 'ambiguous'
            AND context_json IS NULL
            AND record_count = 0
            AND candidate_count >= 2
        ) OR (
            lookup_status NOT IN ('matched', 'ambiguous')
            AND context_json IS NULL
            AND record_count = 0
            AND candidate_count = 0
            AND truncated = 0
        )
    ),
    FOREIGN KEY (triage_event_id) REFERENCES triage_events(id) ON DELETE CASCADE
);

-- Immutable, canonical operator configuration documents. Content is never
-- updated in place; lifecycle metadata changes as a revision is validated,
-- activated, superseded, rejected, or reactivated for rollback.
CREATE TABLE IF NOT EXISTS operator_config_revisions (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('prefilter_policy', 'asset_inventory')),
    revision TEXT NOT NULL,
    document_json TEXT NOT NULL CHECK (length(document_json) <= 1048576),
    source TEXT NOT NULL CHECK (source IN ('shipped', 'operator_import', 'operator')),
    parent_revision_id INTEGER,
    shipped_base_revision TEXT,
    state TEXT NOT NULL CHECK (
        state IN ('draft', 'validated', 'active', 'superseded', 'rejected')
    ),
    validation_json TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    note TEXT,
    FOREIGN KEY (parent_revision_id) REFERENCES operator_config_revisions(id),
    UNIQUE (kind, revision)
);

CREATE INDEX IF NOT EXISTS idx_operator_config_revisions_kind_state
ON operator_config_revisions(kind, state, id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_operator_config_one_active_kind
ON operator_config_revisions(kind)
WHERE state = 'active';

-- One singleton row names the complete active configuration bundle. A single
-- generation prevents consumers from observing a half-activated pair.
CREATE TABLE IF NOT EXISTS operator_config_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active_prefilter_revision_id INTEGER NOT NULL,
    active_asset_revision_id INTEGER NOT NULL,
    previous_prefilter_revision_id INTEGER,
    previous_asset_revision_id INTEGER,
    mode TEXT NOT NULL DEFAULT 'legacy' CHECK (mode IN ('legacy', 'database')),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    updated_at TEXT NOT NULL,
    FOREIGN KEY (active_prefilter_revision_id)
        REFERENCES operator_config_revisions(id),
    FOREIGN KEY (active_asset_revision_id)
        REFERENCES operator_config_revisions(id),
    FOREIGN KEY (previous_prefilter_revision_id)
        REFERENCES operator_config_revisions(id),
    FOREIGN KEY (previous_asset_revision_id)
        REFERENCES operator_config_revisions(id)
);

-- Append-only lifecycle evidence. Configuration content, credentials, and
-- sensor records are deliberately excluded from audit details.
CREATE TABLE IF NOT EXISTS operator_config_audit (
    id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    kind TEXT CHECK (
        kind IS NULL OR kind IN ('prefilter_policy', 'asset_inventory')
    ),
    revision_id INTEGER,
    from_revision_id INTEGER,
    to_revision_id INTEGER,
    actor TEXT NOT NULL,
    auth_via TEXT NOT NULL,
    request_id TEXT,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (revision_id) REFERENCES operator_config_revisions(id),
    FOREIGN KEY (from_revision_id) REFERENCES operator_config_revisions(id),
    FOREIGN KEY (to_revision_id) REFERENCES operator_config_revisions(id)
);

CREATE INDEX IF NOT EXISTS idx_operator_config_audit_occurred
ON operator_config_audit(occurred_at, id);

-- Cross-process reload health. Each consumer owns exactly one bounded status
-- row; configuration content and sensor data are never stored here.
CREATE TABLE IF NOT EXISTS operator_config_consumers (
    consumer TEXT PRIMARY KEY CHECK (consumer IN ('suricata', 'wazuh')),
    loaded_generation INTEGER NOT NULL CHECK (loaded_generation >= 1),
    desired_generation INTEGER NOT NULL CHECK (desired_generation >= 1),
    status TEXT NOT NULL CHECK (status IN ('ok', 'error')),
    prefilter_revision TEXT NOT NULL,
    asset_revision TEXT NOT NULL,
    loaded_at TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 512)
);
