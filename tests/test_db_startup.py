#!/usr/bin/env python3
"""Regression tests for database schema setup during ingest startup."""

import sqlite3
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import migrations


EXPECTED_INDEXES = {
    "idx_triage_dup_check",
    "idx_model_processed_at",
    "idx_triage_timestamp",
    "idx_triage_signature_id",
    "idx_triage_verdict",
    "idx_triage_processed",
    "idx_triage_src_asset_snapshot",
    "idx_triage_dest_asset_snapshot",
}
SENSOR_IDENTITY_INDEX = "idx_sensor_event_source_identity"


def create_existing_database_without_indexes(db_path: Path) -> None:
    """Create a realistic existing database that has no indexes."""
    schema_path = PROJECT_ROOT / "triagewall" / "schema.sql"
    schema_sql = schema_path.read_text()

    table_sql = schema_sql.split("CREATE INDEX", 1)[0]

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(table_sql)
        conn.execute(
            """
            INSERT INTO triage_events (
                timestamp,
                signature_id,
                signature,
                raw_alert,
                verdict
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "2026-01-01T00:00:00+00:00",
                999999,
                "Existing test alert",
                "{}",
                "uncertain",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def create_legacy_database_without_asset_columns(db_path: Path) -> None:
    """Create the pre-v0.3 schema with a historical verdict row."""
    schema_sql = (PROJECT_ROOT / "triagewall" / "schema.sql").read_text()
    schema_sql = schema_sql.split("\n-- Source provenance", 1)[0]
    schema_sql = schema_sql.replace(
        "    src_asset_snapshot_id INTEGER,\n"
        "    dest_asset_snapshot_id INTEGER,\n",
        "",
    )
    schema_sql = schema_sql.replace(
        "    config_generation INTEGER,\n"
        "    prefilter_revision TEXT,\n"
        "    asset_revision TEXT,\n",
        "",
    )
    schema_sql = schema_sql.replace(
        "    source_type TEXT NOT NULL DEFAULT 'suricata',\n",
        "",
    )
    schema_sql = schema_sql.replace(
        "CREATE INDEX IF NOT EXISTS idx_triage_src_asset_snapshot\n"
        "ON triage_events(src_asset_snapshot_id)\n"
        "WHERE src_asset_snapshot_id IS NOT NULL;\n"
        "CREATE INDEX IF NOT EXISTS idx_triage_dest_asset_snapshot\n"
        "ON triage_events(dest_asset_snapshot_id)\n"
        "WHERE dest_asset_snapshot_id IS NOT NULL;\n",
        "",
    )
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_sql)
        conn.execute(
            """INSERT INTO triage_events
               (timestamp, signature_id, signature, raw_alert, verdict)
               VALUES (?, ?, ?, ?, ?)""",
            ("2026-01-01T00:00:00Z", 42, "Historical", "{}", "uncertain"),
        )
        conn.commit()
    finally:
        conn.close()


class DatabaseStartupTests(unittest.TestCase):
    def test_migration_owner_creates_complete_schema(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            migrations.ensure_db_initialized(db_path)
            migrations.verify_db_initialized(db_path)
            conn = sqlite3.connect(db_path)
            try:
                context_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'sensor_event_context'"""
                ).fetchone()
                zeek_context_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'zeek_alert_enrichment'"""
                ).fetchone()
                context_indexes = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA index_list('sensor_event_context')"
                    ).fetchall()
                }
                failure_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('ingest_failures')")
                }
                spc_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'spc_anomalies'"""
                ).fetchone()
            finally:
                conn.close()

            self.assertEqual(context_table, ("sensor_event_context",))
            self.assertEqual(zeek_context_table, ("zeek_alert_enrichment",))
            self.assertIn(SENSOR_IDENTITY_INDEX, context_indexes)
            self.assertIn("source_type", failure_columns)
            self.assertEqual(spc_table, ("spc_anomalies",))

    def test_existing_database_receives_idempotent_asset_metadata_migration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            create_legacy_database_without_asset_columns(db_path)

            migrations.ensure_db_initialized(db_path)
            migrations.ensure_db_initialized(db_path)

            conn = sqlite3.connect(db_path)
            try:
                columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('triage_events')")
                }
                historical = conn.execute(
                    """SELECT src_asset_snapshot_id, dest_asset_snapshot_id
                       FROM triage_events WHERE signature_id = 42"""
                ).fetchone()
                snapshot_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'asset_snapshots'"""
                ).fetchone()
                sensor_table = conn.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type = 'table' AND name = 'sensor_event_context'"""
                ).fetchone()
                sensor_indexes = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA index_list('sensor_event_context')"
                    ).fetchall()
                }
                failure_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('ingest_failures')")
                }
            finally:
                conn.close()

            self.assertIn("src_asset_snapshot_id", columns)
            self.assertIn("dest_asset_snapshot_id", columns)
            self.assertIn("config_generation", columns)
            self.assertIn("prefilter_revision", columns)
            self.assertIn("asset_revision", columns)
            self.assertEqual(historical, (None, None))
            self.assertEqual(snapshot_table, ("asset_snapshots",))
            self.assertEqual(sensor_table, ("sensor_event_context",))
            self.assertIn(SENSOR_IDENTITY_INDEX, sensor_indexes)
            self.assertIn("source_type", failure_columns)

    def test_existing_database_receives_indexes_without_data_loss(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            create_existing_database_without_indexes(db_path)

            migrations.ensure_db_initialized(db_path)
            migrations.ensure_db_initialized(db_path)

            conn = sqlite3.connect(db_path)
            try:
                actual_indexes = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA index_list('triage_events')"
                    ).fetchall()
                }
                existing_row = conn.execute(
                    "SELECT signature_id, signature, verdict FROM triage_events"
                ).fetchone()
            finally:
                conn.close()

            missing_indexes = EXPECTED_INDEXES - actual_indexes

            self.assertFalse(
                missing_indexes,
                f"Missing indexes: {sorted(missing_indexes)}",
            )
            self.assertEqual(
                existing_row,
                (999999, "Existing test alert", "uncertain"),
            )

    def test_existing_configuration_state_receives_legacy_mode_column(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            migrations.ensure_db_initialized(db_path)
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("DROP TABLE operator_config_state")
                conn.execute(
                    """CREATE TABLE operator_config_state (
                           id INTEGER PRIMARY KEY CHECK (id = 1),
                           active_prefilter_revision_id INTEGER NOT NULL,
                           active_asset_revision_id INTEGER NOT NULL,
                           previous_prefilter_revision_id INTEGER,
                           previous_asset_revision_id INTEGER,
                           generation INTEGER NOT NULL CHECK (generation >= 1),
                           updated_at TEXT NOT NULL
                       )"""
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(
                RuntimeError,
                "operator_config_state.mode",
            ):
                migrations.verify_db_initialized(db_path)

            migrations.ensure_db_initialized(db_path)
            migrations.ensure_db_initialized(db_path)

            conn = sqlite3.connect(db_path)
            try:
                columns = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info('operator_config_state')"
                    )
                }
            finally:
                conn.close()
            self.assertIn("mode", columns)

    def test_non_owner_fails_closed_on_uninitialized_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            sqlite3.connect(db_path).close()

            with self.assertRaisesRegex(
                RuntimeError,
                "run the migration owner first",
            ):
                migrations.verify_db_initialized(db_path)

    def test_failed_schema_step_rolls_back_legacy_column_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "triage.db"
            create_legacy_database_without_asset_columns(db_path)
            original_execute = migrations._execute_statements
            calls = 0

            def fail_second_script(conn, script):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise sqlite3.OperationalError("simulated schema failure")
                original_execute(conn, script)

            with patch.object(
                migrations,
                "_execute_statements",
                side_effect=fail_second_script,
            ), self.assertRaisesRegex(
                sqlite3.OperationalError,
                "simulated schema failure",
            ):
                migrations.ensure_db_initialized(db_path)

            conn = sqlite3.connect(db_path)
            try:
                columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info('triage_events')")
                }
            finally:
                conn.close()

            self.assertNotIn("src_asset_snapshot_id", columns)
            self.assertNotIn("dest_asset_snapshot_id", columns)
            self.assertNotIn("config_generation", columns)
            self.assertNotIn("prefilter_revision", columns)
            self.assertNotIn("asset_revision", columns)

    def test_compose_assigns_one_migration_owner_before_consumers(self):
        base = (PROJECT_ROOT / "docker-compose.yml").read_text()
        wazuh = (PROJECT_ROOT / "docker-compose.wazuh.yml").read_text()
        ingest_source = (PROJECT_ROOT / "triagewall" / "ingest.py").read_text()
        dashboard_source = (
            PROJECT_ROOT / "triagewall" / "dashboard" / "app.py"
        ).read_text()
        wazuh_source = (
            PROJECT_ROOT / "triagewall" / "wazuh_ingest.py"
        ).read_text()

        self.assertEqual(
            len(re.findall(r"^  migrate:$", base, flags=re.MULTILINE)),
            1,
        )
        self.assertIn("triagewall/migrate.py", base)
        self.assertEqual(
            len(re.findall(r"^  config-bootstrap:$", base, flags=re.MULTILINE)),
            1,
        )
        self.assertIn("triagewall/config_bootstrap.py", base)
        self.assertIn("PACKAGED_PREFILTER_PATH", base)
        self.assertIn("LEGACY_PREFILTER_PATH", base)
        self.assertIn("network_mode: none", base)
        self.assertGreaterEqual(
            base.count("condition: service_completed_successfully"),
            3,
        )
        self.assertGreaterEqual(base.count("config-bootstrap:"), 3)
        self.assertIn("config-bootstrap:", wazuh)
        self.assertIn("condition: service_completed_successfully", wazuh)
        self.assertNotIn("ensure_db_initialized", ingest_source)
        self.assertNotIn("ensure_spc_schema", ingest_source)
        self.assertNotIn("ensure_db_initialized", wazuh_source)
        self.assertIn("verify_db_initialized(DB_PATH)", dashboard_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
