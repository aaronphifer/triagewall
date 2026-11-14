"""Standalone Zeek conn.log index, correlation, and checkpoint tests."""

import json
import hashlib
import sqlite3
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

from zeek_context import ZeekLookupRequest, ZeekLookupStatus
from zeek_index import (
    MAX_CONN_RECORD_BYTES,
    MAX_PRUNE_ROWS,
    IndexedLineResult,
    ZeekCheckpointConflict,
    ZeekConnValidationError,
    ZeekIncompleteRecordError,
    ZeekLogCheckpoint,
    ensure_zeek_index,
    index_conn_failure,
    index_conn_line,
    index_evidence_line,
    load_checkpoint,
    lookup_connection,
    normalize_conn_record,
    prune_index,
    rotate_checkpoint,
)


BASE_EPOCH = datetime(2026, 8, 26, 16, 0, tzinfo=timezone.utc).timestamp()
SOURCE_INSTANCE = "zeek-local"


def conn_record(uid="C1", **overrides):
    record = {
        "ts": BASE_EPOCH,
        "uid": uid,
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 51000,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 30.0,
        "orig_bytes": 500,
        "resp_bytes": 900,
        "conn_state": "SF",
        "missed_bytes": 0,
        "orig_pkts": 8,
        "resp_pkts": 10,
    }
    record.update(overrides)
    return record


def json_line(record):
    return json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n"


def request(**overrides):
    values = {
        "alert_timestamp": "2026-08-26T16:00:15Z",
        "src_ip": "192.0.2.10",
        "src_port": 51000,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
    }
    values.update(overrides)
    return ZeekLookupRequest(**values)


class ZeekIndexTestCase(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        ensure_zeek_index(self.conn)

    def tearDown(self):
        self.conn.close()

    def add_line(
        self,
        raw_line,
        *,
        inode=11,
        device=7,
        expected_marker="current",
        file_size=None,
        clock=lambda: BASE_EPOCH + 100,
    ):
        current = load_checkpoint(self.conn, SOURCE_INSTANCE)
        expected = current if expected_marker == "current" else expected_marker
        same_file = (
            current is not None
            and current.device == device
            and current.inode == inode
        )
        start = current.offset if same_file else 0
        raw_bytes = raw_line.encode("utf-8") if isinstance(raw_line, str) else raw_line
        offset = start + len(raw_bytes)
        checkpoint = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=device,
            inode=inode,
            offset=offset,
            file_size=offset if file_size is None else file_size,
        )
        result = index_conn_line(
            self.conn,
            raw_line,
            checkpoint,
            expected_checkpoint=expected,
            clock=clock,
        )
        return result, load_checkpoint(self.conn, SOURCE_INSTANCE)

    def add_evidence_line(
        self,
        log_name,
        record,
        *,
        inode=21,
        device=7,
        clock=lambda: BASE_EPOCH + 100,
    ):
        raw = json_line(record)
        current = load_checkpoint(self.conn, SOURCE_INSTANCE, log_name)
        start = current.offset if current is not None else 0
        checkpoint = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name=log_name,
            device=device,
            inode=inode,
            offset=start + len(raw),
            file_size=start + len(raw),
        )
        return index_evidence_line(
            self.conn,
            raw,
            checkpoint,
            expected_checkpoint=current,
            clock=clock,
        )


class ConnNormalizationTests(ZeekIndexTestCase):
    def test_allowlisted_projection_canonicalizes_network_fields(self):
        record = conn_record(
            **{
                "id.orig_h": "2001:0db8::10",
                "proto": "udp",
                "unknown": "ignored",
            }
        )

        normalized = normalize_conn_record(record, SOURCE_INSTANCE)

        self.assertEqual(normalized.orig_h, "2001:db8::10")
        self.assertEqual(normalized.proto, "UDP")
        self.assertEqual(normalized.end_ts, BASE_EPOCH + 30.0)
        self.assertFalse(hasattr(normalized, "unknown"))

    def test_required_and_optional_fields_fail_closed(self):
        cases = (
            {"uid": "bad uid"},
            {"ts": float("nan")},
            {"ts": 1e300},
            {"id.orig_h": "not-an-ip"},
            {"id.orig_p": True},
            {"id.resp_p": 65536},
            {"proto": "icmp"},
            {"duration": -1},
            {"service": "ignore\nnext"},
            {"orig_bytes": 1.5},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ZeekConnValidationError):
                    normalize_conn_record(conn_record(**overrides), SOURCE_INSTANCE)

    def test_source_instance_is_bounded_and_path_free(self):
        for value in ("../zeek", "", "z" * 129):
            with self.subTest(value=value):
                with self.assertRaises(ZeekConnValidationError):
                    normalize_conn_record(conn_record(), value)


class AtomicIndexCheckpointTests(ZeekIndexTestCase):
    def test_schema_upgrade_adds_archive_anchor_columns_and_retention_index(self):
        legacy = sqlite3.connect(":memory:")
        self.addCleanup(legacy.close)
        legacy.execute(
            """CREATE TABLE zeek_log_checkpoints (
                   source_instance TEXT NOT NULL,
                   log_name TEXT NOT NULL,
                   device INTEGER NOT NULL,
                   inode INTEGER NOT NULL,
                   offset INTEGER NOT NULL,
                   file_size INTEGER NOT NULL,
                   updated_at REAL NOT NULL,
                   PRIMARY KEY (source_instance, log_name)
               ) WITHOUT ROWID"""
        )

        ensure_zeek_index(legacy)

        columns = {
            row[1] for row in legacy.execute("PRAGMA table_info(zeek_log_checkpoints)")
        }
        indexes = {
            row[1] for row in legacy.execute("PRAGMA index_list(zeek_connections)")
        }
        self.assertIn("record_bytes", columns)
        self.assertIn("record_sha256", columns)
        self.assertIn("prefix_bytes", columns)
        self.assertIn("prefix_sha256", columns)
        self.assertIn("idx_zeek_conn_indexed", indexes)

    def test_schema_is_separate_from_the_core_verdict_database(self):
        tables = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

        self.assertIn("zeek_connections", tables)
        self.assertNotIn("triage_events", tables)

    def test_valid_line_and_checkpoint_commit_together(self):
        result, checkpoint = self.add_line(json_line(conn_record()))

        self.assertEqual(result, IndexedLineResult(indexed=True))
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)
        stored_checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)
        self.assertEqual(stored_checkpoint.record_bytes, checkpoint.offset)
        self.assertEqual(
            stored_checkpoint.record_sha256,
            "sha256:" + hashlib.sha256(json_line(conn_record())).hexdigest(),
        )
        row = self.conn.execute(
            "SELECT uid, proto, orig_h, resp_h FROM zeek_connections"
        ).fetchone()
        self.assertEqual(row, ("C1", "TCP", "192.0.2.10", "198.51.100.20"))

    def test_exact_duplicate_uid_is_idempotent_and_advances_cursor(self):
        first, first_checkpoint = self.add_line(json_line(conn_record()))
        second, second_checkpoint = self.add_line(json_line(conn_record()))

        self.assertTrue(first.indexed)
        self.assertTrue(second.duplicate)
        self.assertFalse(second.indexed)
        self.assertGreater(second_checkpoint.offset, first_checkpoint.offset)
        stored = self.conn.execute(
            "SELECT ts, orig_bytes FROM zeek_connections WHERE uid = 'C1'"
        ).fetchone()
        self.assertEqual(stored, (BASE_EPOCH, 500))

    def test_conflicting_uid_is_recorded_without_overwriting_original(self):
        self.add_line(json_line(conn_record()))

        result, _checkpoint = self.add_line(
            json_line(conn_record(ts=BASE_EPOCH + 99, orig_bytes=9999))
        )

        self.assertEqual(result.failure_code, "uid_conflict")
        self.assertFalse(result.indexed)
        self.assertFalse(result.duplicate)
        stored = self.conn.execute(
            "SELECT ts, orig_bytes FROM zeek_connections WHERE uid = 'C1'"
        ).fetchone()
        self.assertEqual(stored, (BASE_EPOCH, 500))
        failure = self.conn.execute(
            "SELECT error_code FROM zeek_ingest_failures"
        ).fetchone()
        self.assertEqual(failure[0], "uid_conflict")

    def test_malformed_complete_line_records_digest_and_advances(self):
        raw = b'{"uid":"truncated"}\n'

        result, checkpoint = self.add_line(raw)

        self.assertEqual(result.failure_code, "invalid_record")
        self.assertFalse(result.indexed)
        failure = self.conn.execute(
            """SELECT record_end_offset, record_sha256, error_code, error
               FROM zeek_ingest_failures"""
        ).fetchone()
        self.assertEqual(failure[0], checkpoint.offset)
        self.assertTrue(failure[1].startswith("sha256:"))
        self.assertEqual(failure[2], "invalid_record")
        self.assertIn("ts must be numeric", failure[3])

    def test_oversized_complete_line_is_bounded_failure_metadata(self):
        raw = b"{" + (b"x" * MAX_CONN_RECORD_BYTES) + b"}\n"

        result, _checkpoint = self.add_line(raw)

        self.assertEqual(result.failure_code, "invalid_record")
        error, digest = self.conn.execute(
            "SELECT error, record_sha256 FROM zeek_ingest_failures"
        ).fetchone()
        self.assertIn("exceeds", error)
        self.assertEqual(len(digest), len("sha256:") + 64)

    def test_incomplete_line_never_mutates_index_or_checkpoint(self):
        with self.assertRaises(ZeekIncompleteRecordError):
            self.add_line(json.dumps(conn_record()).encode("utf-8"))

        self.assertIsNone(load_checkpoint(self.conn, SOURCE_INSTANCE))
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM zeek_connections").fetchone()[0],
            0,
        )

    def test_stale_reader_cannot_commit_record_or_checkpoint(self):
        _first, stale_checkpoint = self.add_line(json_line(conn_record("C1")))
        _second, current_checkpoint = self.add_line(json_line(conn_record("C2")))

        with self.assertRaises(ZeekCheckpointConflict):
            self.add_line(
                json_line(conn_record("C3")),
                expected_marker=stale_checkpoint,
            )

        self.assertEqual(
            load_checkpoint(self.conn, SOURCE_INSTANCE),
            current_checkpoint,
        )
        self.assertIsNone(
            self.conn.execute(
                "SELECT uid FROM zeek_connections WHERE uid = 'C3'"
            ).fetchone()
        )

    def test_record_anchor_is_part_of_checkpoint_compare_and_swap(self):
        _first, checkpoint = self.add_line(json_line(conn_record("C1")))
        replacement_digest = "sha256:" + ("0" * 64)
        self.conn.execute(
            """UPDATE zeek_log_checkpoints
               SET record_sha256 = ?
               WHERE source_instance = ? AND log_name = 'conn'""",
            (replacement_digest, SOURCE_INSTANCE),
        )
        self.conn.commit()

        with self.assertRaises(ZeekCheckpointConflict):
            self.add_line(
                json_line(conn_record("C2")),
                expected_marker=checkpoint,
            )


    def test_checkpoint_cannot_skip_bytes_inside_a_file(self):
        raw = json_line(conn_record("C1"))
        unsafe = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=7,
            inode=11,
            offset=len(raw) + 1,
            file_size=len(raw) + 1,
        )

        with self.assertRaises(ZeekCheckpointConflict):
            index_conn_line(
                self.conn,
                raw,
                unsafe,
                expected_checkpoint=None,
            )

        self.assertIsNone(load_checkpoint(self.conn, SOURCE_INSTANCE))

    def test_checkpoint_offsets_are_bounded_to_sqlite_integers(self):
        for field in ("offset", "file_size"):
            values = {
                "source_instance": SOURCE_INSTANCE,
                "log_name": "conn",
                "device": 7,
                "inode": 11,
                "offset": 0,
                "file_size": 0,
            }
            values[field] = (1 << 63)
            if field == "offset":
                values["file_size"] = 1 << 63
            with self.subTest(field=field):
                with self.assertRaises(ZeekConnValidationError):
                    ZeekLogCheckpoint(**values)

    def test_conn_index_rejects_a_different_log_checkpoint(self):
        raw = json_line(conn_record())
        checkpoint = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="dns",
            device=7,
            inode=11,
            offset=len(raw),
            file_size=len(raw),
        )

        with self.assertRaises(ZeekConnValidationError):
            index_conn_line(
                self.conn,
                raw,
                checkpoint,
                expected_checkpoint=None,
            )

    def test_duplicate_json_keys_are_durably_rejected(self):
        raw = (
            b'{"ts":1,"ts":2,"uid":"C1","id.orig_h":"192.0.2.10",'
            b'"id.orig_p":1,"id.resp_h":"198.51.100.20",'
            b'"id.resp_p":2,"proto":"tcp"}\n'
        )

        result, _checkpoint = self.add_line(raw)

        self.assertEqual(result.failure_code, "invalid_record")
        error = self.conn.execute(
            "SELECT error FROM zeek_ingest_failures"
        ).fetchone()[0]
        self.assertIn("duplicate key", error)

    def test_same_file_identity_cannot_shrink_behind_checkpoint(self):
        raw = json_line(conn_record("C1"))
        _result, checkpoint = self.add_line(raw, file_size=len(raw) + 1_000)
        next_raw = json_line(conn_record("C2"))
        unsafe = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=checkpoint.device,
            inode=checkpoint.inode,
            offset=checkpoint.offset + len(next_raw),
            file_size=checkpoint.offset + len(next_raw),
        )

        with self.assertRaises(ZeekCheckpointConflict):
            index_conn_line(
                self.conn,
                next_raw,
                unsafe,
                expected_checkpoint=checkpoint,
            )

        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)

    def test_confirmed_rotation_identity_uses_exact_previous_cursor(self):
        _first, old_checkpoint = self.add_line(json_line(conn_record("C1")))

        result, new_checkpoint = self.add_line(
            json_line(conn_record("C2")),
            inode=12,
            expected_marker=old_checkpoint,
        )

        self.assertTrue(result.indexed)
        self.assertEqual(new_checkpoint.inode, 12)
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), new_checkpoint)

    def test_bounded_external_failure_commits_with_exact_cursor(self):
        raw = b"oversized-record\n"
        checkpoint = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=7,
            inode=11,
            offset=len(raw),
            file_size=len(raw),
        )

        result = index_conn_failure(
            self.conn,
            checkpoint,
            expected_checkpoint=None,
            record_bytes=len(raw),
            record_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
            error_code="record_too_large",
            error="record exceeded the reader bound",
        )

        self.assertEqual(result.failure_code, "record_too_large")
        stored = load_checkpoint(self.conn, SOURCE_INSTANCE)
        self.assertEqual(stored.offset, checkpoint.offset)
        self.assertEqual(stored.record_bytes, len(raw))
        self.assertEqual(
            stored.record_sha256,
            "sha256:" + hashlib.sha256(raw).hexdigest(),
        )

    def test_external_failure_rejects_invalid_digest_without_checkpoint(self):
        checkpoint = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=7,
            inode=11,
            offset=10,
            file_size=10,
        )

        with self.assertRaises(ZeekConnValidationError):
            index_conn_failure(
                self.conn,
                checkpoint,
                expected_checkpoint=None,
                record_bytes=10,
                record_sha256="not-a-digest",
                error_code="record_too_large",
                error="record exceeded the reader bound",
            )

        self.assertIsNone(load_checkpoint(self.conn, SOURCE_INSTANCE))

    def test_rotation_handoff_rejects_an_undrained_checkpoint(self):
        raw = json_line(conn_record())
        _result, checkpoint = self.add_line(raw, file_size=len(raw) + 1)
        successor_raw = b"x"
        successor = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=7,
            inode=12,
            offset=0,
            file_size=len(successor_raw),
            prefix_bytes=len(successor_raw),
            prefix_sha256="sha256:" + hashlib.sha256(successor_raw).hexdigest(),
        )

        with self.assertRaises(ZeekCheckpointConflict):
            rotate_checkpoint(
                self.conn,
                successor,
                expected_checkpoint=checkpoint,
            )

        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)

    def test_rotation_handoff_allows_an_explicitly_reused_file_identity(self):
        raw = json_line(conn_record())
        _result, checkpoint = self.add_line(raw)
        successor_raw = b"x"
        successor = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=checkpoint.device,
            inode=checkpoint.inode,
            offset=0,
            file_size=len(successor_raw),
            prefix_bytes=len(successor_raw),
            prefix_sha256="sha256:" + hashlib.sha256(successor_raw).hexdigest(),
        )

        rotate_checkpoint(
            self.conn,
            successor,
            expected_checkpoint=checkpoint,
            allow_reused_identity=True,
        )

        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), successor)

    def test_rotation_handoff_rejects_unproven_reused_file_identity(self):
        raw = json_line(conn_record())
        _result, checkpoint = self.add_line(raw)
        successor_raw = b"x"
        successor = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=checkpoint.device,
            inode=checkpoint.inode,
            offset=0,
            file_size=len(successor_raw),
            prefix_bytes=len(successor_raw),
            prefix_sha256="sha256:" + hashlib.sha256(successor_raw).hexdigest(),
        )

        with self.assertRaises(ZeekCheckpointConflict):
            rotate_checkpoint(
                self.conn,
                successor,
                expected_checkpoint=checkpoint,
            )

        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)

    def test_rotation_handoff_rejects_an_unanchored_successor(self):
        raw = json_line(conn_record())
        _result, checkpoint = self.add_line(raw)
        successor = ZeekLogCheckpoint(
            source_instance=SOURCE_INSTANCE,
            log_name="conn",
            device=7,
            inode=12,
            offset=0,
            file_size=1,
        )

        with self.assertRaisesRegex(
            ZeekCheckpointConflict,
            "durable prefix anchor",
        ):
            rotate_checkpoint(
                self.conn,
                successor,
                expected_checkpoint=checkpoint,
            )

        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)


class ConnectionLookupTests(ZeekIndexTestCase):
    def test_exact_tuple_lookup_work_does_not_scale_with_protocol_decoys(self):
        self.add_line(json_line(conn_record(duration=60.0)))
        decoys = []
        for number in range(5_000):
            decoys.append(
                (
                    SOURCE_INSTANCE,
                    f"D{number}",
                    BASE_EPOCH,
                    BASE_EPOCH + 60,
                    f"10.{number // 256}.{number % 256}.1",
                    12345,
                    "203.0.113.10",
                    443,
                    "TCP",
                    BASE_EPOCH,
                )
            )
        self.conn.executemany(
            """INSERT INTO zeek_connections (
                   source_instance, uid, ts, end_ts,
                   orig_h, orig_p, resp_h, resp_p, proto, indexed_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            decoys,
        )
        steps = 0

        def count_step():
            nonlocal steps
            steps += 1
            return 0

        self.conn.set_progress_handler(count_step, 1)
        try:
            result = lookup_connection(self.conn, request(), SOURCE_INSTANCE)
        finally:
            self.conn.set_progress_handler(None, 0)

        self.assertEqual(result.status, ZeekLookupStatus.MATCHED)
        self.assertLess(steps, 300)

    def test_identical_forward_and_reverse_tuple_is_not_duplicated(self):
        loop_record = conn_record(
            **{
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 51000,
                "id.resp_h": "192.0.2.10",
                "id.resp_p": 51000,
            }
        )
        self.add_line(json_line(loop_record))

        result = lookup_connection(
            self.conn,
            request(dest_ip="192.0.2.10", dest_port=51000),
            SOURCE_INSTANCE,
        )

        self.assertEqual(result.status, ZeekLookupStatus.MATCHED)
        self.assertEqual(result.candidate_count, 1)

    def test_forward_tuple_matches_inside_long_connection_interval(self):
        self.add_line(json_line(conn_record(duration=60.0)))

        result = lookup_connection(self.conn, request(), SOURCE_INSTANCE)

        self.assertEqual(result.status, ZeekLookupStatus.MATCHED)
        self.assertEqual(result.record_count, 1)
        self.assertEqual(result.candidate_count, 1)
        context = json.loads(result.context_json)
        self.assertEqual(context["connections"][0]["uid"], "C1")
        self.assertEqual(context["connections"][0]["direction"], "same_as_alert")

    def test_reversed_zeek_orientation_is_labeled_not_rejected(self):
        reversed_record = conn_record(
            **{
                "id.orig_h": "198.51.100.20",
                "id.orig_p": 443,
                "id.resp_h": "192.0.2.10",
                "id.resp_p": 51000,
            }
        )
        self.add_line(json_line(reversed_record))

        result = lookup_connection(self.conn, request(), SOURCE_INSTANCE)

        self.assertEqual(result.status, ZeekLookupStatus.MATCHED)
        context = json.loads(result.context_json)
        self.assertEqual(
            context["connections"][0]["direction"],
            "reversed_from_alert",
        )

    def test_outside_interval_or_different_tuple_returns_no_match(self):
        self.add_line(json_line(conn_record(duration=1.0)))

        outside = lookup_connection(
            self.conn,
            request(alert_timestamp="2026-08-26T16:01:00Z"),
            SOURCE_INSTANCE,
        )
        other_port = lookup_connection(
            self.conn,
            request(dest_port=8443),
            SOURCE_INSTANCE,
        )

        self.assertEqual(outside.status, ZeekLookupStatus.NO_MATCH)
        self.assertEqual(other_port.status, ZeekLookupStatus.NO_MATCH)

    def test_multiple_plausible_intervals_are_ambiguous_without_context(self):
        self.add_line(json_line(conn_record("C1", duration=60.0)))
        self.add_line(
            json_line(conn_record("C2", ts=BASE_EPOCH + 2, duration=60.0))
        )

        result = lookup_connection(self.conn, request(), SOURCE_INSTANCE)

        self.assertEqual(result.status, ZeekLookupStatus.AMBIGUOUS)
        self.assertEqual(result.candidate_count, 2)
        self.assertEqual(result.record_count, 0)
        self.assertIsNone(result.context_json)

    def test_candidate_bound_reports_truncation_instead_of_guessing(self):
        self.add_line(json_line(conn_record("C1", duration=60.0)))
        self.add_line(
            json_line(conn_record("C2", ts=BASE_EPOCH + 1, duration=60.0))
        )

        result = lookup_connection(
            self.conn,
            request(max_records=1),
            SOURCE_INSTANCE,
        )

        self.assertEqual(result.status, ZeekLookupStatus.AMBIGUOUS)
        self.assertEqual(result.candidate_count, 2)
        self.assertTrue(result.truncated)

    def test_request_context_byte_limit_is_enforced(self):
        self.add_line(json_line(conn_record()))

        result = lookup_connection(
            self.conn,
            request(max_context_bytes=1),
            SOURCE_INSTANCE,
        )

        self.assertEqual(result.status, ZeekLookupStatus.INVALID_RESPONSE)
        self.assertIsNone(result.context_json)


class ZeekApplicationEvidenceTests(ZeekIndexTestCase):
    def setUp(self):
        super().setUp()
        self.add_line(json_line(conn_record()))

    def test_basic_lookup_does_not_silently_expand_model_evidence(self):
        self.add_evidence_line(
            "http",
            {
                "ts": BASE_EPOCH + 1,
                "uid": "C1",
                "method": "GET",
                "host": "example.test",
                "uri": "/download",
                "user_agent": "curl/8.0",
                "status_code": 200,
            },
        )

        result = lookup_connection(self.conn, request(), SOURCE_INSTANCE)
        context = json.loads(result.context_json)

        self.assertNotIn("http", context)
        self.assertEqual(context["connections"][0]["uid"], "C1")

    def test_deep_lookup_correlates_allowlisted_uid_and_certificate_evidence(self):
        self.add_evidence_line(
            "dns",
            {
                "ts": BASE_EPOCH + 1,
                "uid": "C1",
                "query": "example.test",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
                "answers": ["198.51.100.20"],
                "untrusted_extra": "discard me",
            },
        )
        self.add_evidence_line(
            "http",
            {
                "ts": BASE_EPOCH + 2,
                "uid": "C1",
                "method": "GET",
                "host": "example.test",
                "uri": "/download",
                "user_agent": "curl/8.0",
                "status_code": 200,
            },
            inode=22,
        )
        self.add_evidence_line(
            "ssl",
            {
                "ts": BASE_EPOCH + 3,
                "uid": "C1",
                "server_name": "example.test",
                "version": "TLSv13",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "established": True,
                "cert_chain_fuids": ["F-cert-1"],
            },
            inode=23,
        )
        self.add_evidence_line(
            "x509",
            {
                "ts": BASE_EPOCH + 3,
                "id": "F-cert-1",
                "certificate.subject": "CN=example.test",
                "certificate.issuer": "CN=Test CA",
                "certificate.not_valid_after": BASE_EPOCH + 86_400,
            },
            inode=24,
        )

        result = lookup_connection(
            self.conn,
            request(),
            SOURCE_INSTANCE,
            include_application=True,
        )
        context = json.loads(result.context_json)

        self.assertEqual(context["dns"][0]["query"], "example.test")
        self.assertNotIn("untrusted_extra", context["dns"][0])
        self.assertEqual(context["http"][0]["method"], "GET")
        self.assertEqual(context["tls"][0]["server_name"], "example.test")
        self.assertEqual(
            context["certificates"][0]["certificate.subject"],
            "CN=example.test",
        )
        self.assertEqual(result.match_strategy, "exact_tuple_interval_linked_evidence")

    def test_deep_lookup_links_recent_dns_answer_from_the_same_origin(self):
        self.add_evidence_line(
            "dns",
            {
                "ts": BASE_EPOCH - 60,
                "uid": "C-dns-separate",
                "id.orig_h": "192.0.2.10",
                "query": "download.example",
                "answers": ["198.51.100.20"],
            },
        )

        result = lookup_connection(
            self.conn,
            request(),
            SOURCE_INSTANCE,
            include_application=True,
        )
        context = json.loads(result.context_json)

        self.assertEqual(context["dns"][0]["query"], "download.example")
        self.assertEqual(
            context["dns"][0]["correlation"],
            "recent_dns_answer_for_responder",
        )

    def test_dns_answer_correlation_requires_same_origin_and_recent_time(self):
        for index, (origin, timestamp) in enumerate(
            (
                ("192.0.2.99", BASE_EPOCH - 60),
                ("192.0.2.10", BASE_EPOCH - 301),
            )
        ):
            self.add_evidence_line(
                "dns",
                {
                    "ts": timestamp,
                    "uid": f"C-dns-{index}",
                    "id.orig_h": origin,
                    "query": f"wrong-{index}.example",
                    "answers": ["198.51.100.20"],
                },
                inode=40,
            )

        result = lookup_connection(
            self.conn,
            request(),
            SOURCE_INSTANCE,
            include_application=True,
        )

        self.assertNotIn("dns", json.loads(result.context_json))

    def test_valid_unlinked_notice_is_checkpointed_without_becoming_context(self):
        outcome = self.add_evidence_line(
            "notice",
            {
                "ts": BASE_EPOCH + 1,
                "note": "Scan::Port_Scan",
                "msg": "aggregate notice without a connection UID",
            },
        )

        self.assertFalse(outcome.indexed)
        self.assertIsNone(outcome.failure_code)
        self.assertIsNotNone(load_checkpoint(self.conn, SOURCE_INSTANCE, "notice"))

    def test_deep_context_drops_excess_records_and_reports_truncation(self):
        for index in range(3):
            self.add_evidence_line(
                "http",
                {
                    "ts": BASE_EPOCH + index,
                    "uid": "C1",
                    "method": "GET",
                    "host": "example.test",
                    "uri": f"/{index}/" + ("x" * 700),
                },
                inode=30,
            )

        result = lookup_connection(
            self.conn,
            request(max_context_bytes=900),
            SOURCE_INSTANCE,
            include_application=True,
        )
        context = json.loads(result.context_json)

        self.assertEqual(result.status, ZeekLookupStatus.MATCHED)
        self.assertTrue(result.truncated)
        self.assertTrue(context["application_evidence_truncated"])
        self.assertLessEqual(len(result.context_json.encode("utf-8")), 900)

    def test_invalid_evidence_is_quarantined_and_checkpointed(self):
        outcome = self.add_evidence_line(
            "http",
            {
                "ts": BASE_EPOCH,
                "uid": "C1",
                "host": "bad\nvalue",
            },
        )

        self.assertFalse(outcome.indexed)
        self.assertEqual(outcome.failure_code, "invalid_record")
        self.assertIsNotNone(load_checkpoint(self.conn, SOURCE_INSTANCE, "http"))
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM zeek_evidence").fetchone()[0],
            0,
        )

    def test_unsupported_log_name_fails_before_checkpointing(self):
        with self.assertRaises(ZeekConnValidationError):
            self.add_evidence_line(
                "weird",
                {"ts": BASE_EPOCH, "uid": "C1"},
            )
        self.assertIsNone(load_checkpoint(self.conn, SOURCE_INSTANCE, "weird"))


class ZeekIndexRetentionTests(ZeekIndexTestCase):
    def test_prune_is_bounded_and_preserves_checkpoint(self):
        self.add_line(
            b'{"uid":"bad"}\n',
            clock=lambda: BASE_EPOCH - 1_000,
        )
        self.add_line(
            json_line(conn_record("expired", ts=BASE_EPOCH - 500, duration=1.0)),
            clock=lambda: BASE_EPOCH - 500,
        )
        self.add_line(
            json_line(conn_record("retained", ts=BASE_EPOCH + 500, duration=1.0))
        )
        self.add_evidence_line(
            "dns",
            {
                "ts": BASE_EPOCH - 500,
                "uid": "expired",
                "query": "expired.example",
            },
            clock=lambda: BASE_EPOCH - 500,
        )
        checkpoint = load_checkpoint(self.conn, SOURCE_INSTANCE)

        result = prune_index(
            self.conn,
            BASE_EPOCH,
            batch_size=1,
            max_rows=10,
        )

        self.assertEqual(result.connections, 1)
        self.assertEqual(result.evidence, 1)
        self.assertEqual(result.failures, 1)
        self.assertEqual(
            self.conn.execute(
                "SELECT uid FROM zeek_connections ORDER BY uid"
            ).fetchall(),
            [("retained",)],
        )
        self.assertEqual(load_checkpoint(self.conn, SOURCE_INSTANCE), checkpoint)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM zeek_evidence_links").fetchone()[0],
            0,
        )

    def test_prune_max_rows_is_global_across_index_tables(self):
        self.add_line(
            b'{"uid":"bad"}\n',
            clock=lambda: BASE_EPOCH - 1_000,
        )
        self.add_line(
            json_line(conn_record("expired", ts=BASE_EPOCH - 500, duration=1.0)),
            clock=lambda: BASE_EPOCH - 500,
        )

        result = prune_index(self.conn, BASE_EPOCH, batch_size=1, max_rows=1)

        self.assertEqual(result.connections + result.evidence + result.failures, 1)
        remaining = (
            self.conn.execute("SELECT COUNT(*) FROM zeek_connections").fetchone()[0]
            + self.conn.execute(
                "SELECT COUNT(*) FROM zeek_ingest_failures"
            ).fetchone()[0]
        )
        self.assertEqual(remaining, 1)

    def test_prune_uses_trusted_ingest_time_not_sensor_event_time(self):
        self.add_line(
            json_line(conn_record("future", ts=BASE_EPOCH + 1_000_000)),
            clock=lambda: BASE_EPOCH - 500,
        )

        result = prune_index(self.conn, BASE_EPOCH, batch_size=1, max_rows=10)

        self.assertEqual(result.connections, 1)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM zeek_connections").fetchone()[0],
            0,
        )

    def test_prune_rejects_unbounded_or_invalid_limits(self):
        for kwargs in (
            {"batch_size": 0},
            {"batch_size": 10_001},
            {"max_rows": 0},
            {"max_rows": MAX_PRUNE_ROWS + 1},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    prune_index(self.conn, BASE_EPOCH, **kwargs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
