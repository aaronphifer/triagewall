#!/usr/bin/env python3
"""Regression coverage for retryable ingest checkpoint failures."""

import gzip
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Renaming or unlinking a file that another handle has open raises
# PermissionError on Windows, so the few regressions that must rotate a log the
# daemon is actively holding open only run on POSIX. Linux CI runs them all.
POSIX_ONLY = unittest.skipUnless(
    os.name == "posix", "requires POSIX rename-over-open-file semantics"
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "triagewall"))

import ingest
import migrations
import triage
from sensor_event import (
    normalize_suricata_event,
    suricata_classification_alert,
)


TEST_CONFIG_BUNDLE = SimpleNamespace(
    generation=1,
    prefilter_revision="sha256:" + "a" * 64,
    asset_revision="sha256:" + "b" * 64,
    prefilter_policy=triage.PREFILTER_POLICY,
    asset_inventory=triage.ASSET_INVENTORY,
)


class TestConfigurationOwner:
    def __init__(self, **_kwargs):
        self.bundle = TEST_CONFIG_BUNDLE

    def start(self, _conn):
        return self.bundle

    def maybe_reload(self, _conn):
        return False


class IngestCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript((PROJECT_ROOT / "triagewall" / "schema.sql").read_text())
        self.bundle_patch = patch.object(
            ingest, "ConfigurationBundleOwner", TestConfigurationOwner
        )
        self.bundle_patch.start()

    def tearDown(self):
        self.bundle_patch.stop()
        self.conn.close()

    def test_model_failure_is_retryable_and_not_checkpointable(self):
        raw = json.dumps({
            "event_type": "alert",
            "timestamp": "2026-07-19T00:00:00Z",
            "alert": {"signature_id": 1, "signature": "Retry me"},
        })
        with patch.object(
            triage.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ), patch.object(triage, "OLLAMA_URL", "http://ollama.test/api/generate"):
            result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertFalse(result.checkpoint)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM ingest_failures").fetchone()[0],
            0,
        )

    def test_persistence_failure_is_retryable_and_not_checkpointable(self):
        raw = json.dumps({
            "event_type": "alert",
            "timestamp": "2026-07-19T00:00:00Z",
            "src_ip": " 10.0.0.1 ",
            "proto": "tcp",
            "alert": {"signature_id": 2, "signature": "Persist me"},
        })
        verdict = {"verdict": "real", "confidence": 0.8, "reasoning": "test"}
        context = {
            "source": {"hostname": "example-host"},
            "destination": None,
        }
        with patch.object(
            ingest, "get_asset_context", return_value=context
        ) as get_asset_context, patch.object(
            ingest, "call_ollama", return_value=verdict
        ) as call_ollama, patch.object(
            ingest, "insert_with_retry", return_value=False
        ) as insert_with_retry:
            result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertFalse(result.checkpoint)
        event = json.loads(raw)
        normalized_event = normalize_suricata_event(event)
        classification_event = suricata_classification_alert(normalized_event)
        self.assertEqual(classification_event["src_ip"], "10.0.0.1")
        self.assertEqual(classification_event["proto"], "TCP")
        get_asset_context.assert_called_once_with(classification_event)
        call_ollama.assert_called_once_with(
            classification_event,
            asset_context=context,
        )
        insert_with_retry.assert_called_once_with(
            self.conn,
            normalized_event,
            verdict,
            asset_context=context,
        )
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM ingest_failures").fetchone()[0],
            0,
        )

    def test_enabled_zeek_passes_provider_and_normalized_event_to_triage(self):
        raw = json.dumps({
            "event_type": "alert",
            "timestamp": "2026-07-19T00:00:00Z",
            "flow_id": 42,
            "src_ip": "192.0.2.10",
            "src_port": 51000,
            "dest_ip": "198.51.100.20",
            "dest_port": 443,
            "proto": "tcp",
            "alert": {"signature_id": 20, "signature": "Enrich me"},
        })
        verdict = {"verdict": "real", "confidence": 0.8, "reasoning": "test"}
        provider = object()
        with patch.object(
            ingest, "ZEEK_ENRICHMENT_ENABLED", True, create=True
        ), patch.object(
            ingest, "ZEEK_CONTEXT_PROVIDER", provider, create=True
        ), patch.object(
            ingest, "get_asset_context", return_value={
                "source": None,
                "destination": None,
            }
        ), patch.object(
            ingest,
            "classify_suricata",
            return_value=SimpleNamespace(
                verdict=verdict,
                zeek_enrichment="provenance",
            ),
        ) as classify_suricata, patch.object(
            ingest, "insert_with_retry", return_value=True
        ) as insert_with_retry, patch.object(ingest.spc, "observe"):
            result = ingest.process_line(self.conn, raw)

        self.assertTrue(result.processed)
        classify_suricata.assert_called_once()
        classification_event = classify_suricata.call_args.args[0]
        self.assertEqual(classification_event["proto"], "TCP")
        self.assertIs(
            classify_suricata.call_args.kwargs["zeek_context_provider"],
            provider,
        )
        self.assertEqual(
            classify_suricata.call_args.kwargs["zeek_catchup_timeout_seconds"],
            ingest.ZEEK_CATCHUP_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            classify_suricata.call_args.kwargs[
                "zeek_catchup_retry_interval_seconds"
            ],
            ingest.ZEEK_CATCHUP_RETRY_INTERVAL_SECONDS,
        )
        normalized_event = classify_suricata.call_args.kwargs["normalized_event"]
        self.assertEqual(normalized_event.flow_id, 42)
        self.assertEqual(
            insert_with_retry.call_args.kwargs["zeek_enrichment"],
            "provenance",
        )

    def test_missing_timestamp_is_quarantined_before_triage(self):
        raw = json.dumps({
            "event_type": "alert",
            "alert": {"signature_id": 3, "signature": "Missing timestamp"},
        })
        with patch.object(ingest, "call_ollama") as call_ollama:
            result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertTrue(result.checkpoint)
        failure = self.conn.execute(
            "SELECT raw_line, error FROM ingest_failures"
        ).fetchone()
        self.assertEqual(failure[0], raw)
        self.assertIn("invalid alert timestamp", failure[1])
        call_ollama.assert_not_called()

    def test_tail_loop_checkpoints_invalid_record_and_processes_next_alert(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            db_path = temp_path / "triage.db"
            position_path = temp_path / "position.json"
            invalid = json.dumps({
                "event_type": "alert",
                "alert": {"signature_id": 4, "signature": "Missing timestamp"},
            }) + "\n"
            valid = json.dumps({
                "event_type": "alert",
                "timestamp": "2026-07-19T00:00:00+00:00",
                "alert": {"signature_id": 5, "signature": "Process after invalid"},
            }) + "\n"
            eve_path.write_text(invalid + valid)
            position_path.write_text(json.dumps({"offset": 0, "inode": None, "size": 0}))
            verdict = {"verdict": "real", "confidence": 0.8, "reasoning": "test"}
            calls = []
            migrations.ensure_db_initialized(db_path)

            def return_verdict(event, asset_context=None):
                self.assertEqual(
                    asset_context,
                    {"source": None, "destination": None},
                )
                calls.append(event["alert"]["signature_id"])
                ingest._stop = True
                return verdict

            ingest._stop = False
            try:
                with patch.object(ingest, "EVE_PATH", eve_path), patch.object(
                    ingest, "DB_PATH", db_path
                ), patch.object(ingest, "POSITION_PATH", position_path), patch.object(
                    ingest, "call_ollama", side_effect=return_verdict
                ):
                    ingest.tail_file()
            finally:
                ingest._stop = False

            saved = json.loads(position_path.read_text())
            conn = sqlite3.connect(db_path)
            try:
                failures = conn.execute("SELECT COUNT(*) FROM ingest_failures").fetchone()[0]
                events = conn.execute("SELECT COUNT(*) FROM triage_events").fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(calls, [5])
            self.assertEqual(failures, 1)
            self.assertEqual(events, 1)
            self.assertEqual(saved["offset"], eve_path.stat().st_size)

    def test_intentional_skip_remains_checkpointable(self):
        result = ingest.process_line(
            self.conn,
            json.dumps({"event_type": "flow", "flow_id": 7}),
        )
        self.assertFalse(result)
        self.assertTrue(result.checkpoint)

    def test_permanently_invalid_input_remains_quarantined_and_checkpointable(self):
        raw = '[{"event_type":"alert"}]'
        result = ingest.process_line(self.conn, raw)

        self.assertFalse(result)
        self.assertTrue(result.checkpoint)
        self.assertEqual(
            self.conn.execute("SELECT raw_line FROM ingest_failures").fetchone()[0],
            raw,
        )

    def test_tail_loop_does_not_advance_past_retryable_failure(self):
        class RetryResult:
            processed = False
            checkpoint = False

            def __bool__(self):
                return self.processed

        class SuccessResult:
            processed = True
            checkpoint = True

            def __bool__(self):
                return self.processed

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            db_path = temp_path / "triage.db"
            position_path = temp_path / "position.json"
            first = '{"event_type":"alert","alert":{"signature_id":1}}\n'
            second = '{"event_type":"alert","alert":{"signature_id":2}}\n'
            eve_path.write_text(first + second)
            position_path.write_text(json.dumps({"offset": 0, "inode": None, "size": 0}))
            calls = []
            migrations.ensure_db_initialized(db_path)

            def process_once(conn, line):
                calls.append(line)
                if len(calls) == 1:
                    return RetryResult()
                ingest._stop = True
                return SuccessResult()

            def stop_after_backoff(_seconds):
                ingest._stop = True

            ingest._stop = False
            try:
                with patch.object(ingest, "EVE_PATH", eve_path), patch.object(
                    ingest, "DB_PATH", db_path
                ), patch.object(ingest, "POSITION_PATH", position_path), patch.object(
                    ingest, "process_line", side_effect=process_once
                ), patch.object(ingest.time, "sleep", side_effect=stop_after_backoff):
                    ingest.tail_file()
            finally:
                ingest._stop = False

            saved = json.loads(position_path.read_text())
            self.assertEqual(calls, [first])
            self.assertEqual(saved["offset"], 0)

    def test_tail_loop_retries_same_record_then_checkpoints_success(self):
        class RetryResult:
            processed = False
            checkpoint = False

            def __bool__(self):
                return self.processed

        class SuccessResult:
            processed = True
            checkpoint = True

            def __bool__(self):
                return self.processed

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            db_path = temp_path / "triage.db"
            position_path = temp_path / "position.json"
            first = '{"event_type":"alert","alert":{"signature_id":1}}\n'
            second = '{"event_type":"alert","alert":{"signature_id":2}}\n'
            eve_path.write_text(first + second)
            with eve_path.open("r") as handle:
                handle.readline()
                expected_offset = handle.tell()
            position_path.write_text(json.dumps({"offset": 0, "inode": None, "size": 0}))
            calls = []
            migrations.ensure_db_initialized(db_path)

            def fail_then_succeed(conn, line):
                calls.append(line)
                if len(calls) == 1:
                    return RetryResult()
                ingest._stop = True
                return SuccessResult()

            ingest._stop = False
            try:
                with patch.object(ingest, "EVE_PATH", eve_path), patch.object(
                    ingest, "DB_PATH", db_path
                ), patch.object(ingest, "POSITION_PATH", position_path), patch.object(
                    ingest, "process_line", side_effect=fail_then_succeed
                ), patch.object(ingest.time, "sleep"):
                    ingest.tail_file()
            finally:
                ingest._stop = False

            saved = json.loads(position_path.read_text())
            self.assertEqual(calls, [first, first])
            self.assertEqual(saved["offset"], expected_offset)


def _alert(signature_id, signature, second=0):
    """One complete Suricata JSON-Lines alert record."""
    return json.dumps({
        "event_type": "alert",
        "timestamp": f"2026-08-06T00:00:{second:02d}+00:00",
        "alert": {"signature_id": signature_id, "signature": signature},
    }) + "\n"


class EveRotationChainTests(unittest.TestCase):
    """Bounded, symlink-free discovery of rotated eve.json archives."""

    def test_chain_orders_numbered_and_dated_archives_oldest_first(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            for name in (
                "eve.json",
                "eve.json.1",
                "eve.json.2",
                "eve.json.10",
                "eve.json.3.gz",
            ):
                (temp_path / name).write_text("x\n")
            names = [name for name, _p, _s in ingest._scan_eve_chain(eve_path)]
            # logrotate numbers the oldest archive highest; the live file is last.
            self.assertEqual(
                names,
                ["eve.json.10", "eve.json.3.gz", "eve.json.2", "eve.json.1", "eve.json"],
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            for name in (
                "eve.json",
                "eve.json-20260805-120000",
                "eve.json-20260806-000000",
            ):
                (temp_path / name).write_text("x\n")
            names = [name for name, _p, _s in ingest._scan_eve_chain(eve_path)]
            self.assertEqual(
                names,
                [
                    "eve.json-20260805-120000",
                    "eve.json-20260806-000000",
                    "eve.json",
                ],
            )

    def test_chain_rejects_unrelated_paths_directories_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            eve_path.write_text("x\n")
            (temp_path / "eve.json.1").write_text("x\n")
            (temp_path / "suricata.log").write_text("x\n")  # unrelated prefix
            (temp_path / "eve.json.d").mkdir()  # directory, not a regular file
            expected = ["eve.json.1", "eve.json"]
            if os.name == "posix":
                outside = temp_path / "outside.json"
                outside.write_text("x\n")
                os.symlink(outside, temp_path / "eve.json.link")
            names = [name for name, _p, _s in ingest._scan_eve_chain(eve_path)]
            self.assertEqual(names, expected)

    def test_unrelated_files_do_not_consume_the_archive_budget(self):
        """HOST_EVE_DIR is usually the whole Suricata log directory.

        Counting every directory entry against the archive cap let unrelated
        logs truncate the scan, which hid intermediate archives and skipped
        their alerts. Only eve.json* siblings may consume that budget.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            eve_path.write_text("x\n")
            for name in ("eve.json.1", "eve.json.2"):
                (temp_path / name).write_text("x\n")
            # Far more unrelated files than the archive cap allows.
            for index in range(2_000):
                (temp_path / f"unrelated-{index}.log").write_text("x\n")

            with patch.object(ingest, "MAX_ROTATION_SCAN_ENTRIES", 5):
                names = [
                    name for name, _p, _s in ingest._scan_eve_chain(eve_path)
                ]

            # The complete chain, not a truncated prefix of it.
            self.assertEqual(names, ["eve.json.2", "eve.json.1", "eve.json"])

    def test_exceeding_either_hard_cap_fails_closed(self):
        """An incomplete scan must never be returned as an ordering.

        A partial chain is indistinguishable from a complete one, so callers
        would treat the live file as the successor and permanently skip any
        archive that fell outside the scan.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            eve_path = temp_path / "eve.json"
            eve_path.write_text("x\n")
            for index in range(1, 9):
                (temp_path / f"eve.json.{index}").write_text("x\n")

            # Too many eve.json* siblings for the archive cap.
            with patch.object(ingest, "MAX_ROTATION_SCAN_ENTRIES", 3):
                with self.assertRaises(ingest.IngestCheckpointError) as ctx:
                    ingest._scan_eve_chain(eve_path)
            self.assertIn("rotated eve.json archives", str(ctx.exception))

            # Too many directory entries overall for the directory cap.
            with patch.object(ingest, "MAX_ROTATION_DIR_ENTRIES", 2):
                with self.assertRaises(ingest.IngestCheckpointError) as ctx:
                    ingest._scan_eve_chain(eve_path)
            self.assertIn("entries", str(ctx.exception))

    def test_unreadable_log_directory_fails_closed(self):
        """A failed scandir is not evidence that no archive is pending."""
        with tempfile.TemporaryDirectory() as temp_dir:
            eve_path = Path(temp_dir) / "eve.json"
            eve_path.write_text("x\n")
            with patch.object(
                ingest.os, "scandir", side_effect=OSError("permission denied")
            ):
                with self.assertRaises(ingest.IngestCheckpointError) as ctx:
                    ingest._scan_eve_chain(eve_path)
        self.assertIn("could not scan", str(ctx.exception))

    def test_compressed_archives_are_recognised(self):
        for name in (
            "eve.json.1.gz",
            "eve.json.2.bz2",
            "eve.json.3.xz",
            "eve.json.4.zst",
        ):
            with self.subTest(name=name):
                self.assertTrue(ingest._is_compressed_archive(name))
        for name in ("eve.json", "eve.json.1", "eve.json-20260806-000000"):
            with self.subTest(name=name):
                self.assertFalse(ingest._is_compressed_archive(name))


class EveStableEofTests(unittest.TestCase):
    """A renamed log is not immutable: EOF must be confirmed, not assumed."""

    def test_late_append_prevents_a_stable_eof(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "eve.json.1"
            path.write_text("first\n")
            with path.open("r") as handle:
                handle.read()
                appended = []

                def append_once(_seconds):
                    if not appended:
                        appended.append(True)
                        with path.open("a") as writer:
                            writer.write("late\n")

                with patch.object(ingest.time, "sleep", side_effect=append_once):
                    self.assertFalse(ingest._await_stable_eof(handle))
                self.assertEqual(handle.readline(), "late\n")

    def test_quiet_descriptor_reaches_a_stable_eof(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "eve.json.1"
            path.write_text("first\n")
            with path.open("r") as handle:
                handle.read()
                with patch.object(ingest.time, "sleep", return_value=None):
                    self.assertTrue(ingest._await_stable_eof(handle))

    def test_shutdown_during_settle_does_not_declare_a_drain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "eve.json.1"
            path.write_text("first\n")
            ingest._stop = False
            try:
                with path.open("r") as handle:
                    handle.read()

                    def stop_during_settle(_seconds):
                        ingest._stop = True

                    with patch.object(
                        ingest.time, "sleep", side_effect=stop_during_settle
                    ):
                        self.assertFalse(ingest._await_stable_eof(handle))
            finally:
                ingest._stop = False


class EveRotationCheckpointTests(unittest.TestCase):
    """Fail-closed checkpoint behaviour across Suricata eve.json rotation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp_path = Path(self.temp_dir.name)
        self.eve_path = self.temp_path / "eve.json"
        self.db_path = self.temp_path / "triage.db"
        self.position_path = self.temp_path / "position.json"
        ingest._stop = False
        self.addCleanup(setattr, ingest, "_stop", False)
        bundle_patch = patch.object(
            ingest, "ConfigurationBundleOwner", TestConfigurationOwner
        )
        bundle_patch.start()
        self.addCleanup(bundle_patch.stop)

    def write_position(self, offset, inode, size=0):
        self.position_path.write_text(
            json.dumps({"offset": offset, "inode": inode, "size": size})
        )

    def saved_position(self):
        return json.loads(self.position_path.read_text())

    def run_tail(self, **patches):
        """Run tail_file() with the daemon's paths redirected at the fixture."""
        migrations.ensure_db_initialized(self.db_path)
        with patch.object(ingest, "EVE_PATH", self.eve_path), patch.object(
            ingest, "DB_PATH", self.db_path
        ), patch.object(ingest, "POSITION_PATH", self.position_path), patch.object(
            ingest, "EOF_SETTLE_INTERVAL", 0
        ):
            with self._nested(patches):
                ingest.tail_file()

    def _nested(self, patches):
        from contextlib import ExitStack

        stack = ExitStack()
        for target, kwargs in patches.items():
            obj = ingest.time if target == "sleep" else ingest
            stack.enter_context(patch.object(obj, target, **kwargs))
        return stack

    # --- 1. restart after rotation ---------------------------------------
    def test_restart_after_rotation_drains_old_inode_before_the_new_file(self):
        """Unread alerts in a renamed eve.json must not be skipped after restart."""
        already_read = _alert(11, "already-read", 0)
        unread = _alert(12, "unread-before-rotation", 1)
        after = _alert(13, "after-rotation", 2)

        self.eve_path.write_text(already_read + unread)
        old_inode = self.eve_path.stat().st_ino
        with self.eve_path.open("r") as handle:
            handle.readline()
            offset = handle.tell()
        self.write_position(offset, old_inode)
        self.eve_path.rename(self.temp_path / "eve.json.1")
        self.eve_path.write_text(after)

        calls = []

        def capture(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            if len(calls) >= 2:
                ingest._stop = True
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        self.run_tail(
            call_ollama={"side_effect": capture},
            sleep={"return_value": None},
        )

        self.assertEqual(calls, [12, 13])
        saved = self.saved_position()
        self.assertEqual(saved["inode"], self.eve_path.stat().st_ino)
        self.assertEqual(saved["offset"], self.eve_path.stat().st_size)

    # --- 2/3. missing previous inode --------------------------------------
    def test_missing_previous_inode_with_unread_offset_fails_closed(self):
        self.eve_path.write_text("{}\n")
        self.write_position(50, 99999999, size=100)

        with self.assertRaises(ingest.IngestCheckpointError) as ctx:
            self.run_tail(process_line={})

        self.assertIn("no evidence that the previous file was fully drained", str(ctx.exception))
        self.assertEqual(self.saved_position()["inode"], 99999999)

    def test_missing_previous_inode_with_zero_offset_also_fails_closed(self):
        """offset == 0 does not prove the rotated file had been read."""
        self.eve_path.write_text("{}\n")
        self.write_position(0, 99999999, size=0)

        with self.assertRaises(ingest.IngestCheckpointError) as ctx:
            self.run_tail(process_line={})

        message = str(ctx.exception)
        self.assertIn("an offset of 0 can equally mean", message)
        # Recovery guidance must not tell the operator to reset the checkpoint.
        self.assertIn("restore the rotated archive", message.lower())
        self.assertEqual(self.saved_position()["inode"], 99999999)

    # --- 4. rotated file smaller than the checkpoint -----------------------
    def test_rotated_file_smaller_than_checkpoint_fails_closed(self):
        rotated = self.temp_path / "eve.json.1"
        rotated.write_text("{}\n")
        self.eve_path.write_text("{}\n")
        self.write_position(500, rotated.stat().st_ino, size=500)

        with self.assertRaises(ingest.IngestCheckpointError) as ctx:
            self.run_tail(process_line={})

        self.assertIn("shrank behind the durable checkpoint", str(ctx.exception))

    def test_live_file_smaller_than_checkpoint_fails_closed(self):
        self.eve_path.write_text("{}\n")
        self.write_position(500, self.eve_path.stat().st_ino, size=500)

        with self.assertRaises(ingest.IngestCheckpointError) as ctx:
            self.run_tail(process_line={})

        self.assertIn("shrank behind the durable checkpoint", str(ctx.exception))

    # --- 5. late append after the first EOF observation --------------------
    def test_late_append_on_rotated_inode_is_processed_before_switching(self):
        rotated = self.temp_path / "eve.json.1"
        rotated.write_text(_alert(21, "before-rotation", 0))
        self.eve_path.write_text(_alert(23, "live", 2))
        self.write_position(0, rotated.stat().st_ino)

        calls = []
        appended = []

        def append_once(_seconds):
            # Suricata still holds the pre-rename descriptor and appends.
            if not appended:
                appended.append(True)
                with rotated.open("a") as writer:
                    writer.write(_alert(22, "late-append-after-rename", 1))

        def capture(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            if len(calls) >= 3:
                ingest._stop = True
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        self.run_tail(
            call_ollama={"side_effect": capture},
            sleep={"side_effect": append_once},
        )

        self.assertEqual(calls, [21, 22, 23])
        self.assertEqual(self.saved_position()["inode"], self.eve_path.stat().st_ino)

    # --- 6. rotation while the live descriptor is open ---------------------
    @POSIX_ONLY
    def test_rotation_while_live_descriptor_open_drains_old_descriptor(self):
        self.eve_path.write_text(_alert(31, "live-before-rotation", 0))
        self.write_position(0, self.eve_path.stat().st_ino)

        calls = []

        def rotate_after_first(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            if len(calls) == 1:
                # logrotate moves the path out from under our open descriptor.
                self.eve_path.rename(self.temp_path / "eve.json.1")
                self.eve_path.write_text(_alert(32, "after-rotation", 1))
            if len(calls) >= 2:
                ingest._stop = True
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        self.run_tail(
            call_ollama={"side_effect": rotate_after_first},
            sleep={"return_value": None},
        )

        self.assertEqual(calls, [31, 32])
        self.assertEqual(self.saved_position()["inode"], self.eve_path.stat().st_ino)

    # --- 7. stat/open inode replacement ------------------------------------
    def test_stat_open_inode_replacement_does_not_advance_the_checkpoint(self):
        self.eve_path.write_text(_alert(41, "never-read", 0))
        original_inode = self.eve_path.stat().st_ino
        self.write_position(0, original_inode)

        real_fstat = os.fstat
        swapped = []

        class _Replaced:
            st_ino = 1234567890
            st_size = 0

        def fstat_once(fileno):
            """Simulate the path being replaced between stat() and open()."""
            result = real_fstat(fileno)
            if not swapped and result.st_ino == original_inode:
                swapped.append(True)
                return _Replaced()
            return result

        def stop_after_retry(_seconds):
            ingest._stop = True

        with patch.object(
            ingest.os, "fstat", side_effect=fstat_once
        ), patch.object(ingest, "process_line") as process_line:
            self.run_tail(sleep={"side_effect": stop_after_retry})

        self.assertTrue(swapped)
        process_line.assert_not_called()
        saved = self.saved_position()
        self.assertEqual(saved["offset"], 0)
        self.assertEqual(saved["inode"], original_inode)

    # --- 8. second rotation before the daemon catches up -------------------
    def test_second_rotation_before_catch_up_does_not_lose_records(self):
        """A rotation during a drain must not skip the file it displaced."""
        first_archive = self.temp_path / "eve.json-20260806-000000"
        second_archive = self.temp_path / "eve.json-20260806-000100"
        first_archive.write_text(_alert(51, "oldest-archive", 0))
        self.eve_path.write_text(_alert(52, "displaced-by-second-rotation", 1))
        self.write_position(0, first_archive.stat().st_ino)

        calls = []

        def rotate_again(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            if len(calls) == 1:
                # Suricata rotates again while we are still draining the first
                # archive. The live file becomes an archive of its own.
                self.eve_path.rename(second_archive)
                self.eve_path.write_text(_alert(53, "newest-live", 2))
            if len(calls) >= 3:
                ingest._stop = True
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        self.run_tail(
            call_ollama={"side_effect": rotate_again},
            sleep={"return_value": None},
        )

        self.assertEqual(calls, [51, 52, 53])
        self.assertEqual(self.saved_position()["inode"], self.eve_path.stat().st_ino)

    # --- 9. incomplete final record ----------------------------------------
    def test_incomplete_final_record_remains_uncheckpointed(self):
        complete = _alert(61, "complete", 0)
        partial = '{"event_type":"alert","timestamp":"2026-08-06T00:00:01+00:00"'
        self.eve_path.write_text(complete + partial)
        self.write_position(0, self.eve_path.stat().st_ino)
        # Compare against the on-disk offset so the assertion survives the
        # newline translation that text-mode writes apply on Windows.
        with self.eve_path.open("r") as handle:
            handle.readline()
            complete_offset = handle.tell()

        calls = []

        def capture(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        def stop_on_backoff(_seconds):
            ingest._stop = True

        self.run_tail(
            call_ollama={"side_effect": capture},
            sleep={"side_effect": stop_on_backoff},
        )

        self.assertEqual(calls, [61])
        # The checkpoint stops at the end of the last *complete* record.
        self.assertEqual(self.saved_position()["offset"], complete_offset)
        self.assertLess(
            self.saved_position()["offset"], self.eve_path.stat().st_size
        )

    # --- database lifecycle -------------------------------------------------
    def test_database_connection_closes_on_fail_closed_exit(self):
        self.eve_path.write_text("{}\n")
        self.write_position(10, 99999999, size=10)
        migrations.ensure_db_initialized(self.db_path)
        opened = []

        real_connect = ingest.connect_database

        def track(path):
            conn = real_connect(path)
            opened.append(conn)
            return conn

        with patch.object(ingest, "EVE_PATH", self.eve_path), patch.object(
            ingest, "DB_PATH", self.db_path
        ), patch.object(ingest, "POSITION_PATH", self.position_path), patch.object(
            ingest, "connect_database", side_effect=track
        ):
            with self.assertRaises(ingest.IngestCheckpointError):
                ingest.tail_file()

        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")

    # --- compressed rotation successors -------------------------------------
    def test_compressed_successor_fails_closed_before_the_checkpoint_moves(self):
        """A compressed successor must never become the durable checkpoint.

        Trigger: drain an uncompressed archive whose successor in the chain is
        ``eve.json.1.gz``. Persisting that inode made every later poll open
        gzip bytes as UTF-8 text; the resulting UnicodeDecodeError is not a
        checkpoint error, so the generic retry path spun forever with the
        checkpoint already durably moved -- and a restart reproduced it. The
        alerts in the compressed archive, and every later record, were never
        triaged.
        """
        drained = _alert(21, "unread-in-old-archive", 0)
        old_archive = self.temp_path / "eve.json.2"
        old_archive.write_text(drained)
        old_inode = old_archive.stat().st_ino

        # A real gzip member, so a reader really would fail to decode it.
        compressed = self.temp_path / "eve.json.1.gz"
        compressed.write_bytes(
            gzip.compress(_alert(22, "unread-in-compressed", 1).encode("utf-8"))
        )
        self.eve_path.write_text(_alert(23, "live", 2))

        self.write_position(0, old_inode)

        calls = []

        def capture(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        with self.assertRaises(ingest.IngestCheckpointError) as ctx:
            self.run_tail(
                call_ollama={"side_effect": capture},
                sleep={"return_value": None},
            )

        # The readable archive was fully drained and triaged...
        self.assertEqual(calls, [21])
        # ...and the operator is told what to do, naming the archive.
        self.assertIn("compressed", str(ctx.exception))
        self.assertIn("eve.json.1.gz", str(ctx.exception))
        # The checkpoint never moved onto the compressed inode, and never
        # jumped over it to the live file.
        saved = self.saved_position()
        self.assertEqual(saved["inode"], old_inode)
        self.assertNotEqual(saved["inode"], compressed.stat().st_ino)
        self.assertNotEqual(saved["inode"], self.eve_path.stat().st_ino)

    def test_checkpoint_on_a_compressed_archive_fails_closed(self):
        """The checkpointed archive was compressed in place, keeping its inode."""
        compressed = self.temp_path / "eve.json.1.gz"
        compressed.write_bytes(gzip.compress(b'{"event_type":"alert"}\n'))
        self.eve_path.write_text(_alert(24, "live", 0))
        self.write_position(0, compressed.stat().st_ino)

        with self.assertRaises(ingest.IngestCheckpointError) as ctx:
            self.run_tail(sleep={"return_value": None})

        self.assertIn("compressed", str(ctx.exception))
        self.assertEqual(
            self.saved_position()["inode"], compressed.stat().st_ino
        )

    # --- incomplete rotation scans ------------------------------------------
    def test_truncated_scan_cannot_skip_an_intermediate_archive(self):
        """A scan that hit its cap must not advance the checkpoint.

        Fixture: the checkpointed archive and the live file are both visible,
        but the intermediate archive falls outside the scan bound. The old
        behaviour returned that partial chain, so successor selection saw live
        as the next member and the intermediate archive was skipped forever.
        """
        old_archive = self.temp_path / "eve.json.2"
        old_archive.write_text(_alert(31, "unread-in-old-archive", 0))
        old_inode = old_archive.stat().st_ino
        intermediate = self.temp_path / "eve.json.1"
        intermediate.write_text(_alert(32, "must-not-be-skipped", 1))
        self.eve_path.write_text(_alert(33, "live", 2))

        self.write_position(0, old_inode)

        calls = []

        def capture(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        # Three eve.json* siblings exist; the cap admits fewer.
        with patch.object(ingest, "MAX_ROTATION_SCAN_ENTRIES", 2):
            with self.assertRaises(ingest.IngestCheckpointError) as ctx:
                self.run_tail(
                    call_ollama={"side_effect": capture},
                    sleep={"return_value": None},
                )

        self.assertIn("rotated eve.json archives", str(ctx.exception))
        # The checkpoint stayed put: no jump to live, nothing skipped.
        saved = self.saved_position()
        self.assertEqual(saved["inode"], old_inode)
        self.assertNotEqual(saved["inode"], self.eve_path.stat().st_ino)
        self.assertNotIn(33, calls)

    # --- #59 checkpoint durability must survive this branch -----------------
    def test_rotation_handoff_keeps_checkpoint_writes_atomic(self):
        """#59's atomic save_position must still hold across a rotation.

        Regression guard for the merge: the rotation work restructured the
        same tail_file() loop that #59 made durable.
        """
        unread = _alert(41, "unread-before-rotation", 0)
        after = _alert(42, "after-rotation", 1)
        self.eve_path.write_text(unread)
        old_inode = self.eve_path.stat().st_ino
        self.write_position(0, old_inode)
        self.eve_path.rename(self.temp_path / "eve.json.1")
        self.eve_path.write_text(after)

        calls = []

        def capture(event, asset_context=None):
            calls.append(event["alert"]["signature_id"])
            if len(calls) >= 2:
                ingest._stop = True
            return {"verdict": "real", "confidence": 0.8, "reasoning": "t"}

        self.run_tail(
            call_ollama={"side_effect": capture},
            sleep={"return_value": None},
        )

        self.assertEqual(calls, [41, 42])
        # Written via temp file + os.replace, leaving no debris behind.
        self.assertEqual(list(self.temp_path.glob("*.tmp")), [])
        self.assertEqual(list(self.temp_path.glob(".*.tmp")), [])
        # And the result is a schema-valid cursor, not a torn file.
        with patch.object(ingest, "POSITION_PATH", self.position_path):
            self.assertEqual(
                set(ingest.load_position()), {"offset", "inode", "size"}
            )

    def test_checkpoint_write_failure_stops_ingest(self):
        """#59: an undurable in-memory cursor must not keep running.

        EveCheckpointError is not IngestCheckpointError, so this also proves
        the single `except EveCheckpointError` guard covers both families
        rather than dropping write failures into the generic retry path.
        """
        self.eve_path.write_text(_alert(51, "alert", 0))
        self.write_position(0, self.eve_path.stat().st_ino)

        def refuse(state):
            raise ingest.EveCheckpointError("could not write Suricata checkpoint")

        with self.assertRaises(ingest.EveCheckpointError):
            self.run_tail(
                call_ollama={
                    "return_value": {
                        "verdict": "real",
                        "confidence": 0.8,
                        "reasoning": "t",
                    }
                },
                save_position={"side_effect": refuse},
                sleep={"return_value": None},
            )

    def test_corrupt_checkpoint_still_fails_closed_in_the_daemon(self):
        """#59: a torn position.json must not silently rewind to offset 0."""
        self.eve_path.write_text(_alert(61, "alert", 0))
        self.position_path.write_text('{"offset": 12, "inode":')

        with self.assertRaises(ingest.EveCheckpointError):
            self.run_tail(sleep={"return_value": None})

    def test_both_checkpoint_error_families_exit_through_one_handler(self):
        """main() must terminate both fail-closed families identically.

        IngestCheckpointError subclasses EveCheckpointError precisely so a
        single handler covers a corrupt or unwritable checkpoint *and* a
        rotation that cannot be advanced safely. Listing only the subclass
        would let write failures escape as an unhandled crash.
        """
        self.assertTrue(
            issubclass(ingest.IngestCheckpointError, ingest.EveCheckpointError)
        )
        for error in (
            ingest.EveCheckpointError("corrupt checkpoint"),
            ingest.IngestCheckpointError("rotation cannot be advanced"),
        ):
            with self.subTest(error=type(error).__name__):
                with patch.object(ingest, "DEMO_MODE", False), patch.object(
                    ingest, "tail_file", side_effect=error
                ):
                    self.assertEqual(ingest.main(), 1)


class SuricataCheckpointDurabilityTests(unittest.TestCase):
    """Atomic writes and fail-closed loads for position.json."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.position_path = Path(self.temp_dir.name) / "position.json"
        self.position_patch = patch.object(
            ingest, "POSITION_PATH", self.position_path
        )
        self.position_patch.start()

    def tearDown(self):
        self.position_patch.stop()
        self.temp_dir.cleanup()

    def test_missing_checkpoint_starts_at_origin(self):
        self.assertEqual(
            ingest.load_position(),
            {"offset": 0, "inode": None, "size": 0},
        )

    def test_save_position_is_atomic_and_leaves_no_tmp(self):
        state = {"offset": 42, "inode": 7, "size": 99}
        ingest.save_position(state)
        self.assertEqual(ingest.load_position(), state)
        self.assertFalse(any(self.position_path.parent.glob("*.tmp")))

    def test_save_position_replaces_previous_checkpoint(self):
        ingest.save_position({"offset": 1, "inode": 1, "size": 1})
        ingest.save_position({"offset": 8, "inode": 2, "size": 8})
        self.assertEqual(
            ingest.load_position(),
            {"offset": 8, "inode": 2, "size": 8},
        )

    def test_corrupt_checkpoint_fails_closed_instead_of_rewinding(self):
        """A torn write must not silently restart at offset 0.

        Trigger: crash mid-``write_text`` leaves truncated JSON. The old loader
        caught the decode error and returned offset 0, which re-ingests the
        whole eve.json. Flow-less alerts bypass ``is_duplicate`` and land as
        duplicate ``triage_events`` rows.
        """
        self.position_path.write_text('{"offset": 12, "inode":')
        with self.assertRaises(ingest.EveCheckpointError) as ctx:
            ingest.load_position()
        self.assertIn("could not read Suricata checkpoint", str(ctx.exception))

    def test_invalid_checkpoint_schema_fails_closed(self):
        self.position_path.write_text(json.dumps({"offset": 0}))
        with self.assertRaises(ingest.EveCheckpointError) as ctx:
            ingest.load_position()
        self.assertIn("invalid schema", str(ctx.exception))

    def test_negative_offset_fails_closed(self):
        self.position_path.write_text(
            json.dumps({"offset": -1, "inode": None, "size": 0})
        )
        with self.assertRaises(ingest.EveCheckpointError):
            ingest.load_position()

    def test_bool_offset_fails_closed(self):
        # bool is a subclass of int; must not be accepted as a cursor.
        self.position_path.write_text(
            json.dumps({"offset": True, "inode": None, "size": 0})
        )
        with self.assertRaises(ingest.EveCheckpointError):
            ingest.load_position()


if __name__ == "__main__":
    unittest.main(verbosity=2)
