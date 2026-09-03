"""Bounded immutable filesystem store for standalone Lab artifacts."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable

from triagewall.event_bundle import (
    EVENT_BUNDLE_SCHEMA,
    MAX_BUNDLE_BYTES,
    canonical_json,
    load_event_bundle_bytes,
)
from triagewall.lab_contracts import (
    CANDIDATE_SCHEMA,
    EXPERIMENT_SCHEMA,
    MAX_LAB_CONTRACT_BYTES,
    PROMOTION_REPORT_SCHEMA,
    RESULT_SCHEMA,
    load_lab_contract_bytes,
    result_set_digest,
)


MAX_LISTED_ARTIFACTS = 2_000
COMPLETE_MANIFEST = "run-complete.json"


class LabStoreError(ValueError):
    """Raised when an artifact cannot be safely stored or read."""


class LabStore:
    _KINDS = ("bundles", "candidates", "experiments", "runs", "reports", "tmp")

    def __init__(self, root: Path, *, quota_bytes: int = 10 * 1024 * 1024 * 1024) -> None:
        self.requested_root = root.absolute()
        self.root = root.resolve()
        if quota_bytes < MAX_BUNDLE_BYTES:
            raise LabStoreError("Lab storage quota must allow at least one maximum bundle")
        self.quota_bytes = quota_bytes

    def initialize(self) -> None:
        if self.requested_root.exists() and self.requested_root.is_symlink():
            raise LabStoreError("Lab data root cannot be a symbolic link")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in self._KINDS:
            path = self.root / name
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                # The UI and worker initialize the same dedicated volume and
                # may create this directory concurrently.
                pass
            if path.is_symlink() or not path.is_dir():
                raise LabStoreError(f"Lab {name} path must be a real directory")

    def _artifact_path(self, kind: str, digest: str) -> Path:
        if kind not in {"bundles", "candidates", "experiments", "reports"}:
            raise LabStoreError("unsupported artifact kind")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise LabStoreError("artifact digest is malformed")
        return self.root / kind / f"{digest.removeprefix('sha256:')}.json"

    @staticmethod
    def _regular_file(path: Path, maximum: int) -> bytes:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise LabStoreError("artifact could not be read") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise LabStoreError("artifact must be a regular file")
        if metadata.st_size > maximum:
            raise LabStoreError("artifact exceeds its size limit")
        try:
            with path.open("rb") as handle:
                payload = handle.read(maximum + 1)
        except OSError as exc:
            raise LabStoreError("artifact could not be read") from exc
        if len(payload) > maximum:
            raise LabStoreError("artifact exceeds its size limit")
        return payload

    @staticmethod
    def _publish_once(path: Path, payload: bytes) -> bool:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".stage-", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            try:
                os.link(temporary, path)
            except FileExistsError:
                return False
            return True
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _store(self, kind: str, document: dict[str, Any]) -> dict[str, Any]:
        digest = document["content_sha256"]
        path = self._artifact_path(kind, digest)
        encoded = (canonical_json(document) + "\n").encode("utf-8")
        if not path.exists():
            self.ensure_capacity(len(encoded))
        created = self._publish_once(path, encoded)
        return {"created": created, "digest": digest}

    def usage_bytes(self) -> int:
        total = 0
        for path in self.root.rglob("*"):
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                total += metadata.st_size
        return total

    def ensure_capacity(self, additional_bytes: int) -> None:
        if additional_bytes < 0:
            raise LabStoreError("additional storage must not be negative")
        if self.usage_bytes() + additional_bytes > self.quota_bytes:
            raise LabStoreError("Lab storage quota would be exceeded")

    def load_document(self, kind: str, digest: str) -> dict[str, Any]:
        path = self._artifact_path(kind, digest)
        maximum = MAX_BUNDLE_BYTES if kind == "bundles" else MAX_LAB_CONTRACT_BYTES
        loader = load_event_bundle_bytes if kind == "bundles" else load_lab_contract_bytes
        return loader(self._regular_file(path, maximum))

    def create_run_directory(self, job_id: str) -> Path:
        if not re.fullmatch(r"job-[0-9a-f]{32}", job_id):
            raise LabStoreError("Lab job identity is invalid")
        path = self.root / "runs" / job_id
        path.mkdir(mode=0o700)
        return path

    def publish_result(self, run_dir: Path, result: dict[str, Any]) -> None:
        encoded = (canonical_json(result) + "\n").encode("utf-8")
        self.ensure_capacity(len(encoded))
        if not self._publish_once(run_dir / f"{result['result_id']}.json", encoded):
            raise LabStoreError("Lab result already exists")

    def publish_manifest(self, run_dir: Path, manifest: dict[str, Any]) -> None:
        encoded = (canonical_json(manifest) + "\n").encode("utf-8")
        self.ensure_capacity(len(encoded))
        if not self._publish_once(run_dir / COMPLETE_MANIFEST, encoded):
            raise LabStoreError("Lab completion manifest already exists")

    def import_bundle(self, payload: bytes) -> dict[str, Any]:
        if len(payload) > MAX_BUNDLE_BYTES:
            raise LabStoreError("bundle exceeds its size limit")
        document = load_event_bundle_bytes(payload)
        stored = self._store("bundles", document)
        return {**stored, "artifact": self._bundle_summary(document)}

    def import_contract(self, expected_schema: str, payload: bytes) -> dict[str, Any]:
        if len(payload) > MAX_LAB_CONTRACT_BYTES:
            raise LabStoreError("contract exceeds its size limit")
        document = load_lab_contract_bytes(payload)
        if document["schema"] != expected_schema:
            raise LabStoreError(f"expected {expected_schema}")
        if expected_schema == CANDIDATE_SCHEMA:
            kind = "candidates"
            summary = self._candidate_summary
        elif expected_schema == EXPERIMENT_SCHEMA:
            self._verify_experiment_bindings(document)
            kind = "experiments"
            summary = self._experiment_summary
        elif expected_schema == PROMOTION_REPORT_SCHEMA:
            self._verify_report_bindings(document)
            kind = "reports"
            summary = self._report_summary
        else:
            raise LabStoreError("unsupported contract type")
        stored = self._store(kind, document)
        return {**stored, "artifact": summary(document)}

    def _contains(self, kind: str, reference: dict[str, str]) -> bool:
        path = self._artifact_path(kind, reference["sha256"])
        if not path.exists():
            return False
        loader: Callable[[bytes], dict[str, Any]] = (
            load_event_bundle_bytes if kind == "bundles" else load_lab_contract_bytes
        )
        maximum = MAX_BUNDLE_BYTES if kind == "bundles" else MAX_LAB_CONTRACT_BYTES
        try:
            value = loader(self._regular_file(path, maximum))
        except (LabStoreError, ValueError):
            return False
        identifier = {
            "bundles": "bundle_id",
            "candidates": "candidate_id",
            "experiments": "experiment_id",
        }[kind]
        return value.get(identifier) == reference["id"]

    def _verify_experiment_bindings(self, document: dict[str, Any]) -> None:
        if not self._contains("bundles", document["bundle"]):
            raise LabStoreError("experiment bundle is not installed")
        for field in ("baseline_candidate", "candidate"):
            if not self._contains("candidates", document[field]):
                raise LabStoreError(f"experiment {field} is not installed")

    def _load_reference(self, kind: str, reference: dict[str, str]) -> dict[str, Any]:
        if not self._contains(kind, reference):
            raise LabStoreError(f"report {kind.rstrip('s')} is not installed")
        maximum = MAX_BUNDLE_BYTES if kind == "bundles" else MAX_LAB_CONTRACT_BYTES
        loader = load_event_bundle_bytes if kind == "bundles" else load_lab_contract_bytes
        return loader(self._regular_file(self._artifact_path(kind, reference["sha256"]), maximum))

    def _verify_report_bindings(self, document: dict[str, Any]) -> None:
        self._load_reference("bundles", document["bundle"])
        experiment = self._load_reference("experiments", document["experiment"])
        for field in ("baseline_candidate", "candidate"):
            self._load_reference("candidates", document[field])
            if document[field] != experiment[field]:
                raise LabStoreError(f"report {field} does not match its experiment")
        if document["bundle"] != experiment["bundle"]:
            raise LabStoreError("report bundle does not match its experiment")
        for directory in self._run_directories():
            try:
                manifest, _, runner_digest = self._load_validated_run(directory, 0)
            except LabStoreError:
                continue
            if (
                manifest["experiment"] == document["experiment"]
                and manifest["bundle"] == document["bundle"]
                and manifest["paired_result_count"] == document["completed_result_count"]
                and manifest["result_set_sha256"] == document["result_set_sha256"]
                and runner_digest == document["runner_sha256"]
            ):
                return
        raise LabStoreError("report is not backed by a complete validated run")

    def _list_documents(
        self,
        kind: str,
        loader: Callable[[bytes], dict[str, Any]],
        maximum: int,
        summary: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        directory = self.root / kind
        values = []
        for path in sorted(directory.glob("*.json"))[: MAX_LISTED_ARTIFACTS + 1]:
            if len(values) >= MAX_LISTED_ARTIFACTS:
                break
            try:
                values.append(summary(loader(self._regular_file(path, maximum))))
            except (LabStoreError, ValueError, json.JSONDecodeError):
                continue
        return values

    @staticmethod
    def _bundle_summary(value: dict[str, Any]) -> dict[str, Any]:
        labeled = sum(event.get("labels") is not None for event in value["events"])
        return {
            "id": value["bundle_id"],
            "digest": value["content_sha256"],
            "created_at": value["created_at"],
            "core_version": value["core_version"],
            "event_count": value["event_count"],
            "labeled_event_count": labeled,
        }

    @staticmethod
    def _candidate_summary(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": value["candidate_id"],
            "digest": value["content_sha256"],
            "created_at": value["created_at"],
            "author": value["author"],
            "parent_id": value["parent_candidate_id"],
            "model_name": value["model"]["name"],
            "model_digest": value["model"]["digest"],
            "rationale": value["rationale"],
        }

    def _experiment_summary(self, value: dict[str, Any]) -> dict[str, Any]:
        completed = self._completed_runs(value["experiment_id"], value["content_sha256"])
        selected_events = len(value["event_ids"]) if value["event_ids"] is not None else None
        if selected_events is None:
            try:
                selected_events = len(
                    self._load_reference("bundles", value["bundle"])["events"]
                )
            except LabStoreError:
                selected_events = None
        return {
            "id": value["experiment_id"],
            "digest": value["content_sha256"],
            "created_at": value["created_at"],
            "question": value["question"],
            "bundle_id": value["bundle"]["id"],
            "baseline_id": value["baseline_candidate"]["id"],
            "candidate_id": value["candidate"]["id"],
            "conditions": value["evidence_conditions"],
            "repetitions": value["repetitions"],
            "selected_events": selected_events,
            "planned_results": (
                selected_events * len(value["evidence_conditions"]) * value["repetitions"]
                if selected_events is not None
                else None
            ),
            "completed_runs": completed,
        }

    @staticmethod
    def _result_summary(value: dict[str, Any]) -> dict[str, Any]:
        def side(name: str) -> dict[str, Any]:
            outcome = value[name]
            score = outcome["score"]
            return {
                "candidate_id": outcome["candidate_id"],
                "validation_status": outcome["validation_status"],
                "failure_category": outcome["failure_category"],
                "verdict": outcome["verdict"],
                "confidence": outcome["confidence"],
                "reasoning": outcome["reasoning"],
                "duration_ms": outcome["duration_ms"],
                "score": score,
            }
        return {
            "id": value["result_id"],
            "digest": value["content_sha256"],
            "experiment_id": value["experiment"]["id"],
            "event_id": value["event_id"],
            "condition": value["evidence_condition"],
            "repetition": value["repetition"],
            "execution_order": value["execution_order"],
            "completed_at": value["completed_at"],
            "baseline": side("baseline"),
            "candidate": side("candidate"),
        }

    @staticmethod
    def _report_summary(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": value["report_id"],
            "digest": value["content_sha256"],
            "created_at": value["created_at"],
            "experiment_id": value["experiment"]["id"],
            "status": value["promotion_status"],
            "expected_results": value["expected_result_count"],
            "completed_results": value["completed_result_count"],
            "gates": value["gates"],
            "metrics": value["metrics"],
            "does_not_authorize_production": value["does_not_authorize_production"],
        }

    def list_bundles(self) -> list[dict[str, Any]]:
        return self._list_documents(
            "bundles", load_event_bundle_bytes, MAX_BUNDLE_BYTES, self._bundle_summary
        )

    def list_candidates(self) -> list[dict[str, Any]]:
        return self._list_documents(
            "candidates", load_lab_contract_bytes, MAX_LAB_CONTRACT_BYTES,
            self._candidate_summary,
        )

    def list_experiments(self) -> list[dict[str, Any]]:
        return self._list_documents(
            "experiments", load_lab_contract_bytes, MAX_LAB_CONTRACT_BYTES,
            self._experiment_summary,
        )

    def list_reports(self) -> list[dict[str, Any]]:
        return self._list_documents(
            "reports", load_lab_contract_bytes, MAX_LAB_CONTRACT_BYTES,
            self._report_summary,
        )

    def _run_directories(self) -> list[Path]:
        root = self.root / "runs"
        directories = []
        for path in sorted(root.iterdir(), reverse=True):
            if len(directories) >= MAX_LISTED_ARTIFACTS:
                break
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
                directories.append(path)
        return directories

    def _completed_runs(self, experiment_id: str, digest: str) -> int:
        count = 0
        for directory in self._run_directories():
            try:
                value, _, _ = self._load_validated_run(directory, 0)
            except LabStoreError:
                continue
            reference = value.get("experiment", {})
            if reference.get("id") == experiment_id and reference.get("sha256") == digest:
                count += 1
        return count

    @staticmethod
    def _strict_json(payload: bytes) -> Any:
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise LabStoreError("completion manifest contains a duplicate key")
                value[key] = item
            return value

        def reject_constant(value):
            raise LabStoreError(f"completion manifest contains non-finite JSON: {value}")

        try:
            return json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise LabStoreError("completion manifest is invalid") from exc

    def _load_completion_manifest(self, directory: Path) -> dict[str, Any]:
        path = directory / COMPLETE_MANIFEST
        value = self._strict_json(self._regular_file(path, MAX_LAB_CONTRACT_BYTES))
        fields = {
            "schema", "version", "experiment", "bundle", "paired_result_count",
            "nonaccepted_outcome_count", "result_set_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise LabStoreError("completion manifest has unknown or missing fields")
        if value["schema"] != "triagewall.lab-private-run-completion" or value["version"] != 1:
            raise LabStoreError("completion manifest schema is unsupported")
        for name in ("experiment", "bundle"):
            reference = value[name]
            if not isinstance(reference, dict) or set(reference) != {"id", "sha256"}:
                raise LabStoreError("completion manifest reference is invalid")
            if not isinstance(reference["id"], str) or not reference["id"]:
                raise LabStoreError("completion manifest reference ID is invalid")
            digest = reference["sha256"]
            if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
                raise LabStoreError("completion manifest digest is invalid")
        count = value["paired_result_count"]
        failures = value["nonaccepted_outcome_count"]
        if (
            isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 60_000
            or isinstance(failures, bool) or not isinstance(failures, int)
            or not 0 <= failures <= count * 2
        ):
            raise LabStoreError("completion manifest counts are invalid")
        result_digest = value["result_set_sha256"]
        if not isinstance(result_digest, str) or len(result_digest) != 71 or not result_digest.startswith("sha256:"):
            raise LabStoreError("completion manifest result digest is invalid")
        paths = list(directory.glob("pair-*.json"))
        if len(paths) != count:
            raise LabStoreError("completion manifest result count does not match files")
        return value

    def _load_validated_run(
        self,
        directory: Path,
        summary_limit: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
        manifest = self._load_completion_manifest(directory)
        digest_by_identity = {}
        summaries = []
        runner_digests = set()
        for path in sorted(directory.glob("pair-*.json")):
            try:
                value = load_lab_contract_bytes(
                    self._regular_file(path, MAX_LAB_CONTRACT_BYTES)
                )
            except (LabStoreError, ValueError) as exc:
                raise LabStoreError("run contains an invalid result") from exc
            if (
                value["schema"] != RESULT_SCHEMA
                or value["experiment"] != manifest["experiment"]
                or value["bundle"] != manifest["bundle"]
            ):
                raise LabStoreError("run result references do not match its manifest")
            identity = (
                value["event_id"],
                value["evidence_condition"],
                value["repetition"],
            )
            if identity in digest_by_identity:
                raise LabStoreError("run contains a duplicate result identity")
            digest_by_identity[identity] = value["content_sha256"]
            runner_digests.add(value["runner_sha256"])
            if len(summaries) < summary_limit:
                summaries.append(self._result_summary(value))
        try:
            experiment = self._load_reference("experiments", manifest["experiment"])
            bundle = self._load_reference("bundles", manifest["bundle"])
            selected_ids = experiment["event_ids"] or [
                event["event_id"] for event in bundle["events"]
            ]
            ordered_digests = [
                digest_by_identity[(event_id, condition, repetition)]
                for event_id in selected_ids
                for condition in experiment["evidence_conditions"]
                for repetition in range(1, experiment["repetitions"] + 1)
            ]
        except (KeyError, LabStoreError) as exc:
            raise LabStoreError("run does not cover its installed experiment") from exc
        if len(ordered_digests) != manifest["paired_result_count"] or (
            result_set_digest(ordered_digests) != manifest["result_set_sha256"]
        ):
            raise LabStoreError("run result set does not match its manifest")
        if len(runner_digests) != 1:
            raise LabStoreError("run contains inconsistent runner identities")
        return manifest, summaries, next(iter(runner_digests))

    def list_results(self, limit: int = 200) -> list[dict[str, Any]]:
        bounded = min(max(limit, 1), 500)
        results = []
        for directory in self._run_directories():
            try:
                _, run_results, _ = self._load_validated_run(
                    directory,
                    bounded - len(results),
                )
            except LabStoreError:
                continue
            results.extend(run_results)
            if len(results) >= bounded:
                return results
        return results

    def status(self) -> dict[str, Any]:
        return {
            "bundles": len(self.list_bundles()),
            "candidates": len(self.list_candidates()),
            "experiments": len(self.list_experiments()),
            "results": len(self.list_results(limit=500)),
            "reports": len(self.list_reports()),
            "storage_used_bytes": self.usage_bytes(),
            "storage_quota_bytes": self.quota_bytes,
        }
