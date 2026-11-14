#!/usr/bin/env python3
"""Run one private, immutable TriageWall Lab paired experiment."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagewall.event_bundle import MAX_BUNDLE_BYTES, canonical_json, load_event_bundle_bytes
from triagewall.lab_contracts import (
    CANDIDATE_SCHEMA,
    EXPERIMENT_SCHEMA,
    MAX_LAB_CONTRACT_BYTES,
    load_lab_contract_bytes,
    result_set_digest,
)
from triagewall.lab_runner import OllamaTransport, run_experiment


PRIVATE_MARKER = ".triagewall-lab-private-v1"
COMPLETE_MANIFEST = "run-complete.json"


def _read_regular_file(path: Path, maximum: int) -> bytes:
    if path.is_symlink():
        raise ValueError("input must not be a symbolic link")
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ValueError("input could not be inspected") from exc
    if not stat.S_ISREG(mode):
        raise ValueError("input must be a regular file")
    with path.open("rb") as handle:
        payload = handle.read(maximum + 1)
    if len(payload) > maximum:
        raise ValueError("input exceeded its byte limit")
    return payload


def _load_contract(path: Path, schema: str) -> dict:
    value = load_lab_contract_bytes(
        _read_regular_file(path, MAX_LAB_CONTRACT_BYTES)
    )
    if value["schema"] != schema:
        raise ValueError("Lab contract had the wrong schema")
    return value


def _prepare_private_root(path: Path) -> Path:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("private output must be a real directory")
        entries = list(path.iterdir())
        marker = path / PRIVATE_MARKER
        if entries and not marker.is_file():
            raise ValueError(
                "non-empty output directory is not a TriageWall Lab private store"
            )
    else:
        path.mkdir(parents=True, mode=0o700)
    marker = path / PRIVATE_MARKER
    if not marker.exists():
        with marker.open("xb") as handle:
            handle.write(b"Private TriageWall Lab results. Do not publish.\n")
            handle.flush()
            os.fsync(handle.fileno())
    return path.resolve()


def _atomic_create(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is same-directory, atomic, and refuses to
        # replace an immutable result that already exists.
        os.link(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _arguments(argv=None):
    parser = argparse.ArgumentParser(
        description="Run an isolated baseline/candidate Lab experiment against local Ollama."
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--experiment", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434/api/generate",
        help="Trusted loopback/private Ollama endpoint (default: localhost).",
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _arguments(argv)
    try:
        bundle = load_event_bundle_bytes(
            _read_regular_file(args.bundle, MAX_BUNDLE_BYTES)
        )
        baseline = _load_contract(args.baseline, CANDIDATE_SCHEMA)
        candidate = _load_contract(args.candidate, CANDIDATE_SCHEMA)
        experiment = _load_contract(args.experiment, EXPERIMENT_SCHEMA)
        private_root = _prepare_private_root(args.output_dir)
        run_name = (
            experiment["experiment_id"]
            + "-"
            + experiment["content_sha256"].removeprefix("sha256:")[:16]
        )
        run_dir = private_root / run_name
        run_dir.mkdir(mode=0o700)

        transport = OllamaTransport(args.ollama_url)
        result_digests = []
        failures = 0
        for result in run_experiment(
            bundle=bundle,
            baseline=baseline,
            candidate=candidate,
            experiment=experiment,
            transport=transport,
            timeout=args.timeout,
        ):
            encoded = (canonical_json(result) + "\n").encode("utf-8")
            _atomic_create(run_dir / f"{result['result_id']}.json", encoded)
            result_digests.append(result["content_sha256"])
            failures += sum(
                result[side]["validation_status"] != "accepted"
                for side in ("baseline", "candidate")
            )

        manifest = {
            "schema": "triagewall.lab-private-run-completion",
            "version": 1,
            "experiment": {
                "id": experiment["experiment_id"],
                "sha256": experiment["content_sha256"],
            },
            "bundle": dict(experiment["bundle"]),
            "paired_result_count": len(result_digests),
            "nonaccepted_outcome_count": failures,
            "result_set_sha256": result_set_digest(result_digests),
        }
        _atomic_create(
            run_dir / COMPLETE_MANIFEST,
            (canonical_json(manifest) + "\n").encode("utf-8"),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        message = str(exc).replace("\r", " ").replace("\n", " ")[:300]
        print(f"Lab run failed safely: {message}", file=sys.stderr)
        return 1

    print(
        f"Lab run complete: {len(result_digests)} paired results, "
        f"{failures} non-accepted model outcomes."
    )
    print(f"Private results: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
