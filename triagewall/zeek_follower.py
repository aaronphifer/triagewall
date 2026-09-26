"""Bounded, fail-closed followers for local Zeek JSON log files."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import os
import re
import sqlite3
import stat
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path

try:
    from .zeek_index import (
        MAX_CONN_RECORD_BYTES,
        SUPPORTED_EVIDENCE_LOGS,
        ZeekLogCheckpoint,
        index_conn_failure,
        index_conn_line,
        index_evidence_line,
        load_checkpoint,
        rotate_checkpoint,
    )
except ImportError:  # Direct script-style imports used by container entrypoints.
    from zeek_index import (
        MAX_CONN_RECORD_BYTES,
        SUPPORTED_EVIDENCE_LOGS,
        ZeekLogCheckpoint,
        index_conn_failure,
        index_conn_line,
        index_evidence_line,
        load_checkpoint,
        rotate_checkpoint,
    )


MAX_ROTATION_SCAN_ENTRIES = 512
MAX_ROTATION_DIRECTORY_ENTRIES = 100_000
MAX_ARCHIVE_DIRECTORIES = 400
MAX_ARCHIVE_RECOVERY_CANDIDATES = 64
MAX_ARCHIVE_VERIFY_BYTES = 512 * 1024 * 1024
MAX_RECORDS_PER_POLL = 100_000
READ_CHUNK_BYTES = 64 * 1024
MAX_OVERSIZED_RECORD_BYTES = 1024 * 1024
MAX_SUCCESSOR_PREFIX_BYTES = 64 * 1024
COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst")
_NUMBERED_ROTATION_RE = re.compile(r"^\.([1-9]\d*)$")
_DATED_ARCHIVE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ZEEKCONTROL_INTERVAL_SUFFIX = (
    r"\.(?:(\d{2}:\d{2}:\d{2})-(\d{2}:\d{2}:\d{2})|"
    r"(\d{2}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2}))"
    r"\.log(?:\.(?:gz|bz2|xz|zst))?$"
)


class ZeekFollowerError(RuntimeError):
    """The follower cannot advance without risking a Zeek context gap."""


@dataclass(frozen=True)
class ZeekPollResult:
    scanned: int = 0
    indexed: int = 0
    failures: int = 0
    rotated: bool = False


@dataclass(frozen=True)
class _Source:
    path: Path
    device: int
    inode: int
    size: int
    compressed: bool
    physical_device: int | None = None
    physical_inode: int | None = None
    modified_at: float | None = None

    @property
    def physical_identity(self) -> tuple[int, int]:
        return (
            self.device if self.physical_device is None else self.physical_device,
            self.inode if self.physical_inode is None else self.physical_inode,
        )


@dataclass(frozen=True)
class _RecordRead:
    raw: bytes | None
    complete: bool
    byte_count: int = 0
    digest: str | None = None


def _is_compressed(path: Path) -> bool:
    return path.name.endswith(COMPRESSED_SUFFIXES)


def _rotation_sort_key(name: str, live_name: str):
    if name == live_name:
        return (2, 0, "")
    suffix = name[len(live_name):]
    for compressed in COMPRESSED_SUFFIXES:
        if suffix.endswith(compressed):
            suffix = suffix[: -len(compressed)]
            break
    numbered = _NUMBERED_ROTATION_RE.fullmatch(suffix)
    if numbered is not None:
        return (0, -int(numbered.group(1)), "")
    return (1, 0, suffix)


def _numbered_rotation(name: str, live_name: str) -> int | None:
    suffix = name[len(live_name):]
    for compressed in COMPRESSED_SUFFIXES:
        if suffix.endswith(compressed):
            suffix = suffix[: -len(compressed)]
            break
    match = _NUMBERED_ROTATION_RE.fullmatch(suffix)
    return int(match.group(1)) if match is not None else None


def _log_stem(live_name: str) -> str:
    if not live_name.endswith(".log") or len(live_name) <= 4:
        raise ZeekFollowerError("Zeek live log name must end in .log")
    return live_name[:-4]


def _archived_log_pattern(live_name: str) -> re.Pattern:
    stem = re.escape(_log_stem(live_name))
    return re.compile(
        rf"^{stem}(?:\..+)?\.log(?:\.(?:gz|bz2|xz|zst))?$"
    )


def _zeekcontrol_archive_interval(
    path: Path,
    live_name: str = "conn.log",
) -> tuple[datetime, datetime] | None:
    if _DATED_ARCHIVE_RE.fullmatch(path.parent.name) is None:
        return None
    match = re.fullmatch(
        "^" + re.escape(_log_stem(live_name)) + _ZEEKCONTROL_INTERVAL_SUFFIX,
        path.name,
    )
    if match is None:
        return None
    start_text = (match.group(1) or match.group(3)).replace("-", ":")
    end_text = (match.group(2) or match.group(4)).replace("-", ":")
    try:
        start = datetime.strptime(
            f"{path.parent.name} {start_text}",
            "%Y-%m-%d %H:%M:%S",
        )
        end = datetime.strptime(
            f"{path.parent.name} {end_text}",
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError as exc:
        raise ZeekFollowerError(
            f"invalid ZeekControl archive interval: {path}"
        ) from exc
    if end <= start:
        end += timedelta(days=1)
    return start, end


def _safe_source(path: Path) -> _Source:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ZeekFollowerError(f"could not inspect Zeek log {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ZeekFollowerError(f"Zeek log path must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ZeekFollowerError(f"Zeek log path is not a regular file: {path}")
    return _Source(
        path=path,
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        size=int(metadata.st_size),
        compressed=_is_compressed(path),
        modified_at=float(metadata.st_mtime),
    )


def _optional_live_source(path: Path) -> _Source | None:
    try:
        return _safe_source(path)
    except ZeekFollowerError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise


def _scan_dated_archives(
    archive_root: Path,
    live_name: str = "conn.log",
) -> list[_Source]:
    archives: list[tuple[str, str, _Source]] = []
    archive_pattern = _archived_log_pattern(live_name)
    examined = 0
    dated_directories = 0
    try:
        root_metadata = archive_root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode):
            raise ZeekFollowerError(
                f"Zeek archive root must not be a symlink: {archive_root}"
            )
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise ZeekFollowerError(
                f"Zeek archive root is not a directory: {archive_root}"
            )
        with os.scandir(archive_root) as root_entries:
            for root_entry in root_entries:
                examined += 1
                if examined > MAX_ROTATION_DIRECTORY_ENTRIES:
                    raise ZeekFollowerError(
                        "Zeek archive root exceeds its bounded scan limit"
                    )
                if _DATED_ARCHIVE_RE.fullmatch(root_entry.name) is None:
                    continue
                directory = Path(root_entry.path)
                directory_metadata = directory.lstat()
                if stat.S_ISLNK(directory_metadata.st_mode):
                    raise ZeekFollowerError(
                        f"Zeek dated archive must not be a symlink: {directory}"
                    )
                if not stat.S_ISDIR(directory_metadata.st_mode):
                    raise ZeekFollowerError(
                        f"Zeek dated archive is not a directory: {directory}"
                    )
                dated_directories += 1
                if dated_directories > MAX_ARCHIVE_DIRECTORIES:
                    raise ZeekFollowerError(
                        "Zeek dated archive count exceeds its bounded scan limit"
                    )
                with os.scandir(directory) as entries:
                    for entry in entries:
                        examined += 1
                        if examined > MAX_ROTATION_DIRECTORY_ENTRIES:
                            raise ZeekFollowerError(
                                "Zeek archives exceed their bounded scan limit"
                            )
                        if archive_pattern.fullmatch(entry.name) is None:
                            continue
                        if len(archives) >= MAX_ROTATION_SCAN_ENTRIES:
                            raise ZeekFollowerError(
                                "Zeek archive chain exceeds its bounded scan limit"
                            )
                        archives.append(
                            (
                                root_entry.name,
                                entry.name,
                                _safe_source(Path(entry.path)),
                            )
                        )
    except ZeekFollowerError:
        raise
    except OSError as exc:
        raise ZeekFollowerError(f"could not enumerate Zeek archives: {exc}") from exc
    archives.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in archives]


def _scan_rotation_chain(
    live_path: Path,
    archive_root: Path | None = None,
) -> list[_Source]:
    chain: list[_Source] = []
    examined = 0
    matched = 0
    try:
        with os.scandir(live_path.parent) as entries:
            for entry in entries:
                examined += 1
                if examined > MAX_ROTATION_DIRECTORY_ENTRIES:
                    raise ZeekFollowerError(
                        "Zeek log directory exceeds its bounded scan limit"
                    )
                if not entry.name.startswith(live_path.name):
                    continue
                matched += 1
                if matched > MAX_ROTATION_SCAN_ENTRIES:
                    raise ZeekFollowerError(
                        "Zeek rotation chain exceeds its bounded scan limit"
                    )
                candidate = Path(entry.path)
                chain.append(_safe_source(candidate))
    except ZeekFollowerError:
        raise
    except OSError as exc:
        raise ZeekFollowerError(
            f"could not enumerate Zeek rotation chain: {exc}"
        ) from exc
    chain.sort(key=lambda item: _rotation_sort_key(item.path.name, live_path.name))
    if archive_root is not None:
        chain = _scan_dated_archives(archive_root, live_path.name) + chain
    identities = [(item.device, item.inode) for item in chain]
    if len(identities) != len(set(identities)):
        raise ZeekFollowerError("Zeek rotation chain contains duplicate file identities")
    return chain


def _open_compressed_stream(raw_stream, path: Path):
    if path.name.endswith(".gz"):
        return gzip.GzipFile(fileobj=raw_stream, mode="rb")
    if path.name.endswith(".bz2"):
        return bz2.BZ2File(raw_stream, mode="rb")
    if path.name.endswith(".xz"):
        return lzma.LZMAFile(raw_stream, mode="rb")
    raise ZeekFollowerError(
        f"unsupported compressed Zeek archive format: {path}"
    )


def _stream_matches_checkpoint(stream, checkpoint: ZeekLogCheckpoint) -> bool:
    if checkpoint.offset == 0:
        if checkpoint.prefix_bytes is None or checkpoint.prefix_sha256 is None:
            return False
        stream.seek(0)
        prefix = stream.read(checkpoint.prefix_bytes)
        if len(prefix) != checkpoint.prefix_bytes:
            return False
        digest = "sha256:" + hashlib.sha256(prefix).hexdigest()
        if digest != checkpoint.prefix_sha256:
            return False
        if checkpoint.file_size > checkpoint.prefix_bytes:
            stream.seek(checkpoint.file_size - 1)
            if len(stream.read(1)) != 1:
                return False
        return True
    if checkpoint.record_bytes is None or checkpoint.record_sha256 is None:
        return False
    start = checkpoint.offset - checkpoint.record_bytes
    stream.seek(start)
    anchored = stream.read(checkpoint.record_bytes)
    if len(anchored) != checkpoint.record_bytes:
        return False
    digest = "sha256:" + hashlib.sha256(anchored).hexdigest()
    if digest != checkpoint.record_sha256:
        return False
    if checkpoint.file_size > checkpoint.offset:
        stream.seek(checkpoint.file_size - 1)
        if len(stream.read(1)) != 1:
            return False
    return True


def _source_matches_checkpoint(
    source: _Source,
    checkpoint: ZeekLogCheckpoint,
    *,
    enforce_recovery_work_limit: bool = True,
) -> bool:
    verification_extent = (
        checkpoint.prefix_bytes
        if checkpoint.offset == 0 and not source.compressed
        else max(checkpoint.offset, checkpoint.file_size)
    )
    if verification_extent is None:
        return False
    if (
        enforce_recovery_work_limit
        and verification_extent > MAX_ARCHIVE_VERIFY_BYTES
    ):
        raise ZeekFollowerError(
            "Zeek checkpoint exceeds the bounded recovery verification limit"
        )
    raw_stream = None
    stream = None
    try:
        raw_stream = source.path.open("rb")
        opened = os.fstat(raw_stream.fileno())
        if (int(opened.st_dev), int(opened.st_ino)) != source.physical_identity:
            raise ZeekFollowerError(
                "Zeek archive identity changed during recovery verification"
            )
        stream = (
            _open_compressed_stream(raw_stream, source.path)
            if source.compressed
            else raw_stream
        )
        return _stream_matches_checkpoint(stream, checkpoint)
    except ZeekFollowerError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError) as exc:
        source_kind = "compressed Zeek archive" if source.compressed else "Zeek log"
        raise ZeekFollowerError(
            f"could not verify {source_kind} {source.path}: {exc}"
        ) from exc
    finally:
        if stream is not None and stream is not raw_stream:
            stream.close()
        if raw_stream is not None:
            raw_stream.close()


def _successor_prefix_anchor(
    source: _Source,
) -> tuple[int, int, str] | None:
    raw_stream = None
    stream = None
    try:
        raw_stream = source.path.open("rb")
        opened = os.fstat(raw_stream.fileno())
        if (int(opened.st_dev), int(opened.st_ino)) != source.physical_identity:
            raise ZeekFollowerError(
                "Zeek successor identity changed during prefix verification"
            )
        stream = (
            _open_compressed_stream(raw_stream, source.path)
            if source.compressed
            else raw_stream
        )
        prefix = stream.read(MAX_SUCCESSOR_PREFIX_BYTES)
        observed = os.fstat(raw_stream.fileno())
        if (int(observed.st_dev), int(observed.st_ino)) != source.physical_identity:
            raise ZeekFollowerError(
                "Zeek successor identity changed during prefix verification"
            )
    except ZeekFollowerError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError) as exc:
        source_kind = "compressed Zeek archive" if source.compressed else "Zeek log"
        raise ZeekFollowerError(
            f"could not authenticate {source_kind} successor {source.path}: {exc}"
        ) from exc
    finally:
        if stream is not None and stream is not raw_stream:
            stream.close()
        if raw_stream is not None:
            raw_stream.close()

    if not prefix:
        return None
    if not source.compressed:
        opened_size = int(observed.st_size)
        if len(prefix) != min(opened_size, MAX_SUCCESSOR_PREFIX_BYTES):
            return None
        checkpoint_size = opened_size
    else:
        checkpoint_size = len(prefix)
    if (
        len(prefix) < MAX_SUCCESSOR_PREFIX_BYTES
        and not prefix.endswith((b"\n", b"\r"))
    ):
        return None
    return (
        checkpoint_size,
        len(prefix),
        "sha256:" + hashlib.sha256(prefix).hexdigest(),
    )


def _read_record(stream) -> _RecordRead:
    first = stream.readline(MAX_CONN_RECORD_BYTES + 1)
    if not first:
        return _RecordRead(raw=None, complete=True)
    if len(first) <= MAX_CONN_RECORD_BYTES:
        return _RecordRead(
            raw=first,
            complete=first.endswith((b"\n", b"\r")),
            byte_count=len(first),
        )

    digest = hashlib.sha256(first)
    total = len(first)
    complete = first.endswith((b"\n", b"\r"))
    while not complete:
        remaining = MAX_OVERSIZED_RECORD_BYTES - total
        if remaining <= 0:
            raise ZeekFollowerError(
                "Zeek conn.log record exceeded the "
                f"{MAX_OVERSIZED_RECORD_BYTES}-byte drain limit before a "
                "terminator"
            )
        chunk = stream.readline(min(READ_CHUNK_BYTES, remaining + 1))
        if not chunk:
            raise ZeekFollowerError(
                "oversized Zeek conn.log record reached EOF without a "
                "terminator"
            )
        digest.update(chunk)
        total += len(chunk)
        if total > MAX_OVERSIZED_RECORD_BYTES:
            raise ZeekFollowerError(
                "Zeek conn.log record exceeded the "
                f"{MAX_OVERSIZED_RECORD_BYTES}-byte drain limit before a "
                "terminator"
            )
        complete = chunk.endswith((b"\n", b"\r"))
    return _RecordRead(
        raw=None,
        complete=True,
        byte_count=total,
        digest="sha256:" + digest.hexdigest(),
    )


class ZeekFollower:
    """Read one Zeek JSON log and preserve an exact per-log SQLite cursor."""

    def __init__(
        self,
        live_path: str | Path,
        source_instance: str,
        *,
        max_records_per_poll: int = 1_000,
        eof_stable_observations: int = 2,
        archive_root: str | Path | None = None,
        log_name: str = "conn",
    ) -> None:
        if (
            type(max_records_per_poll) is not int
            or not 1 <= max_records_per_poll <= MAX_RECORDS_PER_POLL
        ):
            raise ValueError(
                f"max_records_per_poll must be from 1 to {MAX_RECORDS_PER_POLL}"
            )
        if type(eof_stable_observations) is not int or eof_stable_observations < 2:
            raise ValueError("eof_stable_observations must be at least 2")
        if log_name not in ({"conn"} | SUPPORTED_EVIDENCE_LOGS):
            raise ValueError("log_name must be a supported Zeek log")
        self.live_path = Path(live_path)
        _log_stem(self.live_path.name)
        self.source_instance = source_instance
        self.log_name = log_name
        self._line_indexer = (
            index_conn_line if log_name == "conn" else index_evidence_line
        )
        self.max_records_per_poll = max_records_per_poll
        self.eof_stable_observations = eof_stable_observations
        self.archive_root = None if archive_root is None else Path(archive_root)
        self._eof_key: tuple[int, int, int, int] | None = None
        self._eof_count = 0
        self._stream = None
        self._raw_stream = None
        self._stream_source: _Source | None = None
        self._opened_as_live = False
        self._observed_successor: tuple[int, int] | None = None

    def close(self) -> None:
        """Release the retained descriptor used to drain renamed logs."""

        if self._stream is not None:
            self._stream.close()
        if self._raw_stream is not None and self._raw_stream is not self._stream:
            self._raw_stream.close()
        self._stream = None
        self._raw_stream = None
        self._stream_source = None
        self._opened_as_live = False
        self._observed_successor = None
        self._reset_eof()

    def _open_source(
        self,
        source: _Source,
        *,
        opened_as_live: bool,
    ) -> None:
        self.close()
        try:
            raw_stream = source.path.open("rb")
            opened = os.fstat(raw_stream.fileno())
        except OSError as exc:
            raise ZeekFollowerError(
                f"could not open Zeek log {source.path}: {exc}"
            ) from exc
        if (
            (int(opened.st_dev), int(opened.st_ino)) != source.physical_identity
        ):
            raw_stream.close()
            raise ZeekFollowerError(
                "Zeek log identity changed between inspection and open"
            )
        try:
            stream = (
                _open_compressed_stream(raw_stream, source.path)
                if source.compressed
                else raw_stream
            )
        except Exception:
            raw_stream.close()
            raise
        self._stream = stream
        self._raw_stream = raw_stream
        self._stream_source = source
        self._opened_as_live = opened_as_live

    def _active_source(
        self,
        checkpoint: ZeekLogCheckpoint | None,
    ) -> _Source:
        if self._stream is not None and self._stream_source is not None:
            raw_stream = self._raw_stream
            if raw_stream is None:
                raise ZeekFollowerError("Zeek raw descriptor is unexpectedly closed")
            opened = os.fstat(raw_stream.fileno())
            physical_identity = (int(opened.st_dev), int(opened.st_ino))
            expected = (
                None
                if checkpoint is None
                else (checkpoint.device, checkpoint.inode)
            )
            logical_identity = (
                self._stream_source.device,
                self._stream_source.inode,
            )
            if (
                physical_identity == self._stream_source.physical_identity
                and (expected is None or logical_identity == expected)
            ):
                source = _Source(
                    path=self._stream_source.path,
                    device=logical_identity[0],
                    inode=logical_identity[1],
                    size=(
                        checkpoint.file_size
                        if self._stream_source.compressed and checkpoint is not None
                        else int(opened.st_size)
                    ),
                    compressed=self._stream_source.compressed,
                    physical_device=physical_identity[0],
                    physical_inode=physical_identity[1],
                    modified_at=float(opened.st_mtime),
                )
                if (
                    checkpoint is not None
                    and not source.compressed
                    and source.size >= checkpoint.offset
                    and source.size >= checkpoint.file_size
                ):
                    path_source = _optional_live_source(source.path)
                    if (
                        path_source is not None
                        and path_source.physical_identity == physical_identity
                        and not _source_matches_checkpoint(
                            path_source,
                            checkpoint,
                            enforce_recovery_work_limit=False,
                        )
                    ):
                        self.close()
                        raise ZeekFollowerError(
                            "the active Zeek log does not match the durable "
                            "record anchor"
                        )
                return source
            self.close()

        source, _chain = self._resolve_source(checkpoint)
        live = _safe_source(self.live_path)
        opened_as_live = source.physical_identity == (live.device, live.inode)
        self._open_source(source, opened_as_live=opened_as_live)
        if checkpoint is not None:
            if self._stream is None or not _stream_matches_checkpoint(
                self._stream,
                checkpoint,
            ):
                self.close()
                raise ZeekFollowerError(
                    "the reopened Zeek log does not match the durable record anchor"
                )
        return source

    def _resolve_source(
        self,
        checkpoint: ZeekLogCheckpoint | None,
    ) -> tuple[_Source, list[_Source]]:
        live = _safe_source(self.live_path)
        if checkpoint is None:
            return live, [live]

        chain = _scan_rotation_chain(self.live_path, self.archive_root)
        matches = [
            item
            for item in chain
            if (item.device, item.inode) == (checkpoint.device, checkpoint.inode)
        ]
        verified_matches = [
            item
            for item in matches
            if _source_matches_checkpoint(item, checkpoint)
        ]
        if len(verified_matches) == 1:
            match = verified_matches[0]
            if match.compressed:
                match = replace(match, size=checkpoint.file_size)
            return match, chain
        if len(verified_matches) > 1:
            raise ZeekFollowerError(
                "the checkpointed inode is ambiguous in the Zeek rotation chain"
            )
        if checkpoint.offset == 0 and (
            checkpoint.prefix_bytes is None or checkpoint.prefix_sha256 is None
        ):
            raise ZeekFollowerError(
                "the zero-offset Zeek checkpoint has no durable successor prefix; "
                "the follower will not trust a reused file identity"
            )
        if checkpoint.offset > 0 and (
            checkpoint.record_bytes is None or checkpoint.record_sha256 is None
        ):
            raise ZeekFollowerError(
                "the checkpointed inode is missing from the Zeek rotation chain; "
                "no durable record anchor is available for archive recovery"
            )
        candidates = [
            item
            for item in chain
            if item.physical_identity != (live.device, live.inode)
        ]
        if len(candidates) > MAX_ARCHIVE_RECOVERY_CANDIDATES:
            raise ZeekFollowerError(
                "Zeek archive recovery exceeds its bounded candidate limit"
            )
        estimated_work = sum(
            (
                checkpoint.prefix_bytes
                if checkpoint.offset == 0 and not item.compressed
                else max(checkpoint.offset, checkpoint.file_size)
            )
            for item in candidates
        )
        if estimated_work > MAX_ARCHIVE_VERIFY_BYTES:
            raise ZeekFollowerError(
                "Zeek archive recovery exceeds its bounded verification budget"
            )
        anchor_matches = [
            item
            for item in candidates
            if _source_matches_checkpoint(item, checkpoint)
        ]
        if len(anchor_matches) != 1:
            reason = "ambiguous" if len(anchor_matches) > 1 else "missing"
            anchor_name = (
                "successor prefix" if checkpoint.offset == 0 else "record anchor"
            )
            raise ZeekFollowerError(
                f"the checkpointed inode is missing and its {anchor_name} is {reason} "
                "in the Zeek archives; "
                "the follower will not skip to the live file"
            )
        archived = anchor_matches[0]
        recovered = replace(
            archived,
            device=checkpoint.device,
            inode=checkpoint.inode,
            size=checkpoint.file_size,
            physical_device=archived.device,
            physical_inode=archived.inode,
        )
        return recovered, chain

    def _observe_stable_eof(
        self,
        source: _Source,
        offset: int,
        size: int,
    ) -> bool:
        key = (source.device, source.inode, offset, size)
        if key == self._eof_key:
            self._eof_count += 1
        else:
            self._eof_key = key
            self._eof_count = 1
        return self._eof_count >= self.eof_stable_observations

    def _reset_eof(self) -> None:
        self._eof_key = None
        self._eof_count = 0

    def _successor(
        self,
        source: _Source,
        chain: list[_Source],
    ) -> _Source | None:
        for index, candidate in enumerate(chain):
            if (
                candidate.physical_identity == source.physical_identity
            ):
                if index + 1 < len(chain):
                    successor = chain[index + 1]
                    current_number = _numbered_rotation(
                        source.path.name,
                        self.live_path.name,
                    )
                    if current_number is not None:
                        successor_number = _numbered_rotation(
                            successor.path.name,
                            self.live_path.name,
                        )
                        expected_number = current_number - 1
                        valid_numbered = successor_number == expected_number
                        valid_live = (
                            expected_number == 0
                            and successor.path.name == self.live_path.name
                        )
                        if not valid_numbered and not valid_live:
                            raise ZeekFollowerError(
                                "the numbered Zeek rotation chain has a gap; "
                                "the follower will not skip an archive"
                            )
                    current_is_dated = (
                        _DATED_ARCHIVE_RE.fullmatch(source.path.parent.name)
                        is not None
                    )
                    if current_number is None and not current_is_dated:
                        raise ZeekFollowerError(
                            "the checkpointed Zeek archive has an unverifiable "
                            "rotation filename; the follower will not infer a "
                            "successor from lexical order"
                        )
                    successor_is_dated = (
                        _DATED_ARCHIVE_RE.fullmatch(successor.path.parent.name)
                        is not None
                    )
                    if current_is_dated and successor_is_dated:
                        current_interval = _zeekcontrol_archive_interval(
                            source.path,
                            self.live_path.name,
                        )
                        successor_interval = _zeekcontrol_archive_interval(
                            successor.path,
                            self.live_path.name,
                        )
                        if (
                            current_interval is None
                            or successor_interval is None
                            or current_interval[1] != successor_interval[0]
                        ):
                            raise ZeekFollowerError(
                                "the ZeekControl dated archive chain has a gap or "
                                "an unverifiable filename; the follower will not "
                                "skip an archive"
                            )
                    if current_is_dated and not successor_is_dated:
                        current_interval = _zeekcontrol_archive_interval(
                            source.path,
                            self.live_path.name,
                        )
                        live_modified = (
                            None
                            if successor.modified_at is None
                            else datetime.fromtimestamp(successor.modified_at)
                        )
                        if (
                            successor.path != self.live_path
                            or current_interval is None
                            or live_modified is None
                            or not (
                                current_interval[1]
                                <= live_modified
                                < current_interval[1]
                                + (current_interval[1] - current_interval[0])
                            )
                        ):
                            raise ZeekFollowerError(
                                "the ZeekControl dated archive-to-live handoff "
                                "cannot be proven adjacent; the follower will not "
                                "skip a possibly missing archive"
                            )
                    return successor
                return None
        return None

    def poll(
        self,
        conn: sqlite3.Connection,
        *,
        record_limit: int | None = None,
    ) -> ZeekPollResult:
        """Process one bounded batch currently available on disk."""

        batch_limit = self.max_records_per_poll if record_limit is None else record_limit
        if (
            type(batch_limit) is not int
            or not 1 <= batch_limit <= self.max_records_per_poll
        ):
            raise ValueError(
                "record_limit must be from 1 to the follower's configured maximum"
            )

        scanned = 0
        indexed = 0
        failures = 0
        rotated = False

        while scanned < batch_limit:
            checkpoint = load_checkpoint(
                conn,
                self.source_instance,
                self.log_name,
            )
            source = self._active_source(checkpoint)
            offset = 0 if checkpoint is None else checkpoint.offset
            if (not source.compressed and source.size < offset) or (
                checkpoint is not None
                and not source.compressed
                and source.size < checkpoint.file_size
            ):
                raise ZeekFollowerError(
                    f"Zeek log {source.path} shrank behind its durable checkpoint"
                )

            stream = self._stream
            if stream is None:
                raise ZeekFollowerError("Zeek log descriptor is unexpectedly closed")
            try:
                stream.seek(offset)
                if stream.tell() != offset:
                    raise ZeekFollowerError(
                        "Zeek log ends before its durable checkpoint"
                    )

                while scanned < batch_limit:
                    record = _read_record(stream)
                    if not record.complete:
                        self._reset_eof()
                        return ZeekPollResult(scanned, indexed, failures, rotated)
                    if record.raw is None and record.digest is None:
                        break
                    if (
                        record.raw is not None
                        and checkpoint is None
                        and record.raw.lstrip().startswith(b"#separator")
                    ):
                        raise ZeekFollowerError(
                            f"Zeek {self.live_path.name} is TSV; enable JSON logs with "
                            "@load policy/tuning/json-logs"
                        )

                    raw_stream = self._raw_stream
                    if raw_stream is None:
                        raise ZeekFollowerError(
                            "Zeek raw descriptor is unexpectedly closed"
                        )
                    observed = os.fstat(raw_stream.fileno())
                    observed_size = (
                        stream.tell()
                        if source.compressed
                        else int(observed.st_size)
                    )
                    next_checkpoint = ZeekLogCheckpoint(
                        source_instance=self.source_instance,
                        log_name=self.log_name,
                        device=source.device,
                        inode=source.inode,
                        offset=stream.tell(),
                        file_size=max(source.size, observed_size, stream.tell()),
                    )
                    if record.digest is not None:
                        record_bytes = record.byte_count
                        record_sha256 = record.digest
                        outcome = index_conn_failure(
                            conn,
                            next_checkpoint,
                            expected_checkpoint=checkpoint,
                            record_bytes=record.byte_count,
                            record_sha256=record.digest,
                            error_code="record_too_large",
                            error=(
                                f"Zeek {self.live_path.name} record exceeded "
                                f"{MAX_CONN_RECORD_BYTES} bytes"
                            ),
                        )
                    else:
                        record_bytes = len(record.raw)
                        record_sha256 = (
                            "sha256:" + hashlib.sha256(record.raw).hexdigest()
                        )
                        outcome = self._line_indexer(
                            conn,
                            record.raw,
                            next_checkpoint,
                            expected_checkpoint=checkpoint,
                        )
                    checkpoint = replace(
                        next_checkpoint,
                        record_bytes=record_bytes,
                        record_sha256=record_sha256,
                    )
                    scanned += 1
                    indexed += int(outcome.indexed)
                    failures += int(outcome.failure_code is not None)
                    self._reset_eof()

                if scanned >= batch_limit:
                    return ZeekPollResult(scanned, indexed, failures, rotated)

                final_offset = stream.tell()
                if source.compressed:
                    final_size = final_offset
                else:
                    raw_stream = self._raw_stream
                    if raw_stream is None:
                        raise ZeekFollowerError(
                            "Zeek raw descriptor is unexpectedly closed"
                        )
                    final_size = int(os.fstat(raw_stream.fileno()).st_size)
            except ZeekFollowerError:
                raise
            except OSError as exc:
                source_kind = (
                    "compressed Zeek archive" if source.compressed else "Zeek log"
                )
                raise ZeekFollowerError(
                    f"could not read {source_kind} {source.path}: {exc}"
                ) from exc

            live = _optional_live_source(self.live_path)
            if live is None:
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if source.physical_identity == live.physical_identity:
                self._reset_eof()
                self._observed_successor = None
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if self._opened_as_live:
                live_identity = (live.device, live.inode)
                if self._observed_successor is None:
                    self._observed_successor = live_identity
                elif self._observed_successor != live_identity:
                    raise ZeekFollowerError(
                        "Zeek live log rotated again before the prior handoff completed"
                    )
            if final_offset != final_size:
                self._reset_eof()
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if not self._observe_stable_eof(source, final_offset, final_size):
                return ZeekPollResult(scanned, indexed, failures, rotated)

            if checkpoint is None:
                if final_size != 0:
                    raise ZeekFollowerError(
                        "cannot rotate an uncheckpointed non-empty Zeek source"
                    )
                self.close()
                rotated = True
                continue
            chain = _scan_rotation_chain(self.live_path, self.archive_root)
            chain_source = next(
                (
                    candidate
                    for candidate in chain
                    if candidate.physical_identity == source.physical_identity
                ),
                None,
            )
            if chain_source is not None:
                current_chain_source = _safe_source(chain_source.path)
                if (
                    current_chain_source.physical_identity
                    != chain_source.physical_identity
                ):
                    raise ZeekFollowerError(
                        "the Zeek rotation chain changed during successor "
                        "selection; the follower will not skip an archive"
                    )
                successor = self._successor(chain_source, chain)
            else:
                raise ZeekFollowerError(
                    "the retained Zeek log is missing from the "
                    "rotation chain; the follower will not skip an archive"
                )
            if successor is None:
                return ZeekPollResult(scanned, indexed, failures, rotated)
            if successor.size == 0:
                return ZeekPollResult(scanned, indexed, failures, rotated)
            successor_anchor = _successor_prefix_anchor(successor)
            if successor_anchor is None:
                return ZeekPollResult(scanned, indexed, failures, rotated)
            successor_size, prefix_bytes, prefix_sha256 = successor_anchor
            next_checkpoint = ZeekLogCheckpoint(
                source_instance=self.source_instance,
                log_name=self.log_name,
                device=successor.device,
                inode=successor.inode,
                offset=0,
                file_size=successor_size,
                prefix_bytes=prefix_bytes,
                prefix_sha256=prefix_sha256,
            )
            rotate_checkpoint(
                conn,
                next_checkpoint,
                expected_checkpoint=checkpoint,
                allow_reused_identity=(
                    (successor.device, successor.inode)
                    == (checkpoint.device, checkpoint.inode)
                    and successor.physical_identity != source.physical_identity
                ),
            )
            rotated = True
            self.close()

        return ZeekPollResult(scanned, indexed, failures, rotated)
