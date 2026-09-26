"""Authentication primitives for the standalone Lab service."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass


LAB_SESSION_COOKIE = "tw_lab_session"
LAB_CSRF_HEADER = "X-TriageWall-Lab-Request"
_PBKDF2_PREFIX = "pbkdf2_sha256$"
_DEFAULT_ITERATIONS = 210_000


class LabAuthError(ValueError):
    """Raised for invalid Lab authentication configuration."""


def hash_lab_api_key(
    plaintext: str,
    *,
    iterations: int = _DEFAULT_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    if not isinstance(plaintext, str) or len(plaintext) < 24:
        raise LabAuthError("Lab API key must contain at least 24 characters")
    if iterations < 100_000:
        raise LabAuthError("PBKDF2 iterations must be at least 100000")
    salt_bytes = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", plaintext.encode("utf-8"), salt_bytes, iterations
    ).hex()
    return f"{_PBKDF2_PREFIX}{iterations}${salt_bytes.hex()}${digest}"


def _parse_hash(value: str) -> tuple[int, bytes, str]:
    parts = value.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        raise LabAuthError("Lab API key hash must use pbkdf2_sha256")
    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        digest = bytes.fromhex(parts[3])
    except ValueError as exc:
        raise LabAuthError("Lab API key hash is malformed") from exc
    if iterations < 100_000 or len(salt) < 16 or len(digest) != 32:
        raise LabAuthError("Lab API key hash parameters are invalid")
    return iterations, salt, digest.hex()


@dataclass(frozen=True)
class LabAuthSettings:
    operator_name: str
    api_key_hash: str
    session_secret: str
    cookie_secure: bool = False
    session_ttl_seconds: int = 8 * 60 * 60

    def validate(self) -> "LabAuthSettings":
        if not self.operator_name or len(self.operator_name) > 128:
            raise LabAuthError("Lab operator name is required and must be bounded")
        _parse_hash(self.api_key_hash)
        if len(self.session_secret) < 32:
            raise LabAuthError("Lab session secret must contain at least 32 characters")
        if not 300 <= self.session_ttl_seconds <= 24 * 60 * 60:
            raise LabAuthError("Lab session TTL must be between 300 and 86400 seconds")
        return self


class LabAuthState:
    def __init__(self, settings: LabAuthSettings) -> None:
        self.settings = settings.validate()
        self._sessions: OrderedDict[str, None] = OrderedDict()
        self._session_lock = threading.Lock()

    def verify_api_key(self, plaintext: str | None) -> bool:
        if not plaintext or not isinstance(plaintext, str):
            return False
        iterations, salt, expected = _parse_hash(self.settings.api_key_hash)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", plaintext.encode("utf-8"), salt, iterations
        ).hex()
        return hmac.compare_digest(expected, candidate)

    def issue_session(self, *, now: int | None = None) -> str:
        issued = int(time.time() if now is None else now)
        nonce = secrets.token_hex(16)
        body = f"v1.{issued}.{nonce}"
        signature = hmac.new(
            self.settings.session_secret.encode("utf-8"),
            body.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        token = f"{body}.{signature}"
        identity = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._session_lock:
            self._sessions[identity] = None
            self._sessions.move_to_end(identity)
            while len(self._sessions) > 32:
                self._sessions.popitem(last=False)
        return token

    def verify_session(self, token: str | None, *, now: int | None = None) -> bool:
        if not token or not isinstance(token, str):
            return False
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "v1":
            return False
        try:
            issued = int(parts[1])
        except ValueError:
            return False
        current = int(time.time() if now is None else now)
        if issued > current + 60 or current - issued > self.settings.session_ttl_seconds:
            return False
        body = ".".join(parts[:3])
        expected = hmac.new(
            self.settings.session_secret.encode("utf-8"),
            body.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, parts[3]):
            return False
        identity = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._session_lock:
            return identity in self._sessions

    def revoke_session(self, token: str | None) -> None:
        if not token or not isinstance(token, str):
            return
        identity = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._session_lock:
            self._sessions.pop(identity, None)


class LabLoginThrottle:
    """Small in-process limiter for the single-operator local login boundary."""

    def __init__(self, *, maximum: int = 5, window_seconds: int = 60) -> None:
        self.maximum = maximum
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> deque[float]:
        attempts = self._attempts.setdefault(key, deque())
        cutoff = now - self.window_seconds
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        return attempts

    def allowed(self, key: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            return len(self._trim(key, current)) < self.maximum

    def record_failure(self, key: str, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        with self._lock:
            if len(self._attempts) >= 1_024 and key not in self._attempts:
                oldest = next(iter(self._attempts))
                self._attempts.pop(oldest, None)
            self._trim(key, current).append(current)

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
