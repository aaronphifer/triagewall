#!/usr/bin/env python3
"""
Triage dashboard backend.

MODE=local  → full data, feedback enabled
MODE=demo   → IPs masked, feedback disabled, read-only

Run:
    uvicorn triagewall.dashboard.app:app --host 0.0.0.0 --port 8084
"""
from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from triagewall.dashboard.api.auth import (
    API_KEY_HEADER_NAME,
    DASHBOARD_WRITE_COOKIE,
    AuthState,
    issue_dashboard_write_cookie,
    validate_config_write_settings,
)
from triagewall.dashboard.api.legacy import create_legacy_router
from triagewall.dashboard.api.pseudonym import (
    ENV_DASHBOARD_WRITE_SECRET,
    ENV_IP_HASH_SECRET,
    load_ip_pseudonym_secret,
)
from triagewall.dashboard.api import services
from triagewall.dashboard.api.v1.router import create_metrics_handler, create_v1_router
from triagewall.database import connect_database
from triagewall.environment import parse_boolean
from triagewall.migrations import verify_db_initialized
from triagewall.time_utils import format_utc_timestamp
from triagewall.zeek_provider import SQLiteZeekContextProvider

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_dotenv(override: bool = False) -> None:
    """Minimal `.env` loader (stdlib-only)."""
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return
    try:
        for raw_line in env_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if not key:
                continue
            if not override and key in os.environ:
                continue
            os.environ[key] = val
    except OSError:
        return


_load_dotenv(override=False)


def _dashboard_mode_from_env() -> str:
    """Resolve one shared demo setting while retaining MODE compatibility."""
    configured_mode = os.environ.get("MODE", "").strip().lower()
    if configured_mode:
        if configured_mode not in {"local", "demo"}:
            raise RuntimeError("MODE must be either 'local' or 'demo'")
        return configured_mode

    if parse_boolean(
        os.environ.get("DEMO_MODE", "false"),
        "DEMO_MODE",
    ):
        return "demo"
    return "local"


MODE = _dashboard_mode_from_env()
STALE_THRESHOLD_SECONDS = int(os.environ.get("STALE_THRESHOLD_SECONDS", "600"))
DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or "/var/lib/triagewall/triage.db"
)
ZEEK_ENRICHMENT_ENABLED = parse_boolean(
    os.environ.get("ZEEK_ENRICHMENT_ENABLED", "false"),
    "ZEEK_ENRICHMENT_ENABLED",
)
ZEEK_INDEX_PATH = Path(
    os.environ.get("ZEEK_INDEX_PATH", "/var/lib/triagewall/zeek-context.db")
)
ZEEK_SOURCE_ID = os.environ.get("ZEEK_SOURCE_ID", "zeek-local")
ZEEK_CONTEXT_PROVIDER = (
    SQLiteZeekContextProvider(ZEEK_INDEX_PATH, ZEEK_SOURCE_ID)
    if ZEEK_ENRICHMENT_ENABLED
    else None
)
STATIC_DIR = Path(__file__).parent / "static"
TRUSTED_HOSTS = {
    host.strip().lower().rstrip(".")
    for host in os.environ.get("TRUSTED_HOSTS", "localhost").split(",")
    if host.strip()
}
API_REDACT_IPS = parse_boolean(
    os.environ.get("TRIAGEWALL_API_REDACT_IPS", "false"),
    "TRIAGEWALL_API_REDACT_IPS",
)
# The dashboard write cookie is same-origin CSRF resistance for the built-in
# UI, not user authentication. Set this when the dashboard is served over
# HTTPS so the browser refuses to send the cookie over plaintext.
DASHBOARD_COOKIE_SECURE = parse_boolean(
    os.environ.get("TRIAGEWALL_DASHBOARD_COOKIE_SECURE", "false"),
    "TRIAGEWALL_DASHBOARD_COOKIE_SECURE",
)
CONFIG_WRITES_ENABLED = parse_boolean(
    os.environ.get("TRIAGEWALL_CONFIG_WRITES_ENABLED", "false"),
    "TRIAGEWALL_CONFIG_WRITES_ENABLED",
)

auth_state = AuthState()

# Validated at import time: enabling IP redaction without a usable secret would
# otherwise degrade silently to reversible hashing, so startup fails instead.
API_IP_HASH_SECRET = load_ip_pseudonym_secret(
    os.environ.get(ENV_IP_HASH_SECRET),
    redact_ips=API_REDACT_IPS,
    dashboard_write_secret=os.environ.get(ENV_DASHBOARD_WRITE_SECRET),
)

# Back-compat aliases for existing tests that reset module-level caches.
_stats_cache = services._stats_cache
_timeline_cache = services._timeline_cache
_spc_cache = services._spc_cache


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Refuse to serve from a database that the migration owner did not prepare."""
    validate_config_write_settings(
        auth_state.keys,
        writes_enabled=CONFIG_WRITES_ENABLED,
    )
    verify_db_initialized(DB_PATH)
    yield


app = FastAPI(title="Triage Dashboard", version="1.0.0", lifespan=lifespan)


def _host_is_allowed(host_header):
    """Allow localhost, IP literals, and explicitly configured DNS names."""
    if not isinstance(host_header, str) or host_header != host_header.strip():
        return False
    try:
        parsed = urlsplit(f"//{host_header}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    if not hostname:
        return False
    hostname = hostname.lower().rstrip(".")
    if hostname in TRUSTED_HOSTS:
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


@app.middleware("http")
async def enforce_trusted_host(request: Request, call_next):
    if not _host_is_allowed(request.headers.get("host", "")):
        return PlainTextResponse("Invalid host header", status_code=400)
    return await call_next(request)


@contextmanager
def db(readonly: bool = False):
    """
    Yield a SQLite connection and always close it after the request operation.
    - readonly=True → open in read-only mode for polling endpoints
    - readonly=False → standard read-write connection (used for feedback)
    """
    conn = connect_database(DB_PATH, readonly=readonly)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def mask_ip(ip):
    """Mask the last two octets of internal IPs in demo mode."""
    if not ip or MODE != "demo":
        return ip
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address in ipaddress.ip_network("10.0.0.0/8"):
        return "10.x.x.x"
    if address in ipaddress.ip_network("192.168.0.0/16"):
        return "192.168.x.x"
    return ip


def row_to_dict(row):
    d = dict(row)
    src_asset_json = d.pop("src_asset_json", None)
    dest_asset_json = d.pop("dest_asset_json", None)
    sensor_source = d.pop("sensor_source", None) or "suricata"
    sensor_instance = d.pop("sensor_instance", None)
    sensor_event_id = d.pop("sensor_event_id", None)
    sensor_agent_id = d.pop("sensor_agent_id", None)
    sensor_agent_name = d.pop("sensor_agent_name", None)
    zeek_eligibility_reason = d.pop("zeek_eligibility_reason", None)
    zeek_lookup_status = d.pop("zeek_lookup_status", None)
    zeek_source_instance = d.pop("zeek_source_instance", None)
    zeek_match_strategy = d.pop("zeek_match_strategy", None)
    zeek_record_count = d.pop("zeek_record_count", None)
    zeek_candidate_count = d.pop("zeek_candidate_count", None)
    zeek_truncated = d.pop("zeek_truncated", None)
    zeek_recorded_at = d.pop("zeek_recorded_at", None)
    zeek_context_json = d.pop("zeek_context_json", None)

    def parse_snapshot(value):
        if not isinstance(value, str):
            return None
        try:
            snapshot = json.loads(value)
        except json.JSONDecodeError:
            return None
        return snapshot if isinstance(snapshot, dict) else None

    d["asset_context"] = {
        "source": parse_snapshot(src_asset_json),
        "destination": parse_snapshot(dest_asset_json),
    }
    agent = None
    if sensor_agent_id is not None or sensor_agent_name is not None:
        agent = {"id": sensor_agent_id, "name": sensor_agent_name}
    d["sensor_context"] = {
        "source": sensor_source,
        "instance": sensor_instance,
        "event_id": sensor_event_id,
        "agent": agent,
    }
    zeek_context = None
    if zeek_eligibility_reason is not None and zeek_lookup_status is not None:
        parsed_context = parse_snapshot(zeek_context_json)
        zeek_context = {
            "eligibility_reason": zeek_eligibility_reason,
            "lookup_status": zeek_lookup_status,
            "source_instance": zeek_source_instance,
            "match_strategy": zeek_match_strategy,
            "record_count": int(zeek_record_count or 0),
            "candidate_count": int(zeek_candidate_count or 0),
            "truncated": bool(zeek_truncated),
            "recorded_at": zeek_recorded_at,
            "context": parsed_context,
        }
    d["zeek_context"] = zeek_context
    for field in ("timestamp", "processed_at", "reviewed_at"):
        if d.get(field):
            try:
                d[field] = format_utc_timestamp(d[field])
            except (TypeError, ValueError):
                d[field] = None
    if MODE == "demo":
        d["src_ip"] = mask_ip(d.get("src_ip"))
        d["dest_ip"] = mask_ip(d.get("dest_ip"))
        d["raw_alert"] = None
        d["reasoning"] = None
        d["human_notes"] = None
        d["asset_context"] = {"source": None, "destination": None}
        d["sensor_context"] = {
            "source": sensor_source,
            "instance": None,
            "event_id": None,
            "agent": None,
        }
        d["zeek_context"] = None
    elif API_REDACT_IPS:
        d["src_ip"] = services.hash_ip(d.get("src_ip"), API_IP_HASH_SECRET)
        d["dest_ip"] = services.hash_ip(d.get("dest_ip"), API_IP_HASH_SECRET)
        # These free-form channels can repeat endpoint addresses or carry
        # additional inventory addresses that cannot be pseudonymized safely
        # by changing only the structured src_ip/dest_ip fields. Fail closed:
        # retain the keyed endpoint pseudonyms, but withhold text and snapshots
        # rather than claiming an incomplete IP-redaction boundary.
        d["raw_alert"] = None
        d["reasoning"] = None
        d["human_notes"] = None
        d["asset_context"] = {"source": None, "destination": None}
        d["zeek_context"] = None
    return d


def _get_mode() -> str:
    return MODE


def _get_db_path():
    return DB_PATH


def _get_stale_threshold() -> int:
    return STALE_THRESHOLD_SECONDS


def _redact_ips() -> bool:
    return API_REDACT_IPS


def _get_ip_secret() -> bytes | None:
    return API_IP_HASH_SECRET


def _config_writes_enabled() -> bool:
    return CONFIG_WRITES_ENABLED


def _get_zeek_context_provider():
    return ZEEK_CONTEXT_PROVIDER


_router_kwargs = dict(
    auth=auth_state,
    db_factory=db,
    get_mode=_get_mode,
    get_db_path=_get_db_path,
    get_stale_threshold=_get_stale_threshold,
    row_to_dict=row_to_dict,
    mask_ip_fn=mask_ip,
    redact_ips=_redact_ips,
    get_ip_secret=_get_ip_secret,
)

app.include_router(
    create_v1_router(
        **_router_kwargs,
        config_writes_enabled=_config_writes_enabled,
        get_zeek_context_provider=_get_zeek_context_provider,
    )
)
app.include_router(create_legacy_router(**_router_kwargs))
app.add_api_route(
    "/metrics",
    create_metrics_handler(
        auth=auth_state,
        db_factory=db,
        get_db_path=_get_db_path,
        get_stale_threshold=_get_stale_threshold,
    ),
    methods=["GET"],
    tags=["ops"],
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})[
        "ApiKeyAuth"
    ] = {
        "type": "apiKey",
        "in": "header",
        "name": API_KEY_HEADER_NAME,
        "description": (
            "PBKDF2-hashed keys configured via TRIAGEWALL_API_KEYS. "
            "Scopes: read, feedback:write, config:write. Unversioned /api/* aliases are "
            "deprecated and scheduled for removal on 2026-12-31."
        ),
    }
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.get("/")
@app.head("/")
@app.get("/triage", include_in_schema=False)
@app.head("/triage", include_in_schema=False)
@app.get("/triage/{event_id}", include_in_schema=False)
@app.head("/triage/{event_id}", include_in_schema=False)
@app.get("/overview", include_in_schema=False)
@app.head("/overview", include_in_schema=False)
@app.get("/behavioral", include_in_schema=False)
@app.head("/behavioral", include_in_schema=False)
@app.get("/integrity", include_in_schema=False)
@app.head("/integrity", include_in_schema=False)
@app.get("/configuration", include_in_schema=False)
@app.head("/configuration", include_in_schema=False)
def index(event_id: int | None = None):
    response = FileResponse(STATIC_DIR / "index.html")
    # Same-origin CSRF resistance for the built-in UI, not a user login. See
    # docs/api.md: remote access still needs a VPN or an authenticated proxy.
    response.set_cookie(
        key=DASHBOARD_WRITE_COOKIE,
        value=issue_dashboard_write_cookie(auth_state.dashboard_write_secret),
        httponly=True,
        samesite="strict",
        secure=DASHBOARD_COOKIE_SECURE,
        path="/",
    )
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
