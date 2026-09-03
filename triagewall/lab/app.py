"""Authenticated standalone HTTP application for TriageWall Lab."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from triagewall.environment import parse_boolean
from triagewall.event_bundle import MAX_BUNDLE_BYTES
from triagewall.lab.auth import (
    LAB_CSRF_HEADER,
    LAB_SESSION_COOKIE,
    LabAuthSettings,
    LabAuthState,
    LabLoginThrottle,
)
from triagewall.lab.jobs import LabJobError, LabJobRepository
from triagewall.lab.store import LabStore, LabStoreError
from triagewall.lab_contracts import (
    CANDIDATE_SCHEMA,
    EXPERIMENT_SCHEMA,
    MAX_LAB_CONTRACT_BYTES,
    PROMOTION_REPORT_SCHEMA,
)


STATIC_DIR = Path(__file__).parent / "static"
MAX_LOGIN_BODY_BYTES = 4 * 1024
MAX_CONTROL_BODY_BYTES = 1024
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _host_allowed(host_header: str | None, trusted_hosts: frozenset[str]) -> bool:
    if not isinstance(host_header, str) or host_header != host_header.strip():
        return False
    try:
        parsed = urlsplit(f"//{host_header}")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        not hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    normalized = hostname.lower().rstrip(".")
    if normalized in trusted_hosts:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


async def _bounded_body(request: Request, maximum: int) -> bytes:
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > maximum:
                raise HTTPException(status_code=413, detail="request body is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid content length") from exc
    chunks = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > maximum:
            raise HTTPException(status_code=413, detail="request body is too large")
        chunks.append(chunk)
    return b"".join(chunks)


def settings_from_env() -> tuple[LabAuthSettings, Path, frozenset[str], int, int, int]:
    auth = LabAuthSettings(
        operator_name=os.environ.get("TRIAGEWALL_LAB_OPERATOR", "").strip(),
        api_key_hash=os.environ.get("TRIAGEWALL_LAB_API_KEY_HASH", "").strip(),
        session_secret=os.environ.get("TRIAGEWALL_LAB_SESSION_SECRET", "").strip(),
        cookie_secure=parse_boolean(
            os.environ.get("TRIAGEWALL_LAB_COOKIE_SECURE", "false"),
            "TRIAGEWALL_LAB_COOKIE_SECURE",
        ),
        session_ttl_seconds=int(
            os.environ.get("TRIAGEWALL_LAB_SESSION_TTL_SECONDS", "28800")
        ),
    )
    root = Path(os.environ.get("TRIAGEWALL_LAB_DATA_DIR", "/var/lib/triagewall-lab"))
    hosts = frozenset(
        value.strip().lower().rstrip(".")
        for value in os.environ.get("TRIAGEWALL_LAB_TRUSTED_HOSTS", "localhost").split(",")
        if value.strip()
    )
    quota = int(os.environ.get("TRIAGEWALL_LAB_STORAGE_QUOTA_BYTES", str(10 * 1024**3)))
    pending = int(os.environ.get("TRIAGEWALL_LAB_MAX_PENDING_JOBS", "4"))
    results = int(os.environ.get("TRIAGEWALL_LAB_MAX_RESULTS_PER_JOB", "1000"))
    if not 64 * 1024**2 <= quota <= 10 * 1024**4:
        raise ValueError("TRIAGEWALL_LAB_STORAGE_QUOTA_BYTES is out of range")
    if not 1 <= pending <= 100:
        raise ValueError("TRIAGEWALL_LAB_MAX_PENDING_JOBS is out of range")
    if not 1 <= results <= 60_000:
        raise ValueError("TRIAGEWALL_LAB_MAX_RESULTS_PER_JOB is out of range")
    return auth, root, hosts, quota, pending, results


def create_app(
    *,
    auth_settings: LabAuthSettings | None = None,
    data_root: Path | None = None,
    trusted_hosts: frozenset[str] | None = None,
    storage_quota_bytes: int | None = None,
    max_pending_jobs: int | None = None,
    max_results_per_job: int | None = None,
) -> FastAPI:
    if any(
        value is None
        for value in (
            auth_settings,
            data_root,
            trusted_hosts,
            storage_quota_bytes,
            max_pending_jobs,
            max_results_per_job,
        )
    ):
        env_auth, env_root, env_hosts, env_quota, env_pending, env_results = settings_from_env()
        auth_settings = auth_settings or env_auth
        data_root = data_root or env_root
        trusted_hosts = trusted_hosts or env_hosts
        storage_quota_bytes = storage_quota_bytes or env_quota
        max_pending_jobs = max_pending_jobs or env_pending
        max_results_per_job = max_results_per_job or env_results
    auth = LabAuthState(auth_settings)
    login_throttle = LabLoginThrottle()
    store = LabStore(data_root, quota_bytes=storage_quota_bytes)
    jobs = LabJobRepository(data_root / "lab-jobs.db", max_pending_jobs=max_pending_jobs)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        store.initialize()
        jobs.initialize()
        yield

    app = FastAPI(
        title="TriageWall Lab",
        version="0.1.0-private",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.lab_auth = auth
    app.state.lab_store = store
    app.state.lab_jobs = jobs

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        if not _host_allowed(request.headers.get("host"), trusted_hosts):
            return PlainTextResponse("Invalid host header", status_code=400)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        return response

    def require_session(request: Request) -> None:
        if not auth.verify_session(request.cookies.get(LAB_SESSION_COOKIE)):
            raise HTTPException(status_code=401, detail="Lab login required")

    def require_mutation(request: Request) -> None:
        require_session(request)
        if request.headers.get(LAB_CSRF_HEADER) != "1":
            raise HTTPException(status_code=403, detail="Lab request header required")

    async def exact_confirmation(request: Request, field: str) -> None:
        try:
            def pairs(items):
                value = {}
                for name, item in items:
                    if name in value:
                        raise ValueError("duplicate control field")
                    value[name] = item
                return value

            def reject_constant(_value):
                raise ValueError("non-finite control value")

            value = json.loads(
                await _bounded_body(request, MAX_CONTROL_BODY_BYTES),
                object_pairs_hook=pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail="invalid Lab confirmation") from exc
        if value != {field: True}:
            raise HTTPException(status_code=422, detail=f"{field} must be exactly true")

    @app.post("/api/v1/session")
    async def login(request: Request):
        payload = await _bounded_body(request, MAX_LOGIN_BODY_BYTES)
        remote = request.client.host if request.client is not None else "unknown"
        if not login_throttle.allowed(remote):
            raise HTTPException(
                status_code=429,
                detail="too many invalid Lab login attempts",
                headers={"Retry-After": "60"},
            )
        try:
            def pairs(items):
                value = {}
                for name, item in items:
                    if name in value:
                        raise ValueError("duplicate login field")
                    value[name] = item
                return value

            def reject_constant(_value):
                raise ValueError("non-finite login value")

            value = json.loads(
                payload,
                object_pairs_hook=pairs,
                parse_constant=reject_constant,
            )
            key = (
                value.get("api_key")
                if isinstance(value, dict) and set(value) == {"api_key"}
                else None
            )
        except (UnicodeDecodeError, ValueError):
            key = None
        if not auth.verify_api_key(key):
            login_throttle.record_failure(remote)
            raise HTTPException(status_code=401, detail="invalid Lab credentials")
        login_throttle.clear(remote)
        response = JSONResponse(
            {"authenticated": True, "operator": auth.settings.operator_name}
        )
        response.set_cookie(
            LAB_SESSION_COOKIE,
            auth.issue_session(),
            httponly=True,
            secure=auth.settings.cookie_secure,
            samesite="strict",
            max_age=auth.settings.session_ttl_seconds,
            path="/",
        )
        return response

    @app.delete("/api/v1/session")
    async def logout(request: Request):
        require_mutation(request)
        auth.revoke_session(request.cookies.get(LAB_SESSION_COOKIE))
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(LAB_SESSION_COOKIE, path="/")
        return response

    @app.get("/api/v1/session")
    async def session(request: Request):
        require_session(request)
        return {"authenticated": True, "operator": auth.settings.operator_name}

    @app.get("/api/v1/status")
    async def status(request: Request):
        require_session(request)
        job_items = jobs.list_jobs(limit=500)
        return {
            "isolation": "lab-only",
            "runner": "dedicated-worker",
            "queued_jobs": sum(item["state"] == "queued" for item in job_items),
            "running_jobs": sum(item["state"] == "running" for item in job_items),
            **store.status(),
        }

    @app.get("/api/v1/bundles")
    async def bundles(request: Request):
        require_session(request)
        return {"items": store.list_bundles()}

    @app.post("/api/v1/bundles")
    async def import_bundle(request: Request):
        require_mutation(request)
        try:
            return store.import_bundle(await _bounded_body(request, MAX_BUNDLE_BYTES))
        except (LabStoreError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from exc

    @app.get("/api/v1/candidates")
    async def candidates(request: Request):
        require_session(request)
        return {"items": store.list_candidates()}

    @app.post("/api/v1/candidates")
    async def import_candidate(request: Request):
        require_mutation(request)
        try:
            return store.import_contract(
                CANDIDATE_SCHEMA,
                await _bounded_body(request, MAX_LAB_CONTRACT_BYTES),
            )
        except (LabStoreError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from exc

    @app.get("/api/v1/experiments")
    async def experiments(request: Request):
        require_session(request)
        return {"items": store.list_experiments()}

    @app.post("/api/v1/experiments")
    async def import_experiment(request: Request):
        require_mutation(request)
        try:
            return store.import_contract(
                EXPERIMENT_SCHEMA,
                await _bounded_body(request, MAX_LAB_CONTRACT_BYTES),
            )
        except (LabStoreError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from exc

    @app.get("/api/v1/jobs")
    async def list_jobs(request: Request, limit: int = 100):
        require_session(request)
        return {"items": jobs.list_jobs(limit=limit)}

    @app.post("/api/v1/experiments/{digest_hex}/runs", status_code=202)
    async def start_run(digest_hex: str, request: Request):
        require_mutation(request)
        await exact_confirmation(request, "confirm_experimental")
        if _DIGEST_HEX_RE.fullmatch(digest_hex) is None:
            raise HTTPException(status_code=404, detail="unknown Lab experiment")
        try:
            experiment = store.load_document("experiments", "sha256:" + digest_hex)
            bundle = store.load_document("bundles", experiment["bundle"]["sha256"])
            count = (
                len(experiment["event_ids"] or bundle["events"])
                * len(experiment["evidence_conditions"])
                * experiment["repetitions"]
            )
            if count > max_results_per_job:
                raise LabStoreError("experiment exceeds the configured result limit")
            return jobs.enqueue(
                experiment={
                    "id": experiment["experiment_id"],
                    "sha256": experiment["content_sha256"],
                },
                requested_by=auth.settings.operator_name,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="unknown Lab experiment") from exc
        except LabJobError as exc:
            raise HTTPException(status_code=409, detail=str(exc)[:300]) from exc
        except (LabStoreError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from exc

    @app.post("/api/v1/jobs/{job_id}/cancel")
    async def cancel_job(job_id: str, request: Request):
        require_mutation(request)
        await exact_confirmation(request, "confirm_cancel")
        try:
            return jobs.cancel(job_id)
        except LabJobError as exc:
            raise HTTPException(status_code=409, detail=str(exc)[:300]) from exc

    @app.get("/api/v1/results")
    async def results(request: Request, limit: int = 200):
        require_session(request)
        return {"items": store.list_results(limit=limit)}

    @app.get("/api/v1/reports")
    async def reports(request: Request):
        require_session(request)
        return {"items": store.list_reports()}

    @app.post("/api/v1/reports")
    async def import_report(request: Request):
        require_mutation(request)
        try:
            return store.import_contract(
                PROMOTION_REPORT_SCHEMA,
                await _bounded_body(request, MAX_LAB_CONTRACT_BYTES),
            )
        except (LabStoreError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from exc

    @app.get("/")
    @app.head("/")
    @app.get("/bundles", include_in_schema=False)
    @app.head("/bundles", include_in_schema=False)
    @app.get("/candidates", include_in_schema=False)
    @app.head("/candidates", include_in_schema=False)
    @app.get("/experiments", include_in_schema=False)
    @app.head("/experiments", include_in_schema=False)
    @app.get("/results", include_in_schema=False)
    @app.head("/results", include_in_schema=False)
    @app.get("/reports", include_in_schema=False)
    @app.head("/reports", include_in_schema=False)
    async def index(view: str | None = None):
        del view
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
