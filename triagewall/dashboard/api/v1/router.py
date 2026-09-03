"""Stable authenticated API v1 routes."""

from __future__ import annotations

import json
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from triagewall import config_repository
from triagewall.dashboard.api.auth import AuthContext, AuthState
from triagewall.dashboard.api.cache_headers import validated_json_response
from triagewall.dashboard.api import metrics as metrics_mod
from triagewall.dashboard.api import services
from triagewall.dashboard.api.v1.models import (
    ActiveConfigResponse,
    ConfigAuditResponse,
    ConfigActivationRequest,
    ConfigActivationResponse,
    ConfigDraftRequest,
    ConfigDraftResponse,
    ConfigKind,
    ConfigPreviewRequest,
    ConfigPreviewResponse,
    ConfigRevisionState,
    ConfigRevisionResponse,
    ConfigRevisionsResponse,
    ConfigSummaryResponse,
    ConfigValidationResponse,
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    InvestigationResponse,
    ModelFilter,
    ReviewFilter,
    SourceFilter,
    SpcAnomaliesResponse,
    StatsModel,
    StatsResponse,
    TimelineInterval,
    TimelineResponse,
    VerdictFilter,
    VerdictDetailResponse,
    VerdictsResponse,
    ZeekContextResponse,
)
from triagewall.time_utils import utc_now_iso
from triagewall.zeek_context import (
    ZeekLookupRequest,
    ZeekLookupResult,
    ZeekLookupStatus,
)


def create_v1_router(
    *,
    auth: AuthState,
    db_factory: Callable,
    get_mode: Callable[[], str],
    get_db_path: Callable,
    get_stale_threshold: Callable[[], int],
    row_to_dict: Callable,
    mask_ip_fn: Callable,
    redact_ips: Callable[[], bool],
    get_ip_secret: Callable[[], bytes | None] = lambda: None,
    config_writes_enabled: Callable[[], bool] = lambda: False,
    get_zeek_context_provider: Callable[[], object | None] = lambda: None,
) -> APIRouter:
    """Build the v1 router with injected app dependencies."""
    router = APIRouter(prefix="/api/v1", tags=["v1"])
    require_read = auth.require_read
    require_write = auth.require_feedback_write

    def require_config_access(
        ctx: AuthContext = Depends(auth.require_config_write),
    ) -> AuthContext:
        if get_mode() == "demo":
            raise HTTPException(
                status_code=403,
                detail="configuration access is unavailable in demo mode",
            )
        return ctx

    def require_config_mutation(
        ctx: AuthContext = Depends(require_config_access),
    ) -> AuthContext:
        if not config_writes_enabled():
            raise HTTPException(
                status_code=403,
                detail="configuration writes are disabled",
            )
        return ctx

    def request_id(request: Request) -> str | None:
        value = request.headers.get("X-Request-ID")
        if value is None:
            return None
        if (
            not value
            or len(value) > config_repository.MAX_REQUEST_ID_LENGTH
            or not all(character.isascii() and character.isprintable() for character in value)
        ):
            raise HTTPException(status_code=422, detail="invalid X-Request-ID")
        return value

    def repository_error(exc: Exception) -> HTTPException:
        if isinstance(exc, config_repository.ConfigNotFoundError):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, config_repository.ConfigConflictError):
            return HTTPException(status_code=409, detail=str(exc))
        if isinstance(exc, config_repository.ConfigIntegrityError):
            return HTTPException(
                status_code=500,
                detail="operator configuration storage is inconsistent",
            )
        return HTTPException(status_code=422, detail=str(exc))

    @router.get(
        "/health",
        response_model=HealthResponse,
        responses={503: {"model": HealthResponse}},
    )
    def health(request: Request):
        payload, status_code = services.compute_health(
            db_factory,
            get_db_path(),
            stale_threshold_seconds=get_stale_threshold(),
            include_storage=False,
        )
        return validated_json_response(
            request,
            payload,
            model=HealthResponse,
            max_age=5,
            status_code=status_code,
        )

    @router.get("/stats", response_model=StatsResponse)
    def stats(
        request: Request,
        _auth: AuthContext = Depends(require_read),
    ):
        stats_dict, generated_at = services.get_cached_stats(db_factory)
        payload = {
            "generated_at": generated_at,
            "mode": get_mode(),
            "stats": StatsModel.model_validate(stats_dict).model_dump(),
        }
        return validated_json_response(
            request,
            payload,
            model=StatsResponse,
            max_age=int(services.STATS_TTL),
        )

    @router.get("/verdicts", response_model=VerdictsResponse)
    def list_verdicts(
        request: Request,
        verdict: VerdictFilter | None = None,
        signature: str | None = Query(
            default=None,
            max_length=services.MAX_SIGNATURE_SEARCH_LENGTH,
        ),
        model: ModelFilter | None = None,
        source: SourceFilter | None = None,
        review: ReviewFilter | None = None,
        limit: int = Query(
            default=services.DEFAULT_VERDICT_LIMIT,
            ge=1,
            le=services.MAX_VERDICT_LIMIT,
        ),
        cursor: str | None = Query(
            default=None,
            max_length=services.MAX_CURSOR_LENGTH,
        ),
        _auth: AuthContext = Depends(require_read),
    ):
        with db_factory(readonly=True) as conn:
            rows, next_cursor, search_scope, search_window = services.fetch_verdicts(
                conn,
                verdict=verdict,
                signature=signature,
                model=model,
                source=source,
                review=review,
                include_private_search=(
                    get_mode() != "demo" and not redact_ips()
                ),
                limit=limit,
                cursor=cursor,
            )
        payload = {
            "generated_at": utc_now_iso(),
            "mode": get_mode(),
            "verdicts": [row_to_dict(r) for r in rows],
            "next_cursor": next_cursor,
            "search_scope": search_scope,
            "search_window": search_window,
        }
        # Rows carry review state that an operator can change at any moment, so
        # the queue is as mutable as the detail view and gets the same policy.
        # A cached list would let a stale row present a reviewed alert as
        # unreviewed and invite a second, note-less feedback write.
        return validated_json_response(
            request,
            payload,
            model=VerdictsResponse,
            max_age=0,
            no_store=True,
        )

    @router.get("/verdicts/{event_id}", response_model=VerdictDetailResponse)
    def get_verdict(
        request: Request,
        event_id: int,
        _auth: AuthContext = Depends(require_read),
    ):
        with db_factory(readonly=True) as conn:
            row = services.fetch_verdict(conn, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="event not found")
        payload = {
            "generated_at": utc_now_iso(),
            "mode": get_mode(),
            "verdict": row_to_dict(row),
        }
        # Operator feedback rewrites this row, so the detail view must never be
        # answered from a cache holding the pre-feedback body.
        return validated_json_response(
            request,
            payload,
            model=VerdictDetailResponse,
            max_age=0,
            no_store=True,
        )

    @router.get(
        "/verdicts/{event_id}/zeek-context",
        response_model=ZeekContextResponse,
    )
    def get_live_zeek_context(
        request: Request,
        event_id: int,
        _auth: AuthContext = Depends(require_read),
    ):
        """Run exact tuple and bounded UID-linked lookup at operator request."""
        if get_mode() == "demo" or redact_ips():
            raise HTTPException(
                status_code=403,
                detail="Zeek context is unavailable while event data is redacted",
            )
        provider = get_zeek_context_provider()
        if provider is None:
            raise HTTPException(
                status_code=503,
                detail="Zeek enrichment is not enabled for the dashboard",
            )
        with db_factory(readonly=True) as conn:
            row = services.fetch_verdict(conn, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="event not found")
        stored = row_to_dict(row).get("zeek_context")
        if stored is None:
            raise HTTPException(
                status_code=409,
                detail="this event was not evaluated for Zeek enrichment",
            )
        if stored["eligibility_reason"] != "eligible":
            raise HTTPException(
                status_code=409,
                detail="this event was not eligible for a Zeek lookup",
            )
        try:
            lookup_request = ZeekLookupRequest(
                alert_timestamp=row["timestamp"],
                src_ip=row["src_ip"],
                src_port=row["src_port"],
                dest_ip=row["dest_ip"],
                dest_port=row["dest_port"],
                proto=row["proto"],
            )
            deep_lookup = getattr(provider, "lookup_deep", None)
            raw_result = (
                deep_lookup(lookup_request)
                if callable(deep_lookup)
                else provider.lookup(lookup_request)
            )
        except Exception:
            result = ZeekLookupResult(status=ZeekLookupStatus.UNAVAILABLE)
        else:
            try:
                raw_status = getattr(raw_result, "status", None)
                result = ZeekLookupResult(
                    status=ZeekLookupStatus(
                        getattr(raw_status, "value", raw_status)
                    ),
                    context_json=getattr(raw_result, "context_json", None),
                    source_instance=getattr(raw_result, "source_instance", None),
                    match_strategy=getattr(raw_result, "match_strategy", None),
                    record_count=getattr(raw_result, "record_count", 0),
                    candidate_count=getattr(raw_result, "candidate_count", 0),
                    truncated=getattr(raw_result, "truncated", False),
                )
            except Exception:
                result = ZeekLookupResult(
                    status=ZeekLookupStatus.INVALID_RESPONSE
                )
        live = {
            "eligibility_reason": "eligible",
            "lookup_status": result.status.value,
            "source_instance": result.source_instance,
            "match_strategy": result.match_strategy,
            "record_count": result.record_count,
            "candidate_count": result.candidate_count,
            "truncated": result.truncated,
            "recorded_at": utc_now_iso(),
            "context": (
                json.loads(result.context_json)
                if result.context_json is not None
                else None
            ),
        }
        payload = {
            "generated_at": utc_now_iso(),
            "mode": "local",
            "event_id": event_id,
            "stored": stored,
            "live": live,
        }
        return validated_json_response(
            request,
            payload,
            model=ZeekContextResponse,
            max_age=0,
            no_store=True,
        )

    @router.get(
        "/verdicts/{event_id}/investigation",
        response_model=InvestigationResponse,
    )
    def get_investigation(
        request: Request,
        event_id: int,
        hours: int = Query(
            default=services.DEFAULT_INVESTIGATION_WINDOW_HOURS,
            ge=1,
            le=services.MAX_INVESTIGATION_WINDOW_HOURS,
        ),
        verdict: VerdictFilter | None = None,
        signature: str | None = Query(
            default=None,
            max_length=services.MAX_SIGNATURE_SEARCH_LENGTH,
        ),
        model: ModelFilter | None = None,
        source: SourceFilter | None = None,
        review: ReviewFilter | None = None,
        search_window: str | None = Query(
            default=None,
            max_length=services.MAX_CURSOR_LENGTH,
        ),
        _auth: AuthContext = Depends(require_read),
    ):
        """Bounded recurrence, related activity and queue-aware neighbours.

        The filter parameters are the ones /verdicts accepts, so previous and
        next stay inside the queue the analyst was working from.
        """
        with db_factory(readonly=True) as conn:
            payload = services.fetch_investigation(
                conn,
                event_id,
                hours=hours,
                mode=get_mode(),
                mask_ip_fn=mask_ip_fn,
                redact_ips=redact_ips(),
                ip_secret=get_ip_secret(),
                verdict=verdict,
                signature=signature,
                model=model,
                source=source,
                review=review,
                search_window=(
                    services.decode_search_window(search_window)
                    if search_window is not None
                    else None
                ),
                include_private_search=(
                    get_mode() != "demo" and not redact_ips()
                ),
            )
        if payload is None:
            raise HTTPException(status_code=404, detail="event not found")
        payload["mode"] = get_mode()
        # Recurrence and verdict distribution move as soon as feedback lands,
        # so this shares the detail view's no-store policy.
        return validated_json_response(
            request,
            payload,
            model=InvestigationResponse,
            max_age=0,
            no_store=True,
        )

    @router.post(
        "/feedback/{event_id}",
        response_model=FeedbackResponse,
    )
    def feedback(
        event_id: int,
        body: FeedbackRequest,
        _auth: AuthContext = Depends(require_write),
    ):
        return services.submit_feedback(
            db_factory,
            mode=get_mode(),
            event_id=event_id,
            human_verdict=body.human_verdict,
            notes=body.notes,
        )

    @router.get("/timeline", response_model=TimelineResponse)
    def timeline(
        request: Request,
        hours: int = Query(default=24, ge=1, le=services.MAX_TIMELINE_HOURS),
        interval: TimelineInterval = Query(default="1h"),
        _auth: AuthContext = Depends(require_read),
    ):
        buckets, generated_at = services.get_timeline(
            db_factory,
            hours=hours,
            interval=interval,
        )
        payload = {
            "generated_at": generated_at,
            "hours": hours,
            "interval": interval,
            "buckets": buckets,
        }
        return validated_json_response(
            request,
            payload,
            model=TimelineResponse,
            max_age=int(services.TIMELINE_TTL),
        )

    @router.get("/spc-anomalies", response_model=SpcAnomaliesResponse)
    def spc_anomalies(
        request: Request,
        _auth: AuthContext = Depends(require_read),
    ):
        payload, generated_at = services.get_spc_anomalies(
            db_factory,
            mode=get_mode(),
            mask_ip_fn=mask_ip_fn,
            redact_ips=redact_ips(),
            ip_secret=get_ip_secret(),
        )
        body = {"generated_at": generated_at, **payload}
        return validated_json_response(
            request,
            body,
            model=SpcAnomaliesResponse,
            max_age=int(services.SPC_TTL),
        )

    @router.get("/config", response_model=ConfigSummaryResponse)
    def config_summary(
        request: Request,
        _auth: AuthContext = Depends(require_config_access),
    ):
        try:
            with db_factory(readonly=True) as conn:
                payload = config_repository.get_config_summary(
                    conn,
                    writes_enabled=config_writes_enabled(),
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigSummaryResponse,
            max_age=0,
            no_store=True,
        )

    @router.get("/config/audit", response_model=ConfigAuditResponse)
    def config_audit(
        request: Request,
        limit: int = Query(
            default=config_repository.DEFAULT_AUDIT_LIMIT,
            ge=1,
            le=config_repository.MAX_AUDIT_LIMIT,
        ),
        cursor: str | None = Query(
            default=None,
            max_length=config_repository.MAX_CONFIG_CURSOR_LENGTH,
        ),
        kind: ConfigKind | None = None,
        _auth: AuthContext = Depends(require_config_access),
    ):
        try:
            with db_factory(readonly=True) as conn:
                payload = config_repository.list_audit(
                    conn,
                    limit=limit,
                    cursor=cursor,
                    kind=kind,
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigAuditResponse,
            max_age=0,
            no_store=True,
        )

    @router.get("/config/{kind}", response_model=ActiveConfigResponse)
    def active_config(
        request: Request,
        kind: ConfigKind,
        _auth: AuthContext = Depends(require_config_access),
    ):
        try:
            with db_factory(readonly=True) as conn:
                payload = config_repository.get_active_config(conn, kind)
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ActiveConfigResponse,
            max_age=0,
            no_store=True,
        )

    @router.get(
        "/config/{kind}/revisions",
        response_model=ConfigRevisionsResponse,
    )
    def config_revisions(
        request: Request,
        kind: ConfigKind,
        limit: int = Query(
            default=config_repository.DEFAULT_REVISION_LIMIT,
            ge=1,
            le=config_repository.MAX_REVISION_LIMIT,
        ),
        cursor: str | None = Query(
            default=None,
            max_length=config_repository.MAX_CONFIG_CURSOR_LENGTH,
        ),
        state: ConfigRevisionState | None = None,
        _auth: AuthContext = Depends(require_config_access),
    ):
        try:
            with db_factory(readonly=True) as conn:
                payload = config_repository.list_revisions(
                    conn,
                    kind=kind,
                    limit=limit,
                    cursor=cursor,
                    state=state,
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigRevisionsResponse,
            max_age=0,
            no_store=True,
        )

    @router.get(
        "/config/{kind}/revisions/{revision_id}",
        response_model=ConfigRevisionResponse,
    )
    def config_revision(
        request: Request,
        kind: ConfigKind,
        revision_id: int,
        _auth: AuthContext = Depends(require_config_access),
    ):
        try:
            with db_factory(readonly=True) as conn:
                payload = config_repository.get_config_revision(
                    conn,
                    kind=kind,
                    revision_id=revision_id,
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigRevisionResponse,
            max_age=0,
            no_store=True,
        )

    @router.post(
        "/config/{kind}/drafts",
        response_model=ConfigDraftResponse,
        status_code=201,
        responses={200: {"model": ConfigDraftResponse}},
    )
    def create_config_draft(
        request: Request,
        kind: ConfigKind,
        body: ConfigDraftRequest,
        auth_ctx: AuthContext = Depends(require_config_mutation),
    ):
        try:
            with db_factory() as conn:
                payload = config_repository.create_draft(
                    conn,
                    kind=kind,
                    document=body.document,
                    parent_revision_id=body.parent_revision_id,
                    expected_generation=body.expected_generation,
                    note=body.note,
                    actor=auth_ctx.principal,
                    auth_via=auth_ctx.via,
                    request_id=request_id(request),
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigDraftResponse,
            max_age=0,
            # A resumed candidate already existed; only a new row is a 201.
            status_code=200 if payload.get("resumed") else 201,
            no_store=True,
        )

    @router.post(
        "/config/{kind}/drafts/{draft_id}/validate",
        response_model=ConfigValidationResponse,
    )
    def validate_config_draft(
        request: Request,
        kind: ConfigKind,
        draft_id: int,
        auth_ctx: AuthContext = Depends(require_config_mutation),
    ):
        try:
            with db_factory() as conn:
                payload = config_repository.validate_draft(
                    conn,
                    kind=kind,
                    draft_id=draft_id,
                    actor=auth_ctx.principal,
                    auth_via=auth_ctx.via,
                    request_id=request_id(request),
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigValidationResponse,
            max_age=0,
            no_store=True,
        )

    @router.post(
        "/config/{kind}/drafts/{draft_id}/preview",
        response_model=ConfigPreviewResponse,
    )
    def preview_config_draft(
        request: Request,
        kind: ConfigKind,
        draft_id: int,
        body: ConfigPreviewRequest,
        auth_ctx: AuthContext = Depends(require_config_mutation),
    ):
        try:
            with db_factory() as conn:
                payload = config_repository.preview_draft(
                    conn,
                    kind=kind,
                    draft_id=draft_id,
                    expected_generation=body.expected_generation,
                    hours=body.hours,
                    candidate_limit=body.candidate_limit,
                    actor=auth_ctx.principal,
                    auth_via=auth_ctx.via,
                    request_id=request_id(request),
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigPreviewResponse,
            max_age=0,
            no_store=True,
        )

    @router.post(
        "/config/{kind}/drafts/{draft_id}/activate",
        response_model=ConfigActivationResponse,
    )
    def activate_config_draft(
        request: Request,
        kind: ConfigKind,
        draft_id: int,
        body: ConfigActivationRequest,
        auth_ctx: AuthContext = Depends(require_config_mutation),
    ):
        try:
            with db_factory() as conn:
                payload = config_repository.activate_draft(
                    conn,
                    kind=kind,
                    draft_id=draft_id,
                    expected_generation=body.expected_generation,
                    acknowledge_broad_rules=body.acknowledge_broad_rules,
                    acknowledge_shipped_base_change=(
                        body.acknowledge_shipped_base_change
                    ),
                    acknowledge_incomplete_asset_preview=(
                        body.acknowledge_incomplete_asset_preview
                    ),
                    actor=auth_ctx.principal,
                    auth_via=auth_ctx.via,
                    request_id=request_id(request),
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigActivationResponse,
            max_age=0,
            no_store=True,
        )

    @router.post(
        "/config/{kind}/revisions/{revision_id}/rollback",
        response_model=ConfigActivationResponse,
    )
    def rollback_config_revision(
        request: Request,
        kind: ConfigKind,
        revision_id: int,
        body: ConfigActivationRequest,
        auth_ctx: AuthContext = Depends(require_config_mutation),
    ):
        try:
            with db_factory() as conn:
                payload = config_repository.rollback_revision(
                    conn,
                    kind=kind,
                    revision_id=revision_id,
                    expected_generation=body.expected_generation,
                    acknowledge_broad_rules=body.acknowledge_broad_rules,
                    acknowledge_shipped_base_change=(
                        body.acknowledge_shipped_base_change
                    ),
                    acknowledge_incomplete_asset_preview=(
                        body.acknowledge_incomplete_asset_preview
                    ),
                    actor=auth_ctx.principal,
                    auth_via=auth_ctx.via,
                    request_id=request_id(request),
                )
        except config_repository.ConfigRepositoryError as exc:
            raise repository_error(exc) from exc
        return validated_json_response(
            request,
            payload,
            model=ConfigActivationResponse,
            max_age=0,
            no_store=True,
        )

    return router


def create_metrics_handler(
    *,
    auth: AuthState,
    db_factory: Callable,
    get_db_path: Callable,
    get_stale_threshold: Callable[[], int],
):
    """Return a /metrics endpoint handler."""

    def metrics(
        _auth: AuthContext = Depends(auth.require_read),
    ):
        stats_dict, _ = services.get_cached_stats(db_factory)
        health_payload, _ = services.compute_health(
            db_factory,
            get_db_path(),
            stale_threshold_seconds=get_stale_threshold(),
            include_storage=False,
        )
        body = metrics_mod.metrics_from_stats(
            stats_dict,
            last_alert_age_seconds=health_payload["last_alert_age_seconds"],
        )
        return PlainTextResponse(
            body,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return metrics
