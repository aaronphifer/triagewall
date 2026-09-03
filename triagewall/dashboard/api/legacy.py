"""Deprecated unversioned /api/* aliases for the existing dashboard."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends, Query, Request

from triagewall.dashboard.api.auth import AuthContext, AuthState
from triagewall.dashboard.api.cache_headers import cached_json_response
from triagewall.dashboard.api import services
from triagewall.dashboard.api.v1.models import (
    FeedbackRequest,
    FeedbackResponse,
    LegacyHealthResponse,
    LegacyStatsModel,
    LegacyVerdictsResponse,
    SpcAnomaliesResponse,
    TimelineBucket,
)


def create_legacy_router(
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
) -> APIRouter:
    """Thin deprecated aliases preserving dashboard response shapes.

    These keep ``cached_json_response`` rather than the validating helper used
    by v1: their shapes are frozen until removal on 2026-12-31, and their
    filter values stay lenient so existing clients that pass an unrecognized
    value keep the historical "no filter" behaviour instead of newly failing.
    """
    router = APIRouter(tags=["legacy"], deprecated=True)
    require_read = auth.require_read
    require_write = auth.require_feedback_write

    @router.get(
        "/api/health",
        response_model=LegacyHealthResponse,
        deprecated=True,
        responses={503: {"model": LegacyHealthResponse}},
    )
    def health(request: Request):
        payload, status_code = services.compute_health(
            db_factory,
            get_db_path(),
            stale_threshold_seconds=get_stale_threshold(),
            include_storage=True,
        )
        return cached_json_response(
            request,
            payload,
            max_age=5,
            status_code=status_code,
        )

    @router.get(
        "/api/verdicts",
        response_model=LegacyVerdictsResponse,
        deprecated=True,
    )
    def list_verdicts(
        request: Request,
        verdict: str | None = None,
        signature: str | None = Query(
            default=None,
            max_length=services.MAX_SIGNATURE_SEARCH_LENGTH,
        ),
        model: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        _auth: AuthContext = Depends(require_read),
    ):
        with db_factory(readonly=True) as conn:
            rows, _next, _search_scope, _search_window = services.fetch_verdicts(
                conn,
                verdict=verdict,
                signature=signature,
                model=model,
                # This deprecated alias remains signature-only until removal;
                # expanded workbench search is a v1 contract addition.
                include_private_search=False,
                # Reachable under default unauthenticated reads, so its search
                # does the same bounded work as v1: the newest-candidate window
                # and the query-time budget. Only the work is bounded; the
                # frozen response shape, filters, and absent cursor are
                # unchanged, and an unsearched read stays outside the deadline.
                bounded_search=True,
                limit=limit,
                cursor=None,
            )
        stats_dict, _generated = services.get_cached_stats(db_factory)
        legacy_verdicts = []
        for row in rows:
            legacy_row = row_to_dict(row)
            # Zeek provenance is a v1 addition. Keep the deprecated wire shape
            # frozen even when the underlying query can see the companion row.
            legacy_row.pop("zeek_context", None)
            legacy_verdicts.append(legacy_row)
        payload = {
            "mode": get_mode(),
            "stats": LegacyStatsModel.model_validate(stats_dict).model_dump(),
            "verdicts": legacy_verdicts,
        }
        return cached_json_response(request, payload, max_age=5)

    @router.post(
        "/api/feedback/{event_id}",
        response_model=FeedbackResponse,
        deprecated=True,
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

    @router.get("/api/timeline", deprecated=True)
    def timeline(
        request: Request,
        _auth: AuthContext = Depends(require_read),
    ):
        buckets, _generated = services.get_timeline(
            db_factory,
            hours=24,
            interval="1h",
        )
        # Legacy clients expect a bare array.
        return cached_json_response(
            request,
            [TimelineBucket.model_validate(b).model_dump() for b in buckets],
            max_age=int(services.TIMELINE_TTL),
        )

    @router.get(
        "/api/spc-anomalies",
        response_model=SpcAnomaliesResponse,
        deprecated=True,
    )
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
        return cached_json_response(
            request,
            body,
            max_age=int(services.SPC_TTL),
        )

    return router
