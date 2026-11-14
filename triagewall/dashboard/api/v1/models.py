"""Pydantic models for the Triagewall API v1 contract."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from triagewall import config_repository
from triagewall.config_repository import MAX_NOTE_LENGTH
from triagewall.dashboard.api.services import MAX_FEEDBACK_NOTES_LENGTH

# Typed filter vocabularies. Declaring them here keeps the OpenAPI schema, the
# route signatures and the tests in agreement, and makes an unknown value a 422
# rather than a filter that silently does nothing.
VerdictFilter = Literal["real", "false_positive", "uncertain"]
ModelFilter = Literal["llm", "prefilter"]
SourceFilter = Literal["suricata", "wazuh"]
ReviewFilter = Literal["unreviewed", "agreed", "corrected"]
TimelineInterval = Literal["1h"]
ConfigKind = Literal["prefilter_policy", "asset_inventory"]
ConfigRevisionState = Literal[
    "draft", "validated", "active", "superseded", "rejected"
]


class StatsModel(BaseModel):
    """Rolling 24h counters plus lifetime total."""

    model_config = ConfigDict(extra="forbid")

    total: int
    real: int
    real_: int = Field(
        description="Deprecated alias for real; removed after 2026-12-31."
    )
    fp: int
    unc: int
    reviewed: int
    agreed: int
    disagreed: int
    prefilter_count: int
    llm_count: int
    today_total: int
    today_prefilter: int
    today_llm: int
    model_real_count: int
    model_fp_count: int
    model_uncertain_count: int
    unreviewed_model_count: int


class StatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local", "demo"]
    stats: StatsModel


class LegacyStatsModel(BaseModel):
    """Frozen counter shape used by the deprecated combined endpoint."""

    # New internal/v1 counters are intentionally ignored so this deprecated
    # response remains byte-shape compatible until its removal date.
    model_config = ConfigDict(extra="ignore")

    total: int
    real: int
    real_: int
    fp: int
    unc: int
    reviewed: int
    agreed: int
    disagreed: int
    prefilter_count: int
    llm_count: int
    today_total: int
    today_prefilter: int
    today_llm: int


class AgentContext(BaseModel):
    """Sensor agent identity. Fixed shape; not an operator-extensible bag."""

    model_config = ConfigDict(extra="forbid")

    id: Any = None
    name: Any = None


class SensorContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str | None = None
    instance: str | None = None
    event_id: str | None = None
    agent: AgentContext | None = None


class AssetContext(BaseModel):
    """Two-sided asset snapshot.

    The wrapper is a fixed two-key structure, but ``source`` and
    ``destination`` stay free-form dictionaries on purpose: their contents come
    from the operator's own asset inventory, so enumerating them here would
    invent a schema Triagewall does not define.
    """

    model_config = ConfigDict(extra="forbid")

    source: dict[str, Any] | None = None
    destination: dict[str, Any] | None = None


class ZeekContext(BaseModel):
    """Bounded enrichment provenance; full context appears on detail only."""

    model_config = ConfigDict(extra="forbid")

    eligibility_reason: Literal[
        "eligible",
        "prefilter_resolved",
        "unsupported_source",
        "missing_endpoint",
        "unsupported_protocol",
        "missing_port",
    ]
    lookup_status: Literal[
        "disabled",
        "matched",
        "no_match",
        "ambiguous",
        "unavailable",
        "invalid_response",
    ]
    source_instance: str | None = None
    match_strategy: str | None = None
    record_count: int = Field(ge=0, le=32, strict=True)
    candidate_count: int = Field(ge=0, le=33, strict=True)
    truncated: bool
    recorded_at: str
    context: dict[str, Any] | None = None


class VerdictRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    timestamp: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    signature_id: int | None = None
    signature: str | None = None
    category: str | None = None
    severity: int | None = None
    verdict: str | None = None
    confidence: float | None = None
    reasoning: str | None = None
    model_used: str | None = None
    processed_at: str | None = None
    human_verdict: str | None = None
    human_notes: str | None = None
    agreed: int | None = None
    reviewed_at: str | None = None
    asset_context: AssetContext | None = None
    sensor_context: SensorContext | None = None
    zeek_context: ZeekContext | None = None
    raw_alert: str | None = None


class QueueSearchScope(BaseModel):
    """The newest retained-event window examined by a queue search."""

    model_config = ConfigDict(extra="forbid")

    candidate_limit: int = Field(gt=0, strict=True)
    candidates_in_scope: int = Field(ge=0, strict=True)
    truncated: bool


class VerdictsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local", "demo"]
    verdicts: list[VerdictRow]
    next_cursor: str | None = None
    search_scope: QueueSearchScope | None = None
    search_window: str | None = None


class VerdictDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local", "demo"]
    verdict: VerdictRow


class ZeekContextResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local"]
    event_id: int
    stored: ZeekContext
    live: ZeekContext


RelationshipKind = Literal["same_rule", "same_source_ip", "same_destination_ip"]


class RelatedAlert(BaseModel):
    """A slim row shown inside a related-activity group."""

    model_config = ConfigDict(extra="forbid")

    id: int
    timestamp: str | None = None
    processed_at: str | None = None
    signature_id: int | None = None
    signature: str | None = None
    verdict: str | None = None
    confidence: float | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    source_type: str | None = None
    relationship: RelationshipKind


class RelatedGroup(BaseModel):
    """One relationship, with the honest scope of the query behind it.

    ``exact`` marks a group answered by an indexed equality over the whole
    window. Address groups are false: they are matched inside a bounded set of
    the newest ``candidate_limit`` rows, so ``truncated`` reports that older
    rows in the window were never examined.
    """

    model_config = ConfigDict(extra="forbid")

    relationship: RelationshipKind
    label: str
    reason: str
    exact: bool
    truncated: bool
    candidate_limit: int | None = None
    candidates_examined: int | None = None
    alerts: list[RelatedAlert]


class RecurrenceSummary(BaseModel):
    """Occurrences of this alert's group in the bounded candidate set.

    ``available`` is false when the row carries no signature_id: there is no
    group to belong to, and correlating on NULL would gather unrelated rows.
    ``exact`` is true only when the candidate query exhausted the window;
    otherwise ``truncated`` makes the partial count explicit.
    """

    model_config = ConfigDict(extra="forbid")

    available: bool
    signature_id: int | None = None
    source_type: str | None = None
    occurrences: int
    first_seen: str | None = None
    last_seen: str | None = None
    real_count: int
    false_positive_count: int
    uncertain_count: int
    unclassified_count: int
    exact: bool
    truncated: bool
    candidate_limit: int | None = None
    candidates_examined: int


class NeighborAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    signature: str | None = None
    verdict: str | None = None
    processed_at: str | None = None
    source_type: str | None = None


class QueueFilters(BaseModel):
    """The queue filters the neighbours were resolved against."""

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictFilter | None = None
    signature: str | None = None
    model: ModelFilter | None = None
    source: SourceFilter | None = None
    review: ReviewFilter | None = None


class QueueNeighbors(BaseModel):
    model_config = ConfigDict(extra="forbid")

    previous: NeighborAlert | None = None
    next: NeighborAlert | None = None
    filters: QueueFilters
    search_scope: QueueSearchScope | None = None


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["local", "demo"]
    event_id: int
    window_hours: int
    window_start: str
    recurrence: RecurrenceSummary
    related: list[RelatedGroup]
    neighbors: QueueNeighbors
    search_window: str | None = None


class TimelineBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    total_alerts: int
    prefiltered_count: int
    prefilter_percentage: float
    real_count: int


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    hours: int
    interval: TimelineInterval
    buckets: list[TimelineBucket]


class SpcAnomaly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected_at: str | None = None
    feature: str | None = None
    ip: str | None = None
    signature_id: int | None = None
    z: float | None = None
    note: str | None = None


class SpcAnomaliesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    available: bool
    anomalies: list[SpcAnomaly]
    count_24h: int | None = None


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "stale"]
    last_alert_age_seconds: int
    generated_at: str


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    human_verdict: VerdictFilter
    notes: str = Field(default="", max_length=MAX_FEEDBACK_NOTES_LENGTH)


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    agreed: bool


class ConfigRevisionMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    kind: ConfigKind
    revision: str
    source: Literal["shipped", "operator_import", "operator"]
    parent_revision_id: int | None = None
    shipped_base_revision: str | None = None
    state: ConfigRevisionState
    validation: dict[str, Any]
    created_at: str
    created_by: str
    note: str | None = None


class ConfigConsumerReloadStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumer: Literal["suricata", "wazuh"]
    loaded_generation: int
    desired_generation: int
    status: Literal["ok", "error"]
    prefilter_revision: str
    asset_revision: str
    loaded_at: str
    checked_at: str
    status_age_seconds: int
    last_error: str | None = None


class ConfigReloadStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supported: bool
    desired_generation: int
    consumers: list[ConfigConsumerReloadStatus]


class ConfigSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["legacy", "database"]
    generation: int
    updated_at: str
    writes_enabled: bool
    reload: ConfigReloadStatus
    active: dict[ConfigKind, ConfigRevisionMetadata]
    revision_counts: dict[ConfigKind, dict[str, int]]


class ActiveConfigResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    mode: Literal["legacy", "database"]
    generation: int
    revision: ConfigRevisionMetadata
    document: dict[str, Any]


class ConfigRevisionResponse(ActiveConfigResponse):
    """One authorized immutable revision, active or inactive."""


class ConfigRevisionsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    kind: ConfigKind
    revisions: list[ConfigRevisionMetadata]
    next_cursor: str | None = None


class ConfigDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document: dict[str, Any]
    parent_revision_id: int = Field(gt=0, strict=True)
    expected_generation: int = Field(gt=0, strict=True)
    note: str | None = Field(default=None, max_length=MAX_NOTE_LENGTH)


class ConfigDraftResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    draft: ConfigRevisionMetadata
    resumed: bool = False
    validated_revision_id: int | None = None


class ConfigValidationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    draft_id: int
    validation: dict[str, Any]
    revision: ConfigRevisionMetadata
    candidate_parent_revision_id: int | None = None


class ConfigPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_generation: int = Field(gt=0, strict=True)
    hours: int = Field(
        default=config_repository.DEFAULT_PREVIEW_HOURS,
        ge=1,
        le=config_repository.MAX_PREVIEW_HOURS,
        strict=True,
    )
    candidate_limit: int = Field(
        default=config_repository.DEFAULT_PREVIEW_CANDIDATES,
        ge=1,
        le=config_repository.MAX_PREVIEW_CANDIDATES,
        strict=True,
    )


class ConfigPreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    kind: ConfigKind
    draft_id: int
    candidate_revision_id: int
    active_revision_id: int
    generation: int
    window_hours: int
    window_start: str
    candidate_limit: int
    candidates_examined: int
    truncated: bool
    summary: dict[str, Any]
    warnings: list[str]


class ConfigActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_generation: int = Field(gt=0, strict=True)
    acknowledge_broad_rules: bool = False
    acknowledge_shipped_base_change: bool = False
    # Required only for an asset inventory while asset-scoped prefilter rules
    # are active and no complete preview evaluated them.
    acknowledge_incomplete_asset_preview: bool = False


class ConfigActivationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activated_at: str
    kind: ConfigKind
    generation: int
    previous_revision_id: int
    authority_cutover: bool
    revision: ConfigRevisionMetadata


class ConfigAuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    occurred_at: str
    kind: ConfigKind | None = None
    revision_id: int | None = None
    from_revision_id: int | None = None
    to_revision_id: int | None = None
    actor: str
    auth_via: str
    request_id: str | None = None
    action: str
    detail: dict[str, Any]


class ConfigAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    entries: list[ConfigAuditEntry]
    next_cursor: str | None = None


class LegacyHealthResponse(BaseModel):
    """Deprecated /api/health shape including storage metrics."""

    model_config = ConfigDict(extra="allow")

    status: Literal["ok", "stale"]
    last_alert_age_seconds: int
    generated_at: str | None = None
    storage: dict[str, Any] | None = None


class LegacyVerdictsResponse(BaseModel):
    """Deprecated combined /api/verdicts shape."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["local", "demo"]
    stats: LegacyStatsModel
    verdicts: list[VerdictRow]
