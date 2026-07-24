from __future__ import annotations

from datetime import UTC, datetime

from sentinelops.storage import AuditAnchorMetrics

OUTBOX_STATUSES = ("pending", "claimed", "delivered", "dead_letter")
SECURITY_STATUSES = (
    "initializing",
    "healthy",
    "degraded",
    "configuration_blocked",
    "integrity_blocked",
    "unlock_pending",
)


def _timestamp(value: datetime | None) -> float:
    if value is None:
        return 0.0
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


def render_prometheus_metrics(snapshot: AuditAnchorMetrics | None) -> str:
    counts = snapshot.status_counts if snapshot is not None else {}
    state = snapshot.security_state if snapshot is not None else None
    oldest_age = (
        snapshot.oldest_undelivered_age_seconds
        if snapshot is not None
        else 0.0
    )
    last_delivered = (
        _timestamp(snapshot.last_delivered_at)
        if snapshot is not None
        else 0.0
    )

    lines = [
        "# HELP sentinelops_audit_anchor_outbox_items "
        "Current durable audit-anchor outbox items by status.",
        "# TYPE sentinelops_audit_anchor_outbox_items gauge",
    ]
    lines.extend(
        "sentinelops_audit_anchor_outbox_items"
        f'{{status="{status}"}} {int(counts.get(status, 0))}'
        for status in OUTBOX_STATUSES
    )
    lines.extend(
        [
            "# HELP sentinelops_audit_anchor_dead_letter_items "
            "Audit anchors requiring operator intervention.",
            "# TYPE sentinelops_audit_anchor_dead_letter_items gauge",
            "sentinelops_audit_anchor_dead_letter_items "
            f"{int(counts.get('dead_letter', 0))}",
            "# HELP sentinelops_audit_anchor_oldest_delivery_age_seconds "
            "Age of the oldest pending or claimed anchor.",
            "# TYPE sentinelops_audit_anchor_oldest_delivery_age_seconds gauge",
            "sentinelops_audit_anchor_oldest_delivery_age_seconds "
            f"{max(0.0, oldest_age):.6f}",
            "# HELP sentinelops_audit_anchor_last_delivery_timestamp_seconds "
            "Database timestamp of the latest successful anchor delivery.",
            "# TYPE sentinelops_audit_anchor_last_delivery_timestamp_seconds gauge",
            "sentinelops_audit_anchor_last_delivery_timestamp_seconds "
            f"{last_delivered:.6f}",
            "# HELP sentinelops_audit_anchor_security_write_blocked "
            "Whether cluster writes are blocked by the audit-anchor gate.",
            "# TYPE sentinelops_audit_anchor_security_write_blocked gauge",
            "sentinelops_audit_anchor_security_write_blocked "
            f"{1 if state is not None and state.write_blocked else 0}",
            "# HELP sentinelops_audit_anchor_security_state "
            "One-hot persistent audit-anchor security state.",
            "# TYPE sentinelops_audit_anchor_security_state gauge",
        ]
    )
    lines.extend(
        "sentinelops_audit_anchor_security_state"
        f'{{status="{status}"}} {1 if state is not None and state.status == status else 0}'
        for status in SECURITY_STATUSES
    )
    lines.extend(
        [
            "# HELP sentinelops_audit_anchor_reconcile_last_attempt_timestamp_seconds "
            "Database timestamp of the latest reconciliation attempt.",
            "# TYPE "
            "sentinelops_audit_anchor_reconcile_last_attempt_timestamp_seconds gauge",
            "sentinelops_audit_anchor_reconcile_last_attempt_timestamp_seconds "
            f"{_timestamp(state.last_attempt_at if state else None):.6f}",
            "# HELP sentinelops_audit_anchor_reconcile_last_success_timestamp_seconds "
            "Database timestamp of the latest successful reconciliation.",
            "# TYPE "
            "sentinelops_audit_anchor_reconcile_last_success_timestamp_seconds gauge",
            "sentinelops_audit_anchor_reconcile_last_success_timestamp_seconds "
            f"{_timestamp(state.last_success_at if state else None):.6f}",
        ]
    )
    return "\n".join(lines) + "\n"
