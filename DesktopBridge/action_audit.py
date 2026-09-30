from __future__ import annotations

from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any
import re
import uuid


AUDIT_SCHEMA_VERSION = 3
AUDIT_CAPACITY = 200
PERMISSION_AUDIT_CAPACITY = 400
OPERATION_TRACE_SCHEMA_VERSION = 1
_OPERATION_ID_PATTERN = re.compile(r"^op_[0-9a-f]{20}$")

_AUDIT_LOCK = RLock()
_AUDIT_ENTRIES: deque[dict[str, Any]] = deque(maxlen=AUDIT_CAPACITY)
_PERMISSION_DECISIONS: deque[dict[str, Any]] = deque(maxlen=PERMISSION_AUDIT_CAPACITY)
_AUDIT_EVENT_SEQUENCE = 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_operation_id() -> str:
    """Return one opaque correlation id for a single top-level bridge operation."""
    return "op_" + uuid.uuid4().hex[:20]


def _next_event_sequence_locked() -> int:
    global _AUDIT_EVENT_SEQUENCE
    _AUDIT_EVENT_SEQUENCE += 1
    return _AUDIT_EVENT_SEQUENCE


def append_action_audit(entry: dict[str, Any]) -> dict[str, Any]:
    """Append one already-redacted action audit record to the in-memory ring buffer."""
    record = deepcopy(dict(entry))
    record.setdefault("schema_version", AUDIT_SCHEMA_VERSION)
    record.setdefault("audit_id", uuid.uuid4().hex[:16])
    record.setdefault("timestamp_utc", _utc_now_iso())
    with _AUDIT_LOCK:
        record.setdefault("event_sequence", _next_event_sequence_locked())
        _AUDIT_ENTRIES.append(record)
    return deepcopy(record)


def append_action_completion_if_missing(entry: dict[str, Any]) -> dict[str, Any]:
    """Atomically ensure one final action-result record exists for an operation."""
    record = deepcopy(dict(entry))
    operation_id = str(record.get("operation_id", ""))
    if not _OPERATION_ID_PATTERN.fullmatch(operation_id):
        raise ValueError("operation completion requires a locally generated operation_id.")

    record.setdefault("schema_version", AUDIT_SCHEMA_VERSION)
    record.setdefault("entry_type", "action_result")
    record.setdefault("audit_id", uuid.uuid4().hex[:16])
    record.setdefault("timestamp_utc", _utc_now_iso())
    with _AUDIT_LOCK:
        for existing in reversed(_AUDIT_ENTRIES):
            if existing.get("operation_id") == operation_id:
                return deepcopy(existing)
        record.setdefault("event_sequence", _next_event_sequence_locked())
        _AUDIT_ENTRIES.append(record)
    return deepcopy(record)


def append_permission_decision(entry: dict[str, Any]) -> dict[str, Any]:
    """Append one redacted runtime-permission decision to a separate in-memory ring."""
    record = deepcopy(dict(entry))
    record.setdefault("schema_version", AUDIT_SCHEMA_VERSION)
    record.setdefault("entry_type", "runtime_permission_decision")
    record.setdefault("audit_id", uuid.uuid4().hex[:16])
    record.setdefault("timestamp_utc", _utc_now_iso())
    with _AUDIT_LOCK:
        record.setdefault("event_sequence", _next_event_sequence_locked())
        _PERMISSION_DECISIONS.append(record)
    return deepcopy(record)


def _operation_trace_from_snapshots(
    operation_id: str,
    action_entries: list[dict[str, Any]],
    permission_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    action_snapshot = [
        deepcopy(entry)
        for entry in action_entries
        if entry.get("operation_id") == operation_id
    ]
    permission_snapshot = [
        deepcopy(entry)
        for entry in permission_entries
        if entry.get("operation_id") == operation_id
    ]

    combined: list[tuple[str, dict[str, Any]]] = [
        ("permission_decision", entry) for entry in permission_snapshot
    ] + [
        ("action_result", entry) for entry in action_snapshot
    ]
    combined.sort(
        key=lambda item: (
            int(item[1].get("event_sequence", 0)),
            str(item[1].get("timestamp_utc", "")),
            str(item[1].get("audit_id", "")),
        )
    )

    root_actions = {
        str(entry.get("operation_root_action", ""))
        for _kind, entry in combined
        if entry.get("operation_root_action")
    }
    action_result = action_snapshot[-1] if action_snapshot else None
    permission_denied = [entry for entry in permission_snapshot if entry.get("allowed") is False]

    permission_decision_required = bool(
        action_result.get("permission_decision_required", True)
        if action_result
        else True
    )
    permission_complete = bool(permission_snapshot) or not permission_decision_required
    complete = bool(action_result) and permission_complete and len(root_actions) == 1
    if not combined:
        completeness_reason = "operation not found in current in-memory audit rings"
    elif not action_result:
        completeness_reason = "action-result record is unavailable or was evicted from the bounded audit ring"
    elif not permission_snapshot and permission_decision_required:
        completeness_reason = "permission-decision records are unavailable or were evicted from the bounded audit ring"
    elif len(root_actions) != 1:
        completeness_reason = "operation root-action metadata is inconsistent"
    else:
        completeness_reason = "all currently required trace components are present"

    timeline = []
    for sequence, (kind, entry) in enumerate(combined, start=1):
        timeline.append(
            {
                "sequence": sequence,
                "kind": kind,
                "timestamp_utc": entry.get("timestamp_utc"),
                "event_sequence": entry.get("event_sequence"),
                "audit_id": entry.get("audit_id"),
                "action": entry.get("action"),
                "outcome": entry.get("outcome"),
                "required_tier": entry.get("required_tier"),
                "decision": entry.get("decision"),
                "verification_passed": entry.get("verification_passed"),
            }
        )

    return {
        "trace_schema_version": OPERATION_TRACE_SCHEMA_VERSION,
        "operation_id": operation_id,
        "found": bool(combined),
        "complete": complete,
        "completeness_reason": completeness_reason,
        "operation_root_action": next(iter(root_actions)) if len(root_actions) == 1 else None,
        "summary": {
            "permission_decision_count": len(permission_snapshot),
            "permission_denied_count": len(permission_denied),
            "permission_decision_required": permission_decision_required,
            "action_result_count": len(action_snapshot),
            "final_outcome": action_result.get("outcome") if action_result else None,
            "verification_passed": action_result.get("verification_passed") if action_result else None,
            "retry_performed": action_result.get("retry_performed") if action_result else None,
            "started_at_utc": combined[0][1].get("timestamp_utc") if combined else None,
            "finished_at_utc": combined[-1][1].get("timestamp_utc") if combined else None,
        },
        "permission_decisions": permission_snapshot,
        "action_results": action_snapshot,
        "timeline": timeline,
        "storage": "memory_only_bounded_audit_join",
        "caller_selectable_operation_id": False,
    }


def operation_trace(operation_id: str) -> dict[str, Any]:
    """Join one locally generated operation across action and permission audit streams."""
    operation_id = str(operation_id or "").strip()
    if not _OPERATION_ID_PATTERN.fullmatch(operation_id):
        raise ValueError("operation_id must match op_<20 lowercase hex characters>.")

    with _AUDIT_LOCK:
        action_snapshot = list(_AUDIT_ENTRIES)
        permission_snapshot = list(_PERMISSION_DECISIONS)
    return _operation_trace_from_snapshots(operation_id, action_snapshot, permission_snapshot)


def recent_action_audit(
    *,
    limit: int = 20,
    action: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    limit = max(1, min(100, int(limit)))
    action_filter = (action or "").strip().casefold()
    outcome_filter = (outcome or "").strip().casefold()
    with _AUDIT_LOCK:
        snapshot = list(_AUDIT_ENTRIES)
        permission_snapshot = list(_PERMISSION_DECISIONS)

    matched: list[dict[str, Any]] = []
    for entry in reversed(snapshot):
        if action_filter and str(entry.get("action", "")).casefold() != action_filter:
            continue
        if outcome_filter and str(entry.get("outcome", "")).casefold() != outcome_filter:
            continue
        matched.append(deepcopy(entry))
        if len(matched) >= limit:
            break

    permission_matched: list[dict[str, Any]] = []
    for entry in reversed(permission_snapshot):
        if action_filter and str(entry.get("action", "")).casefold() != action_filter:
            continue
        if outcome_filter and str(entry.get("outcome", "")).casefold() != outcome_filter:
            continue
        permission_matched.append(deepcopy(entry))
        if len(permission_matched) >= limit:
            break

    recent_operation_ids: list[str] = []
    seen_operation_ids: set[str] = set()
    candidate_entries = sorted(
        matched + permission_matched,
        key=lambda entry: int(entry.get("event_sequence", 0)),
        reverse=True,
    )
    for entry in candidate_entries:
        operation_id = str(entry.get("operation_id", ""))
        if not _OPERATION_ID_PATTERN.fullmatch(operation_id) or operation_id in seen_operation_ids:
            continue
        seen_operation_ids.add(operation_id)
        recent_operation_ids.append(operation_id)
        if len(recent_operation_ids) >= 5:
            break

    recent_operation_traces = []
    for operation_id in recent_operation_ids:
        trace = _operation_trace_from_snapshots(operation_id, snapshot, permission_snapshot)
        recent_operation_traces.append(
            {
                "trace_schema_version": trace["trace_schema_version"],
                "operation_id": trace["operation_id"],
                "found": trace["found"],
                "complete": trace["complete"],
                "completeness_reason": trace["completeness_reason"],
                "operation_root_action": trace["operation_root_action"],
                "summary": trace["summary"],
                "timeline": trace["timeline"],
            }
        )

    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "storage": "memory_only_ring_buffer",
        "capacity": AUDIT_CAPACITY,
        "count": len(snapshot),
        "returned_count": len(matched),
        "entries": matched,
        "permission_storage": "memory_only_ring_buffer",
        "permission_capacity": PERMISSION_AUDIT_CAPACITY,
        "permission_count": len(permission_snapshot),
        "permission_returned_count": len(permission_matched),
        "permission_decisions": permission_matched,
        "correlation": {
            "field": "operation_id",
            "root_action_field": "operation_root_action",
            "nested_checks_share_operation_id": True,
            "caller_selectable": False,
        },
        "trace_compat": {
            "schema_version": 1,
            "purpose": "stale_tool_catalog_compatibility",
            "max_recent_operations": 5,
            "full_trace_tool": "get_desktop_operation_trace",
            "requires_new_input_schema": False,
        },
        "recent_operation_traces": recent_operation_traces,
    }


def reset_action_audit_for_tests() -> None:
    """Test-only helper. This is intentionally not exposed through MCP."""
    global _AUDIT_EVENT_SEQUENCE
    with _AUDIT_LOCK:
        _AUDIT_ENTRIES.clear()
        _PERMISSION_DECISIONS.clear()
        _AUDIT_EVENT_SEQUENCE = 0
