from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_MAX_TAIL_BYTES = 256 * 1024
_STATUS_STALE_SECONDS = 180.0
_NEXT_CHECK_GRACE_SECONDS = 120.0
_ALERT_EVENT_TYPES = {
    "frozen",
    "tts_spoken",
    "tts_failed",
    "alert_suppressed",
    "emergency_stop_observed",
}


def _watchdog_root() -> Path:
    override = os.environ.get("YUNKAI_WATCHDOG_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return (Path(__file__).resolve().parent.parent / "Yunkai-Watchdog").resolve()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return value if isinstance(value, dict) else None


def _tail_jsonl(path: Path, *, max_records: int = 200) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - _MAX_TAIL_BYTES)
            handle.seek(start)
            raw = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []

    lines = raw.splitlines()
    if start > 0 and lines:
        lines = lines[1:]
    records: list[dict[str, Any]] = []
    for line in lines[-max_records:]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def get_watchdog_status(recent_alert_limit: int = 10) -> dict[str, Any]:
    if not isinstance(recent_alert_limit, int) or recent_alert_limit < 1 or recent_alert_limit > 50:
        raise ValueError("recent_alert_limit must be an integer from 1 through 50")

    root = _watchdog_root()
    runtime = root / "runtime"
    status = _read_json(runtime / "status.json")
    sentinel = _read_json(runtime / "sentinel_status.json")
    frozen = _read_json(runtime / "FROZEN.json")
    incident = _read_json(runtime / "ACTIVE_INCIDENT.json")
    control = _read_json(runtime / "control.json")
    emergency_stop = (runtime / "EMERGENCY_STOP").exists()
    records = _tail_jsonl(runtime / "audit.jsonl")

    latest_observation = next(
        (record for record in reversed(records) if record.get("eventType") == "observation_classified"),
        None,
    )
    alerts = [record for record in records if record.get("eventType") in _ALERT_EVENT_TYPES][-recent_alert_limit:]

    now = datetime.now(timezone.utc)
    updated_at = _parse_time(status.get("updatedAt") if status else None)
    next_check_at = _parse_time(status.get("nextCheckAt") if status else None)
    freshness_seconds = None if updated_at is None else max(0.0, (now - updated_at).total_seconds())
    sentinel_updated_at = _parse_time(sentinel.get("updatedAt") if sentinel else None)
    sentinel_freshness_seconds = (
        None if sentinel_updated_at is None else max(0.0, (now - sentinel_updated_at).total_seconds())
    )
    incident_created_at = _parse_time(incident.get("createdAt") if incident else None)
    frozen_created_at = _parse_time(frozen.get("createdAt") if frozen else None)
    incident_freshness_seconds = (
        None if incident_created_at is None else max(0.0, (now - incident_created_at).total_seconds())
    )
    frozen_freshness_seconds = (
        None if frozen_created_at is None else max(0.0, (now - frozen_created_at).total_seconds())
    )

    primary_fresh = (
        status is not None
        and freshness_seconds is not None
        and freshness_seconds <= _STATUS_STALE_SECONDS
    )
    sentinel_fresh = (
        sentinel is not None
        and sentinel_freshness_seconds is not None
        and sentinel_freshness_seconds <= _STATUS_STALE_SECONDS
    )
    incident_matches_freeze = bool(
        incident
        and frozen
        and isinstance(incident.get("key"), str)
        and incident.get("key") == frozen.get("key")
    )
    status_reports_freeze = bool(status and status.get("frozen"))
    retained_freeze_is_current = bool(
        primary_fresh
        and frozen is not None
        and (
            status_reports_freeze
            or (
                incident_matches_freeze
                and frozen_freshness_seconds is not None
                and frozen_freshness_seconds <= _STATUS_STALE_SECONDS
            )
        )
    )
    current_incident = (
        incident
        if retained_freeze_is_current
        and incident_freshness_seconds is not None
        and incident_freshness_seconds <= _STATUS_STALE_SECONDS
        else None
    )
    current_frozen_incident = frozen if retained_freeze_is_current else None

    # FROZEN.json is a durable Watchdog self-control latch: it intentionally
    # survives until an operator runs `arm`. It is not proof that the same UI
    # permission/auth/quota condition is still present hours or days later.
    # Fresh monitor metadata therefore outranks the retained latch for current
    # status interpretation. A stale monitor can never make a retained incident
    # authoritative for another connector's permission decision.
    if emergency_stop:
        monitoring_state = "stopped"
    elif status is None:
        monitoring_state = "unknown"
    elif not primary_fresh:
        monitoring_state = "stale"
    elif bool(status.get("stopped")):
        monitoring_state = "stopped"
    elif retained_freeze_is_current or status_reports_freeze:
        monitoring_state = "frozen"
    elif (
        next_check_at is not None
        and now > next_check_at
        and (now - next_check_at).total_seconds() > _NEXT_CHECK_GRACE_SECONDS
    ):
        monitoring_state = "stale"
    else:
        monitoring_state = "active"

    if sentinel is None:
        background_monitoring_state = "unknown"
    elif not sentinel_fresh:
        background_monitoring_state = "stale"
    elif sentinel.get("lifecycleState") == "STOPPED":
        background_monitoring_state = "stopped"
    else:
        background_monitoring_state = "active"

    incident_state = current_incident.get("state") if current_incident else None
    final_state = status.get("finalState") if primary_fresh and status else None
    background_quota = bool(sentinel_fresh and sentinel and sentinel.get("quotaExhausted"))
    background_attention = bool(sentinel_fresh and sentinel and sentinel.get("attentionRequired"))
    quota_exhausted = (
        final_state == "QUOTA_EXHAUSTED"
        or incident_state == "QUOTA_EXHAUSTED"
        or background_quota
    )
    human_action_required = bool(
        emergency_stop
        or incident_state in {
            "PERMISSION_REQUIRED",
            "AUTH_REQUIRED",
            "QUOTA_EXHAUSTED",
            "UNKNOWN_UNSAFE",
        }
        or background_attention
        or quota_exhausted
    )
    watchdog_health_attention_required = (
        monitoring_state in {"stopped", "stale"}
        or background_monitoring_state in {"stopped", "stale"}
    )
    attention_required = human_action_required or watchdog_health_attention_required

    return {
        "ok": True,
        "schema_version": 1,
        "watchdog_root": str(root),
        "runtime_present": runtime.exists(),
        "monitoring_state": monitoring_state,
        "attention_required": attention_required,
        "human_action_required": human_action_required,
        "watchdog_health_attention_required": watchdog_health_attention_required,
        "quota_exhausted": quota_exhausted,
        "status": status,
        "status_freshness_seconds": freshness_seconds,
        "status_is_fresh": primary_fresh,
        "background_monitoring_state": background_monitoring_state,
        "background_status_freshness_seconds": sentinel_freshness_seconds,
        "background_status_is_fresh": sentinel_fresh,
        "background_sentinel": sentinel,
        "emergency_stop": emergency_stop,
        "frozen_incident": current_frozen_incident,
        "active_incident": current_incident,
        "historical_incidents": {
            "retained_frozen_incident": frozen if current_frozen_incident is None else None,
            "retained_active_incident": incident if current_incident is None else None,
            "authoritative_for_current_ui": False,
        },
        "incident_freshness_seconds": incident_freshness_seconds,
        "frozen_incident_freshness_seconds": frozen_freshness_seconds,
        "authority": {
            "role": "observation_and_watchdog_self_control_only",
            "authorization_authority": False,
            "may_override_connector_permission_state": False,
            "permission_authority": "target_connector_or_capability_policy",
            "stale_incidents_authoritative": False,
        },
        "control": {
            "mute_until": control.get("muteUntil") if control else None,
            "acknowledged_incident_count": len(control.get("acknowledgedIncidentKeys", []))
            if control and isinstance(control.get("acknowledgedIncidentKeys"), list)
            else 0,
            "freeze_latched": frozen is not None,
            "freeze_latch_current": current_frozen_incident is not None,
            "freeze_latch_requires_explicit_arm": frozen is not None,
        },
        "latest_observation": latest_observation,
        "recent_alerts": alerts,
        "recent_alert_count": len(alerts),
        "privacy": {
            "full_ui_transcript_returned": False,
            "screenshots_returned": False,
            "typed_content_returned": False,
        },
    }
