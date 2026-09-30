from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchdog_status import get_watchdog_status


class WatchdogStatusTests(unittest.TestCase):
    def test_reads_status_incident_and_bounded_alerts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "status.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "updatedAt": "2099-08-31T05:00:00.000Z",
                        "finalState": "QUOTA_EXHAUSTED",
                        "frozen": True,
                        "stopped": False,
                        "recoveryVerified": False,
                        "actionsAttempted": 0,
                        "nextCheckMs": None,
                        "nextCheckAt": None,
                        "reason": "unsafe state requires manual action",
                    }
                ),
                encoding="utf-8",
            )
            incident = {
                "schemaVersion": 1,
                "key": "quota-incident",
                "state": "QUOTA_EXHAUSTED",
                "reason": "quota",
                "createdAt": "2099-08-31T05:00:00.000Z",
            }
            (runtime / "FROZEN.json").write_text(json.dumps(incident), encoding="utf-8")
            (runtime / "ACTIVE_INCIDENT.json").write_text(json.dumps(incident), encoding="utf-8")
            records = [
                {
                    "schemaVersion": 1,
                    "timestamp": "2099-08-31T05:00:00.000Z",
                    "runId": "run",
                    "eventType": "observation_classified",
                    "details": {"state": "QUOTA_EXHAUSTED", "surface": "codex"},
                },
                {
                    "schemaVersion": 1,
                    "timestamp": "2099-08-31T05:00:01.000Z",
                    "runId": "run",
                    "eventType": "frozen",
                    "details": {"state": "QUOTA_EXHAUSTED"},
                },
            ]
            (runtime / "audit.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"YUNKAI_WATCHDOG_ROOT": str(root)}):
                status = get_watchdog_status(recent_alert_limit=5)
            self.assertTrue(status["ok"])
            self.assertEqual(status["monitoring_state"], "frozen")
            self.assertTrue(status["quota_exhausted"])
            self.assertTrue(status["attention_required"])
            self.assertTrue(status["human_action_required"])
            self.assertEqual(status["active_incident"]["state"], "QUOTA_EXHAUSTED")
            self.assertTrue(status["control"]["freeze_latch_current"])
            self.assertFalse(status["authority"]["authorization_authority"])
            self.assertFalse(status["authority"]["may_override_connector_permission_state"])
            self.assertEqual(status["latest_observation"]["details"]["surface"], "codex")
            self.assertEqual(status["recent_alert_count"], 1)
            self.assertFalse(status["privacy"]["full_ui_transcript_returned"])

    def test_background_sentinel_can_raise_quota_attention_without_foreground_freeze(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / "status.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "updatedAt": "2099-08-31T05:00:00.000Z",
                        "finalState": "RUNNING_NORMAL",
                        "frozen": False,
                        "stopped": False,
                        "recoveryVerified": False,
                        "actionsAttempted": 0,
                        "nextCheckMs": 600000,
                        "nextCheckAt": "2099-08-31T05:10:00.000Z",
                        "reason": "healthy observe-only cycle",
                    }
                ),
                encoding="utf-8",
            )
            (runtime / "sentinel_status.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "updatedAt": "2099-08-31T05:00:30.000Z",
                        "knownWindowCount": 2,
                        "attentionRequired": True,
                        "quotaExhausted": True,
                        "windows": [{"surface": "codex", "state": "QUOTA_EXHAUSTED"}],
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"YUNKAI_WATCHDOG_ROOT": str(root)}):
                status = get_watchdog_status()
            self.assertTrue(status["quota_exhausted"])
            self.assertTrue(status["attention_required"])
            self.assertEqual(status["background_monitoring_state"], "active")
            self.assertTrue(status["background_sentinel"]["quotaExhausted"])

    def test_stale_retained_permission_freeze_is_historical_not_current_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            stale_time = "2000-01-01T00:00:00.000Z"
            (runtime / "status.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "component": "main",
                        "instanceId": "child-old",
                        "processId": 123,
                        "startedAt": stale_time,
                        "updatedAt": stale_time,
                        "heartbeatAt": stale_time,
                        "lifecycleState": "STARTING",
                        "primaryMonitorActive": False,
                        "metadataOnly": True,
                        "finalState": "RUNNING_NORMAL",
                        "frozen": False,
                        "stopped": False,
                        "recoveryVerified": False,
                        "actionsAttempted": 0,
                        "nextCheckMs": None,
                        "nextCheckAt": None,
                        "reason": "old monitor state",
                    }
                ),
                encoding="utf-8",
            )
            (runtime / "sentinel_status.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "component": "sentinel",
                        "instanceId": "child-old",
                        "processId": 123,
                        "startedAt": stale_time,
                        "updatedAt": stale_time,
                        "heartbeatAt": stale_time,
                        "lifecycleState": "STOPPED",
                        "lastErrorCode": None,
                        "metadataOnly": True,
                        "knownWindowCount": 1,
                        "attentionRequired": False,
                        "quotaExhausted": False,
                        "windows": [{"surface": "codex", "state": "UNKNOWN_UNSAFE"}],
                    }
                ),
                encoding="utf-8",
            )
            incident = {
                "schemaVersion": 1,
                "key": "old-permission",
                "state": "PERMISSION_REQUIRED",
                "reason": "old permission cue",
                "createdAt": stale_time,
            }
            (runtime / "FROZEN.json").write_text(json.dumps(incident), encoding="utf-8")
            (runtime / "ACTIVE_INCIDENT.json").write_text(json.dumps(incident), encoding="utf-8")

            with patch.dict(os.environ, {"YUNKAI_WATCHDOG_ROOT": str(root)}):
                status = get_watchdog_status()

            self.assertEqual(status["monitoring_state"], "stale")
            self.assertEqual(status["background_monitoring_state"], "stale")
            self.assertFalse(status["status_is_fresh"])
            self.assertFalse(status["background_status_is_fresh"])
            self.assertIsNone(status["active_incident"])
            self.assertIsNone(status["frozen_incident"])
            self.assertEqual(
                status["historical_incidents"]["retained_active_incident"]["state"],
                "PERMISSION_REQUIRED",
            )
            self.assertEqual(
                status["historical_incidents"]["retained_frozen_incident"]["state"],
                "PERMISSION_REQUIRED",
            )
            self.assertFalse(status["human_action_required"])
            self.assertTrue(status["watchdog_health_attention_required"])
            self.assertTrue(status["attention_required"])
            self.assertTrue(status["control"]["freeze_latched"])
            self.assertFalse(status["control"]["freeze_latch_current"])
            self.assertTrue(status["control"]["freeze_latch_requires_explicit_arm"])
            self.assertFalse(status["authority"]["authorization_authority"])
            self.assertFalse(status["authority"]["may_override_connector_permission_state"])
            self.assertFalse(status["authority"]["stale_incidents_authoritative"])

    def test_stale_quota_incident_does_not_report_current_quota_exhaustion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            stale_time = "2000-01-01T00:00:00.000Z"
            (runtime / "status.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "updatedAt": stale_time,
                        "finalState": "QUOTA_EXHAUSTED",
                        "frozen": True,
                        "stopped": False,
                        "nextCheckAt": None,
                    }
                ),
                encoding="utf-8",
            )
            incident = {
                "schemaVersion": 1,
                "key": "old-quota",
                "state": "QUOTA_EXHAUSTED",
                "reason": "old quota cue",
                "createdAt": stale_time,
            }
            (runtime / "FROZEN.json").write_text(json.dumps(incident), encoding="utf-8")
            (runtime / "ACTIVE_INCIDENT.json").write_text(json.dumps(incident), encoding="utf-8")

            with patch.dict(os.environ, {"YUNKAI_WATCHDOG_ROOT": str(root)}):
                status = get_watchdog_status()

            self.assertEqual(status["monitoring_state"], "stale")
            self.assertFalse(status["quota_exhausted"])
            self.assertFalse(status["human_action_required"])
            self.assertIsNone(status["active_incident"])

    def test_missing_runtime_fails_read_only_to_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"YUNKAI_WATCHDOG_ROOT": temporary}):
                status = get_watchdog_status()
            self.assertEqual(status["monitoring_state"], "unknown")
            self.assertFalse(status["quota_exhausted"])
            self.assertFalse(status["runtime_present"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
