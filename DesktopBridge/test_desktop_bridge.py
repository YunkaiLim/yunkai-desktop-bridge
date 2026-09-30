from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from action_audit import reset_action_audit_for_tests
from bridge_manifest import (
    BRIDGE_VERSION,
    CAPABILITY_MANIFEST_SCHEMA_VERSION,
    CAPABILITY_STATE_SCHEMA_VERSION,
    PLANNER_ROUTING_SCHEMA_VERSION,
    desktop_capability_state,
    desktop_device_snapshot,
    desktop_planner_routing_hints,
)
from desktop_bridge import (
    DesktopBridge,
    DesktopBridgeError,
    DesktopWindow,
    GAME_INPUT_BACKENDS,
    SAFE_GAME_KEYS,
    SAFE_HOTKEYS,
    SAFE_KEYS,
)
from server import server
from yunkai_shared.device_contract import validate_device_snapshot


class FakeDesktopBridge(DesktopBridge):
    def virtual_screen(self):
        return (-1920, 0, 3840, 1080)


class FakeGuardedBridge(FakeDesktopBridge):
    def __init__(self):
        self.events = []

    def active_window(self):
        return DesktopWindow(
            hwnd=10,
            title="Notes - Notepad",
            process_id=20,
            rect=(100, 100, 1100, 700),
            visible=True,
            minimized=False,
        )

    def click(self, x, y, button="left", clicks=1):
        self.events.append(("click", x, y, button, clicks))
        return {
            "status": "ok",
            "action": "click",
            "x": x,
            "y": y,
            "button": button,
            "clicks": clicks,
        }

    def type_text(self, text, *, _before_chunk=None):
        if _before_chunk is not None:
            _before_chunk()
        self.events.append(("type", text))
        return {"status": "ok", "action": "type_text", "characters": len(text),
                "chunk_count": 1, "chunk_size_policy": 4096}

    def _send_vk(self, vk, down):
        self.events.append(("key", vk, down))


class FakeFocusBridge(DesktopBridge):
    def __init__(self):
        self.window = DesktopWindow(
            hwnd=42,
            title="Focus Target",
            process_id=99,
            rect=(20, 30, 620, 430),
            visible=True,
            minimized=False,
        )

    def _window_from_hwnd(self, hwnd):
        if int(hwnd) != self.window.hwnd:
            raise DesktopBridgeError("unexpected test window")
        return self.window

    def active_window(self):
        return self.window


class FakeUIABridge(FakeGuardedBridge):
    def __init__(self, elements=None):
        super().__init__()
        self.uia_elements = elements or [
            {
                "name": "Search",
                "control_type": "button",
                "automation_id": "search-button",
                "class_name": "",
                "framework_id": "Chrome",
                "rect": [200, 150, 260, 190],
                "enabled": True,
                "offscreen": False,
                "is_password": False,
                "has_keyboard_focus": False,
                "keyboard_focusable": True,
                "depth": 5,
                "actionable": True,
            },
            {
                "name": "Address and search bar",
                "control_type": "edit",
                "automation_id": "address",
                "class_name": "",
                "framework_id": "Chrome",
                "rect": [300, 120, 800, 160],
                "enabled": True,
                "offscreen": False,
                "is_password": False,
                "has_keyboard_focus": True,
                "keyboard_focusable": True,
                "depth": 5,
                "actionable": True,
            },
            {
                "name": "Close",
                "control_type": "button",
                "automation_id": "close",
                "class_name": "",
                "framework_id": "Chrome",
                "rect": [1000, 100, 1099, 140],
                "enabled": True,
                "offscreen": False,
                "is_password": False,
                "has_keyboard_focus": False,
                "keyboard_focusable": True,
                "depth": 2,
                "actionable": True,
            },
        ]

    def list_uia_elements(self, hwnd=None, limit=120, max_depth=12):
        return list(self.uia_elements), False

    def hotkey(self, combo):
        self.events.append(("hotkey", combo))
        return {"status": "ok", "action": "hotkey", "hotkey": combo}


class FakeCorrelatedUIABridge(FakeUIABridge):
    def click(self, x, y, button="left", clicks=1):
        self._require_permission_tier("interact", action="click")
        return super().click(x, y, button=button, clicks=clicks)


class FakeStateBridge(DesktopBridge):
    def __init__(self, current_context):
        self.current_context = current_context

    def fast_context(self, control_limit=80, include_visual_hash=False):
        result = dict(self.current_context)
        if not include_visual_hash:
            result.pop("visual_dhash", None)
        return result


class FakeTransactionalBridge(DesktopBridge):
    def __init__(self, changed=True, postconditions_passed=True):
        self.changed = changed
        self.postconditions_passed = postconditions_passed
        self.events = []

    def fast_context(self, control_limit=80, include_visual_hash=False):
        return {
            "active_window": {"hwnd": 10, "title": "Notes - Notepad"},
            "semantic_signature": "aaaaaaaaaaaaaaaaaaaaaaaa",
            "visual_dhash": "0000000000000000" if include_visual_hash else None,
        }

    def click_active_window_uia_element(self, expected_window_title, **kwargs):
        self.events.append(("click", expected_window_title, kwargs))
        return {"status": "ok", "action": "click_active_window_uia_element"}

    def type_active_window_uia_text(self, text, expected_window_title, **kwargs):
        self.events.append(("type", text, expected_window_title, kwargs))
        return {"status": "ok", "action": "type_active_window_uia_text", "characters": len(text)}

    def verify_state_change(self, **kwargs):
        self.events.append(("verify", kwargs))
        return {
            "status": "ok",
            "action": "verify_state_change",
            "state_change_detected": self.changed,
        }

    def evaluate_expected_postconditions(self, **kwargs):
        configured = any(
            value not in (None, "")
            for key, value in kwargs.items()
            if key != "expected_element_present"
        ) or kwargs.get("expected_element_present") is not None
        if not configured:
            return {"configured": False, "postconditions_passed": True, "checks": []}
        self.events.append(("postcondition", kwargs))
        return {
            "configured": True,
            "postconditions_passed": bool(self.postconditions_passed),
            "checks": [{"kind": "test", "passed": bool(self.postconditions_passed)}],
        }


class FakeDelayedTransactionalBridge(FakeTransactionalBridge):
    def __init__(self):
        super().__init__(changed=True, postconditions_passed=True)
        self.observation_reads = 0

    def verify_state_change(self, **kwargs):
        self.observation_reads += 1
        self.events.append(("verify", kwargs))
        changed = self.observation_reads >= 2
        return {
            "status": "ok",
            "action": "verify_state_change",
            "state_change_detected": changed,
            "semantic_changed": changed,
            "window_identity_changed": False,
            "visual_change_confident": False,
        }

    def evaluate_expected_postconditions(self, **kwargs):
        configured = any(
            value not in (None, "")
            for key, value in kwargs.items()
            if key != "expected_element_present"
        ) or kwargs.get("expected_element_present") is not None
        if not configured:
            return {"configured": False, "postconditions_passed": True, "checks": []}
        self.events.append(("postcondition", kwargs))
        passed = self.observation_reads >= 2
        return {
            "configured": True,
            "postconditions_passed": passed,
            "checks": [{"kind": "test", "passed": passed}],
        }


class FakeFastPathBridge(FakeUIABridge):
    def __init__(self, target_name="Generate", target_automation_id="generate-button"):
        super().__init__(
            elements=[
                {
                    "name": target_name,
                    "control_type": "button",
                    "automation_id": target_automation_id,
                    "class_name": "",
                    "framework_id": "Chrome",
                    "rect": [200, 150, 320, 200],
                    "enabled": True,
                    "offscreen": False,
                    "is_password": False,
                    "has_keyboard_focus": False,
                    "keyboard_focusable": True,
                    "depth": 5,
                    "actionable": True,
                }
            ]
        )
        self.fast_context_calls = []
        self.safe_semantic_click_calls = 0

    def fast_context(self, control_limit=80, include_visual_hash=False):
        self.fast_context_calls.append((control_limit, include_visual_hash))
        return {
            "active_window": {"hwnd": 10, "title": "Notes - Notepad"},
            "semantic_signature": "aaaaaaaaaaaaaaaaaaaaaaaa",
            "semantic_source": "uia",
            "uia_elements": list(self.uia_elements),
            "uia_count": len(self.uia_elements),
            "uia_returned_count": len(self.uia_elements),
            "uia_truncated": False,
            **({"visual_dhash": "0000000000000000"} if include_visual_hash else {}),
        }

    def click_active_window_uia_element(self, expected_window_title, **kwargs):
        self.safe_semantic_click_calls += 1
        return super().click_active_window_uia_element(expected_window_title, **kwargs)

    def verify_state_change(self, **kwargs):
        self.events.append(("verify", kwargs))
        return {
            "status": "ok",
            "action": "verify_state_change",
            "state_change_detected": True,
            "semantic_changed": True,
            "window_identity_changed": False,
            "visual_change_confident": False,
            "current": {
                "semantic_signature": "bbbbbbbbbbbbbbbbbbbbbbbb",
                "visual_dhash": None,
                "window_hwnd": 10,
                "window_title": "Notes - Notepad",
                "semantic_source": "uia",
            },
        }


class FakeTruncatedUIABridge(FakeUIABridge):
    def list_uia_elements(self, hwnd=None, limit=120, max_depth=12):
        return [], True


class FakeRefusingTransactionalBridge(FakeTransactionalBridge):
    def click_active_window_uia_element(self, expected_window_title, **kwargs):
        self.events.append(("click_refused", expected_window_title, kwargs))
        raise DesktopBridgeError("selector refused for test")


class FakeGameBridge(DesktopBridge):
    def __init__(self):
        self.events = []
        self._runtime_profile_override = "elevated_game"

    @staticmethod
    def _fake_window():
        return DesktopWindow(
            hwnd=1,
            title="ZenlessZoneZero",
            process_id=2,
            rect=(0, 0, 1920, 1080),
            visible=True,
            minimized=False,
        )

    def _require_foreground_title(self, expected_window_title):
        if expected_window_title.casefold() not in "ZenlessZoneZero".casefold():
            raise DesktopBridgeError("foreground mismatch")
        return self._fake_window()

    def _send_vk(self, vk, down):
        self.events.append((vk, down))

    def _send_game_vk(self, vk, down, backend="SCAN", hwnd=None):
        self.events.append((vk, down, backend))


class DesktopBridgeTests(unittest.TestCase):
    def test_capability_manifest_is_versioned_deterministic_and_permission_separate(self):
        bridge = FakeDesktopBridge()
        first = bridge.capability_manifest()
        second = bridge.capability_manifest()

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], CAPABILITY_MANIFEST_SCHEMA_VERSION)
        self.assertEqual(first["bridge"]["version"], BRIDGE_VERSION)
        self.assertEqual(first["bridge"]["id"], "desktop.windows")
        self.assertFalse(first["adapter"]["tool_catalog_authoritative"])
        self.assertFalse(first["discovery"]["requires_new_tool_schema"])
        self.assertTrue(first["discovery"]["schema_cache_tolerant"])
        self.assertFalse(first["permission_model"]["capabilities_are_permissions"])
        self.assertTrue(first["permission_model"]["separate_runtime_policy"])
        self.assertEqual(first["contract_versions"]["capability_state"], CAPABILITY_STATE_SCHEMA_VERSION)
        self.assertEqual(first["contract_versions"]["planner_routing"], PLANNER_ROUTING_SCHEMA_VERSION)
        self.assertEqual(first["contract_versions"]["action_audit"], 3)
        self.assertEqual(first["contract_versions"]["operation_trace"], 1)
        self.assertEqual(first["contract_versions"]["device_contract"], 1)
        self.assertEqual(first["contract_versions"]["permission_state"], 1)
        self.assertIn("desktop.operation.trace", first["capability_groups"]["observability"])
        self.assertIn("desktop.planner.routing_hints", first["capability_groups"]["planning"])
        self.assertFalse(first["feature_flags"]["automatic_action_retry"])
        self.assertTrue(first["feature_flags"]["dynamic_capability_state"])
        self.assertTrue(first["feature_flags"]["dynamic_planner_routing_hints"])

        first["feature_flags"]["uia_semantics"] = False
        self.assertTrue(bridge.capability_manifest()["feature_flags"]["uia_semantics"])

    def test_unified_snapshot_adapts_legacy_state_without_breaking_it(self):
        policy = {
            "schema_version": 1,
            "runtime_profile": "standard",
            "allowed_tiers": ["observe", "interact"],
            "denied_tiers": ["elevated_input"],
            "permission_tiers": ["observe", "interact", "elevated_input"],
            "profiles": {
                "elevated_game": ["observe", "interact", "elevated_input"],
                "observe_only": ["observe"],
                "standard": ["observe", "interact"],
            },
            "default_profile": "standard",
            "profile_source": "bridge_runtime_configuration",
            "model_selectable_profile": False,
            "self_escalation": False,
            "side_effect_free": True,
        }
        legacy_state = desktop_capability_state(
            semantic_source="uia",
            uia_enabled=True,
            vision_recommended=False,
            local_vision_status={"configured": True, "enabled": True},
            runtime_policy=policy,
        )
        routing = desktop_planner_routing_hints(
            capability_state=legacy_state,
            runtime_policy=policy,
        )
        snapshot = desktop_device_snapshot(
            capability_manifest=FakeDesktopBridge().capability_manifest(),
            capability_state=legacy_state,
            planner_routing_hints=routing,
            runtime_policy=policy,
        )

        self.assertEqual(validate_device_snapshot(snapshot), snapshot)
        self.assertEqual(snapshot["device"]["device_id"], "desktop.windows")
        self.assertEqual(snapshot["contract"]["version"], "0.1")
        self.assertIn("permission", legacy_state["states"]["desktop.mouse.click"])
        self.assertNotIn(
            "permission", snapshot["capability_state"]["states"]["desktop.mouse.click"]
        )
        self.assertEqual(
            snapshot["permission_state"]["states"]["desktop.mouse.click"]["state"],
            "allowed",
        )
        self.assertEqual(
            snapshot["permission_state"]["states"]["desktop.game_input.elevated_experimental"][
                "state"
            ],
            "denied",
        )
        self.assertEqual(snapshot["planner_routing_hints"]["routes"]["game_input"]["status"], "blocked")

    def test_capability_state_keeps_availability_separate_from_permission(self):
        standard_policy = {
            "runtime_profile": "standard",
            "allowed_tiers": ["observe", "interact"],
        }
        state = desktop_capability_state(
            semantic_source="uia",
            uia_enabled=True,
            vision_recommended=False,
            local_vision_status={"configured": True, "enabled": True},
            runtime_policy=standard_policy,
        )
        self.assertEqual(state["schema_version"], CAPABILITY_STATE_SCHEMA_VERSION)
        self.assertEqual(state["bridge_version"], BRIDGE_VERSION)
        self.assertTrue(state["availability_independent_from_permission"])
        self.assertFalse(state["probe_semantics"]["external_health_checks_performed"])
        self.assertEqual(state["summary"]["total"], 30)
        self.assertEqual(state["summary"]["available"], 30)
        self.assertEqual(state["summary"]["degraded"], 0)
        self.assertEqual(state["summary"]["unavailable"], 0)
        self.assertEqual(state["summary"]["permission_denied"], 1)

        game = state["states"]["desktop.game_input.elevated_experimental"]
        self.assertEqual(game["availability"], "available")
        self.assertEqual(game["permission"]["state"], "denied")
        self.assertEqual(game["permission"]["required_tier"], "elevated_input")

    def test_capability_state_reports_surface_degradation_and_missing_fallback(self):
        observe_only_policy = {
            "runtime_profile": "observe_only",
            "allowed_tiers": ["observe"],
        }
        state = desktop_capability_state(
            semantic_source="sparse",
            uia_enabled=True,
            vision_recommended=True,
            local_vision_status={"configured": False, "enabled": False},
            runtime_policy=observe_only_policy,
        )
        self.assertEqual(state["summary"]["degraded"], 6)
        self.assertEqual(state["summary"]["unavailable"], 1)
        self.assertEqual(state["summary"]["permission_denied"], 15)
        self.assertEqual(
            state["states"]["desktop.uia.semantic_click"]["reason_code"],
            "uia_surface_sparse",
        )
        self.assertEqual(
            state["states"]["desktop.local_vision_fallback"]["availability"],
            "unavailable",
        )
        self.assertEqual(
            state["states"]["desktop.local_vision_fallback"]["reason_code"],
            "local_vision_not_configured",
        )
        self.assertEqual(
            state["states"]["desktop.local_vision_fallback"]["basis"],
            "configuration_only",
        )
        self.assertEqual(
            state["states"]["desktop.uia.semantic_click"]["basis"],
            "current_surface",
        )

    def test_capability_state_preserves_partial_non_uia_verification_paths(self):
        state = desktop_capability_state(
            semantic_source="win32",
            uia_enabled=False,
            vision_recommended=False,
            local_vision_status={"configured": True, "enabled": True},
            runtime_policy={
                "runtime_profile": "standard",
                "allowed_tiers": ["observe", "interact"],
            },
        )
        self.assertEqual(
            state["states"]["desktop.uia.semantic_click"]["availability"],
            "unavailable",
        )
        self.assertEqual(
            state["states"]["desktop.action.expected_postconditions"]["availability"],
            "degraded",
        )
        self.assertEqual(
            state["states"]["desktop.action.expected_postconditions"]["reason_code"],
            "uia_backend_unavailable_partial_fallback",
        )
        self.assertEqual(
            state["states"]["desktop.action.bounded_observation_stabilization"]["availability"],
            "degraded",
        )

    def test_planner_routing_hints_prefer_verified_uia_and_never_auto_execute(self):
        policy = {
            "schema_version": 1,
            "runtime_profile": "elevated_game",
            "allowed_tiers": ["observe", "interact", "elevated_input"],
        }
        state = desktop_capability_state(
            semantic_source="uia",
            uia_enabled=True,
            vision_recommended=False,
            local_vision_status={"configured": True, "enabled": True},
            runtime_policy=policy,
        )
        first = desktop_planner_routing_hints(capability_state=state, runtime_policy=policy)
        second = desktop_planner_routing_hints(capability_state=state, runtime_policy=policy)

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], PLANNER_ROUTING_SCHEMA_VERSION)
        self.assertEqual(first["bridge_version"], BRIDGE_VERSION)
        self.assertTrue(first["advisory_only"])
        self.assertTrue(first["planner_owns_final_selection"])
        self.assertFalse(first["bridge_auto_executes"])
        self.assertFalse(first["automatic_fallback_execution"])
        self.assertFalse(first["permission_bypass_allowed"])
        self.assertFalse(first["tool_catalog_authoritative"])
        self.assertEqual(first["summary"], {"ready": 6, "degraded": 0, "blocked": 0, "total": 6})
        self.assertEqual(first["routes"]["perception"]["preferred_strategy"], "uia_semantic_first")
        self.assertEqual(first["routes"]["semantic_action"]["preferred_strategy"], "verified_uia_single_action")
        self.assertIn("no_automatic_retry", first["routes"]["semantic_action"]["constraints"])
        self.assertEqual(first["routes"]["text_input"]["preferred_strategy"], "verified_uia_text")
        self.assertEqual(first["routes"]["game_input"]["status"], "ready")

    def test_planner_routing_hints_block_game_input_in_standard_without_policy_bypass(self):
        policy = {
            "schema_version": 1,
            "runtime_profile": "standard",
            "allowed_tiers": ["observe", "interact"],
        }
        state = desktop_capability_state(
            semantic_source="uia",
            uia_enabled=True,
            vision_recommended=False,
            local_vision_status={"configured": True, "enabled": True},
            runtime_policy=policy,
        )
        hints = desktop_planner_routing_hints(capability_state=state, runtime_policy=policy)

        self.assertEqual(hints["summary"], {"ready": 5, "degraded": 0, "blocked": 1, "total": 6})
        game = hints["routes"]["game_input"]
        self.assertEqual(game["status"], "blocked")
        self.assertEqual(game["reason_code"], "elevated_input_permission_denied")
        self.assertEqual(game["fallbacks"], [])
        self.assertIn("permission_bypass_forbidden", game["constraints"])
        self.assertIn("do_not_fallback_to_normal_keyboard_to_bypass_policy", game["constraints"])

    def test_planner_routing_hints_omit_currently_unusable_fallbacks(self):
        policy = {
            "schema_version": 1,
            "runtime_profile": "standard",
            "allowed_tiers": ["observe", "interact"],
        }
        state = desktop_capability_state(
            semantic_source="uia",
            uia_enabled=True,
            vision_recommended=False,
            local_vision_status={"configured": False, "enabled": False},
            runtime_policy=policy,
        )
        hints = desktop_planner_routing_hints(capability_state=state, runtime_policy=policy)

        perception_fallbacks = hints["routes"]["perception"]["fallbacks"]
        self.assertEqual([item["strategy"] for item in perception_fallbacks], ["screenshot_reasoning"])
        self.assertNotIn(
            "desktop.local_vision_fallback",
            [cap for item in perception_fallbacks for cap in item["capability_steps"]],
        )

    def test_planner_routing_hints_degrade_safely_on_sparse_observe_only_surface(self):
        policy = {
            "schema_version": 1,
            "runtime_profile": "observe_only",
            "allowed_tiers": ["observe"],
        }
        state = desktop_capability_state(
            semantic_source="sparse",
            uia_enabled=True,
            vision_recommended=True,
            local_vision_status={"configured": False, "enabled": False},
            runtime_policy=policy,
        )
        hints = desktop_planner_routing_hints(capability_state=state, runtime_policy=policy)

        self.assertEqual(hints["summary"], {"ready": 1, "degraded": 2, "blocked": 3, "total": 6})
        self.assertEqual(hints["routes"]["perception"]["preferred_strategy"], "screenshot_reasoning")
        self.assertEqual(hints["routes"]["perception"]["status"], "degraded")
        self.assertEqual(hints["routes"]["semantic_action"]["status"], "blocked")
        self.assertEqual(hints["routes"]["text_input"]["status"], "blocked")
        self.assertEqual(hints["routes"]["verification"]["preferred_strategy"], "state_change_only")
        self.assertEqual(hints["routes"]["verification"]["status"], "degraded")
        self.assertEqual(hints["routes"]["observability"]["status"], "ready")
        self.assertEqual(hints["routes"]["game_input"]["status"], "blocked")

    def test_virtual_point_validation_supports_negative_monitor_coordinates(self):
        bridge = FakeDesktopBridge()
        self.assertEqual(bridge._validate_point(-100, 100), (-100, 100))
        self.assertEqual(bridge._validate_point(1919, 1079), (1919, 1079))
        with self.assertRaises(DesktopBridgeError):
            bridge._validate_point(-1921, 100)
        with self.assertRaises(DesktopBridgeError):
            bridge._validate_point(1920, 100)

    def test_window_region_clamps_invisible_frame_margins(self):
        bridge = FakeDesktopBridge()
        self.assertEqual(
            bridge.clamp_region_to_virtual_screen(-1930, -8, 1930, 1088),
            (-1920, 0, 1920, 1080),
        )
        with self.assertRaises(DesktopBridgeError):
            bridge.clamp_region_to_virtual_screen(3000, 0, 3100, 100)

    def test_guarded_relative_point_stays_inside_active_window(self):
        bridge = FakeGuardedBridge()
        window, x, y = bridge.active_window_point(0.5, 0.5, "Notepad")
        self.assertEqual(window.title, "Notes - Notepad")
        self.assertEqual((x, y), (600, 400))
        _, x0, y0 = bridge.active_window_point(0.0, 0.0, "Notes")
        self.assertEqual((x0, y0), (100, 100))
        _, x1, y1 = bridge.active_window_point(1.0, 1.0, "Notepad")
        self.assertEqual((x1, y1), (1099, 699))
        with self.assertRaises(DesktopBridgeError):
            bridge.active_window_point(0.5, 0.5, "Chrome")
        with self.assertRaises(DesktopBridgeError):
            bridge.active_window_point(1.1, 0.5, "Notepad")

    def test_guarded_actions_require_expected_window_title(self):
        bridge = FakeGuardedBridge()
        click_result = bridge.click_active_window_relative(0.25, 0.25, "Notepad")
        self.assertEqual(click_result["window"], "Notes - Notepad")
        self.assertEqual(bridge.events[0], ("click", 350, 250, "left", 1))

        type_result = bridge.type_active_window_text("hello", "Notes")
        self.assertEqual(type_result["characters"], 5)
        self.assertEqual(bridge.events[1], ("type", "hello"))

        key_result = bridge.press_active_window_key("ENTER", "Notepad")
        self.assertEqual(key_result["key"], "ENTER")
        self.assertEqual(bridge.events[2:], [("key", SAFE_KEYS["ENTER"], True), ("key", SAFE_KEYS["ENTER"], False)])

    def test_focus_window_success_completes_operation_trace(self):
        reset_action_audit_for_tests()
        bridge = FakeFocusBridge()
        with (
            patch("desktop_bridge.win32gui.GetForegroundWindow", return_value=0),
            patch("desktop_bridge.win32gui.ShowWindow"),
            patch("desktop_bridge.win32gui.BringWindowToTop"),
            patch("desktop_bridge.win32gui.SetForegroundWindow") as set_foreground,
            patch("desktop_bridge.win32api.GetCurrentThreadId", return_value=7),
            patch(
                "desktop_bridge.win32process.GetWindowThreadProcessId",
                return_value=(7, 99),
            ),
            patch("desktop_bridge.time.sleep"),
        ):
            result = bridge.focus_window(42)

        set_foreground.assert_called_once_with(42)
        trace = bridge.operation_trace(result["operation_id"])
        self.assertTrue(trace["complete"])
        self.assertEqual(trace["operation_root_action"], "focus_window")
        self.assertEqual(trace["summary"]["permission_decision_count"], 1)
        self.assertEqual(trace["summary"]["action_result_count"], 1)
        self.assertEqual(trace["summary"]["final_outcome"], "succeeded")
        self.assertFalse(trace["summary"]["retry_performed"])

    def test_ordinary_text_action_completes_trace_without_logging_content(self):
        reset_action_audit_for_tests()
        sensitive_text = "ordinary-text-must-not-enter-audit-9471"
        bridge = FakeGuardedBridge()
        result = bridge.type_active_window_text(sensitive_text, "Notepad")

        trace = bridge.operation_trace(result["operation_id"])
        audit = bridge.recent_action_audit(limit=5)
        self.assertTrue(trace["complete"])
        self.assertEqual(trace["summary"]["final_outcome"], "succeeded")
        self.assertEqual(trace["summary"]["action_result_count"], 1)
        completion = trace["action_results"][0]
        self.assertEqual(completion["action"], "type_active_window_text")
        self.assertTrue(completion["input_metadata"]["metadata_only"])
        self.assertFalse(completion["input_metadata"]["content_logged"])
        self.assertNotIn(sensitive_text, repr(trace))
        self.assertNotIn(sensitive_text, repr(audit))

    def test_ordinary_safe_key_completes_trace_without_logging_key_content(self):
        reset_action_audit_for_tests()
        bridge = FakeGuardedBridge()
        result = bridge.press_active_window_key("ENTER", "Notepad")

        trace = bridge.operation_trace(result["operation_id"])
        self.assertTrue(trace["complete"])
        self.assertEqual(trace["summary"]["final_outcome"], "succeeded")
        self.assertEqual(trace["summary"]["action_result_count"], 1)
        self.assertNotIn("ENTER", repr(trace))

    def test_ordinary_action_failure_completes_trace_without_logging_input(self):
        reset_action_audit_for_tests()
        sensitive_key = "PRIVATE_KEY_CONTENT_9471"
        bridge = FakeGuardedBridge()
        with self.assertRaises(DesktopBridgeError):
            bridge.press_active_window_key(sensitive_key, "Notepad")

        audit = bridge.recent_action_audit(limit=5)
        self.assertEqual(audit["returned_count"], 1)
        operation_id = audit["entries"][0]["operation_id"]
        trace = bridge.operation_trace(operation_id)
        self.assertTrue(trace["complete"])
        self.assertEqual(trace["summary"]["final_outcome"], "refused")
        self.assertEqual(trace["summary"]["action_result_count"], 1)
        completion = trace["action_results"][0]
        self.assertEqual(completion["effect_status"], "not_confirmed_after_failure")
        self.assertEqual(completion["failure"]["type"], "DesktopBridgeError")
        self.assertFalse(completion["failure"]["message_logged"])
        self.assertNotIn(sensitive_key, repr(trace))

    def test_permissionless_release_completion_preserves_emergency_authority(self):
        reset_action_audit_for_tests()
        bridge = FakeGameBridge()
        result = bridge.release_game_keys()

        trace = bridge.operation_trace(result["operation_id"])
        self.assertTrue(trace["complete"])
        self.assertFalse(trace["summary"]["permission_decision_required"])
        self.assertEqual(trace["summary"]["permission_decision_count"], 0)
        self.assertEqual(trace["summary"]["action_result_count"], 1)
        self.assertEqual(trace["summary"]["final_outcome"], "succeeded")

        with self.assertRaises(DesktopBridgeError):
            bridge.type_active_window_text("x", "__DESKTOPBRIDGE_TEST_NEVER_MATCH__")
        with self.assertRaises(DesktopBridgeError):
            bridge.press_active_window_key("DELETE", "Notepad")

    def test_uia_semantic_click_requires_unique_safe_match(self):
        bridge = FakeUIABridge()
        result = bridge.click_active_window_uia_element(
            "Notepad",
            name="Search",
            control_type="button",
        )
        self.assertEqual(result["action"], "click_active_window_uia_element")
        self.assertEqual(bridge.events[0], ("click", 230, 170, "left", 1))
        self.assertEqual(result["matched_element"]["name"], "Search")

        with self.assertRaises(DesktopBridgeError):
            bridge.click_active_window_uia_element("Notepad", name="Close", control_type="button")

        duplicate = list(bridge.uia_elements) + [dict(bridge.uia_elements[0], automation_id="search-button-2")]
        ambiguous = FakeUIABridge(duplicate)
        with self.assertRaises(DesktopBridgeError):
            ambiguous.click_active_window_uia_element("Notepad", name="Search", control_type="button")

    def test_uia_semantic_text_input_rejects_passwords_and_can_replace(self):
        bridge = FakeUIABridge()
        result = bridge.type_active_window_uia_text(
            "hello",
            "Notepad",
            name="Address and search bar",
            replace_existing=True,
        )
        self.assertEqual(result["action"], "type_active_window_uia_text")
        self.assertTrue(result["keyboard_focus_verified"])
        self.assertEqual(
            bridge.events,
            [
                ("click", 550, 140, "left", 1),
                ("hotkey", "CTRL+A"),
                ("type", "hello"),
            ],
        )

        password = FakeUIABridge(
            [
                {
                    "name": "Password",
                    "control_type": "edit",
                    "automation_id": "password",
                    "rect": [300, 200, 700, 240],
                    "enabled": True,
                    "offscreen": False,
                    "is_password": True,
                    "depth": 4,
                    "actionable": True,
                }
            ]
        )
        with self.assertRaises(DesktopBridgeError):
            password.type_active_window_uia_text("secret", "Notepad", name="Password")

        unfocused = FakeUIABridge(
            [
                {
                    "name": "Editor",
                    "control_type": "edit",
                    "automation_id": "editor",
                    "class_name": "",
                    "framework_id": "Chrome",
                    "rect": [300, 200, 700, 240],
                    "enabled": True,
                    "offscreen": False,
                    "is_password": False,
                    "has_keyboard_focus": False,
                    "keyboard_focusable": True,
                    "depth": 4,
                    "actionable": True,
                }
            ]
        )
        with self.assertRaisesRegex(DesktopBridgeError, "did not receive keyboard focus"):
            unfocused.type_active_window_uia_text("should-not-type", "Notepad", name="Editor")
        self.assertEqual(unfocused.events, [("click", 500, 220, "left", 1)])

    def test_secure_secret_input_can_target_password_field_without_logging_secret(self):
        reset_action_audit_for_tests()
        secret = "dummy-test-never-log-this-value"
        bridge = FakeUIABridge(
            [
                {
                    "name": "API key",
                    "control_type": "edit",
                    "automation_id": "api-key",
                    "rect": [300, 200, 700, 240],
                    "enabled": True,
                    "offscreen": False,
                    "is_password": True,
                    "has_keyboard_focus": True,
                    "keyboard_focusable": True,
                    "depth": 4,
                    "actionable": True,
                }
            ]
        )
        result = bridge.type_secret_into_active_window_uia(
            secret,
            "openai_runtime",
            "Notepad",
            name="API key",
            replace_existing=True,
        )
        self.assertEqual(result["action"], "type_secret_alias_into_active_window_uia")
        self.assertFalse(result["secret_value_exposed"])
        self.assertTrue(result["keyboard_focus_verified"])
        self.assertIn(("type", secret), bridge.events)
        serialized_result = repr(result)
        self.assertNotIn(secret, serialized_result)
        audit = bridge.recent_action_audit(limit=10)
        self.assertNotIn(secret, repr(audit))
        self.assertIn("openai_runtime", repr(audit))
        self.assertIn("password_field", repr(audit))

    def test_verify_state_change_compares_semantic_visual_and_window_identity(self):
        bridge = FakeStateBridge(
            {
                "active_window": {"hwnd": 10, "title": "Notes - Notepad"},
                "semantic_signature": "bbbbbbbbbbbbbbbbbbbbbbbb",
                "visual_dhash": "0000000000000003",
                "semantic_source": "uia",
                "uia_actionable_count": 7,
                "control_count": 2,
            }
        )
        result = bridge.verify_state_change(
            previous_semantic_signature="aaaaaaaaaaaaaaaaaaaaaaaa",
            previous_visual_dhash="0000000000000000",
            previous_window_hwnd=10,
            previous_window_title="Notes - Notepad",
        )
        self.assertTrue(result["state_change_detected"])
        self.assertTrue(result["semantic_changed"])
        self.assertTrue(result["visual_changed"])
        self.assertFalse(result["visual_change_confident"])
        self.assertEqual(result["visual_hamming_distance"], 2)
        self.assertEqual(result["visual_hamming_threshold"], 8)
        self.assertFalse(result["window_identity_changed"])
        self.assertEqual(result["current"]["semantic_source"], "uia")

    def test_verify_state_change_ignores_small_visual_only_hover_noise(self):
        bridge = FakeStateBridge(
            {
                "active_window": {"hwnd": 10, "title": "Notes - Notepad"},
                "semantic_signature": "aaaaaaaaaaaaaaaaaaaaaaaa",
                "visual_dhash": "000000000000001f",
                "semantic_source": "uia",
                "uia_actionable_count": 3,
                "control_count": 1,
            }
        )
        result = bridge.verify_state_change(
            previous_semantic_signature="aaaaaaaaaaaaaaaaaaaaaaaa",
            previous_visual_dhash="0000000000000000",
            previous_window_hwnd=10,
            previous_window_title="Notes - Notepad",
        )
        self.assertFalse(result["state_change_detected"])
        self.assertTrue(result["visual_changed"])
        self.assertFalse(result["visual_change_confident"])
        self.assertEqual(result["visual_hamming_distance"], 5)

    def test_verify_state_change_accepts_large_visual_only_change(self):
        bridge = FakeStateBridge(
            {
                "active_window": {"hwnd": 10, "title": "Notes - Notepad"},
                "semantic_signature": "aaaaaaaaaaaaaaaaaaaaaaaa",
                "visual_dhash": "00000000000000ff",
                "semantic_source": "uia",
                "uia_actionable_count": 3,
                "control_count": 1,
            }
        )
        result = bridge.verify_state_change(
            previous_semantic_signature="aaaaaaaaaaaaaaaaaaaaaaaa",
            previous_visual_dhash="0000000000000000",
            previous_window_hwnd=10,
            previous_window_title="Notes - Notepad",
        )
        self.assertTrue(result["state_change_detected"])
        self.assertTrue(result["visual_change_confident"])
        self.assertEqual(result["visual_hamming_distance"], 8)

    def test_verify_state_change_can_confirm_unchanged_state(self):
        bridge = FakeStateBridge(
            {
                "active_window": {"hwnd": 10, "title": "Notes - Notepad"},
                "semantic_signature": "aaaaaaaaaaaaaaaaaaaaaaaa",
                "visual_dhash": "0000000000000000",
                "semantic_source": "uia",
                "uia_actionable_count": 3,
                "control_count": 1,
            }
        )
        result = bridge.verify_state_change(
            previous_semantic_signature="aaaaaaaaaaaaaaaaaaaaaaaa",
            previous_visual_dhash="0000000000000000",
            previous_window_hwnd=10,
            previous_window_title="Notes - Notepad",
        )
        self.assertFalse(result["state_change_detected"])
        self.assertFalse(result["semantic_changed"])
        self.assertFalse(result["visual_changed"])
        self.assertEqual(result["visual_hamming_distance"], 0)

    def test_verification_policy_modes_are_bounded_and_deterministic(self):
        verification = {
            "state_change_detected": True,
            "semantic_changed": True,
            "window_identity_changed": False,
            "visual_change_confident": False,
        }
        self.assertTrue(DesktopBridge.evaluate_verification_policy(verification, "any_confident_change")["policy_passed"])
        self.assertTrue(DesktopBridge.evaluate_verification_policy(verification, "semantic_or_window")["policy_passed"])
        self.assertTrue(DesktopBridge.evaluate_verification_policy(verification, "semantic_only")["policy_passed"])
        self.assertFalse(DesktopBridge.evaluate_verification_policy(verification, "window_only")["policy_passed"])
        self.assertFalse(DesktopBridge.evaluate_verification_policy(verification, "visual_only")["policy_passed"])
        with self.assertRaises(DesktopBridgeError):
            DesktopBridge.evaluate_verification_policy(verification, "anything_goes")

    def test_expected_postconditions_support_element_presence_and_window_title(self):
        bridge = FakeUIABridge()
        result = bridge.evaluate_expected_postconditions(
            expected_element_name="Search",
            expected_element_control_type="button",
            expected_window_title_contains="Notepad",
        )
        self.assertTrue(result["configured"])
        self.assertTrue(result["postconditions_passed"])
        self.assertEqual(len(result["checks"]), 2)
        self.assertTrue(result["checks"][0]["expected_present"])
        self.assertTrue(result["checks"][0]["observed_present"])

        chromium_heading = FakeUIABridge(elements=[
            {
                "name": "Yunkai AI Hub",
                "control_type": "text",
                "aria_role": "heading",
                "automation_id": "",
                "class_name": "",
                "framework_id": "Chrome",
                "rect": [200, 150, 460, 190],
                "enabled": True,
                "offscreen": False,
                "is_password": False,
                "has_keyboard_focus": False,
                "keyboard_focusable": False,
                "depth": 5,
                "actionable": False,
            },
        ])
        heading = chromium_heading.evaluate_expected_postconditions(
            expected_element_name="Yunkai AI Hub",
            expected_element_control_type="heading",
        )
        self.assertTrue(heading["postconditions_passed"])
        self.assertTrue(heading["checks"][0]["observed_present"])

        missing = bridge.evaluate_expected_postconditions(
            expected_element_name="Missing",
            expected_element_control_type="button",
        )
        self.assertFalse(missing["postconditions_passed"])

        absent = bridge.evaluate_expected_postconditions(
            expected_element_name="Missing",
            expected_element_control_type="button",
            expected_element_present=False,
        )
        self.assertTrue(absent["postconditions_passed"])
        self.assertTrue(absent["checks"][0]["absence_proven"])

        with self.assertRaises(DesktopBridgeError):
            bridge.evaluate_expected_postconditions(expected_element_present=False)

    def test_expected_postcondition_absence_is_not_proven_by_truncated_tree(self):
        bridge = FakeTruncatedUIABridge()
        result = bridge.evaluate_expected_postconditions(
            expected_element_name="Missing",
            expected_element_control_type="button",
            expected_element_present=False,
        )
        self.assertFalse(result["postconditions_passed"])
        self.assertTrue(result["checks"][0]["tree_truncated"])
        self.assertFalse(result["checks"][0]["absence_proven"])

    def test_expected_postcondition_is_an_and_gate_after_verification_policy(self):
        reset_action_audit_for_tests()
        bridge = FakeTransactionalBridge(changed=True, postconditions_passed=False)
        result = bridge.click_active_window_uia_element_verified(
            "Notepad",
            name="Save",
            control_type="button",
            settle_ms=50,
            expected_post_element_name="Saved",
            expected_post_element_control_type="text",
        )
        self.assertTrue(result["policy"]["policy_passed"])
        self.assertFalse(result["postconditions"]["postconditions_passed"])
        self.assertFalse(result["verification_passed"])
        self.assertEqual(result["verification_contract"]["decision"], "fail")
        self.assertTrue(result["verification_contract"]["policy_passed"])
        self.assertFalse(result["verification_contract"]["postconditions_passed"])
        self.assertEqual(result["verification_contract"]["observation"]["attempts"], 4)
        self.assertFalse(result["verification_contract"]["observation"]["action_retry_performed"])
        self.assertEqual(result["audit"]["outcome"], "verification_failed")
        event_names = [event[0] for event in bridge.events]
        self.assertEqual(event_names.count("click"), 1)
        self.assertEqual(event_names.count("verify"), 4)
        self.assertEqual(event_names.count("postcondition"), 4)

    def test_delayed_post_action_observation_can_stabilize_without_retry(self):
        reset_action_audit_for_tests()
        bridge = FakeDelayedTransactionalBridge()
        result = bridge.click_active_window_uia_element_verified(
            "Notepad",
            name="Save",
            control_type="button",
            settle_ms=50,
            verification_policy="semantic_only",
            expected_post_element_name="Saved",
            expected_post_element_control_type="text",
        )
        self.assertTrue(result["verification_passed"])
        self.assertEqual(result["verification_contract"]["decision"], "pass")
        self.assertEqual(result["verification_contract"]["observation"]["attempts"], 2)
        self.assertTrue(result["verification_contract"]["observation"]["stabilized_after_initial_read"])
        self.assertFalse(result["verification_contract"]["observation"]["action_retry_performed"])
        self.assertFalse(result["retry_performed"])
        event_names = [event[0] for event in bridge.events]
        self.assertEqual(event_names.count("click"), 1)
        self.assertEqual(event_names.count("verify"), 2)
        self.assertEqual(event_names.count("postcondition"), 2)

    def test_invalid_expected_post_request_is_refused_before_action(self):
        reset_action_audit_for_tests()
        bridge = FakeTransactionalBridge(changed=True)
        with self.assertRaisesRegex(DesktopBridgeError, "requires an expected-post UIA selector"):
            bridge.click_active_window_uia_element_verified(
                "Notepad",
                name="Save",
                control_type="button",
                settle_ms=50,
                expected_post_element_present=False,
            )
        self.assertEqual(bridge.events, [])
        audit = bridge.recent_action_audit(limit=1)
        self.assertEqual(audit["entries"][0]["outcome"], "refused")
        self.assertFalse(audit["entries"][0]["retry_performed"])

    def test_verified_uia_click_is_single_attempt_and_returns_verification(self):
        reset_action_audit_for_tests()
        bridge = FakeTransactionalBridge(changed=True)
        result = bridge.click_active_window_uia_element_verified(
            "Notepad",
            name="Save",
            control_type="button",
            settle_ms=50,
        )
        self.assertTrue(result["verification_passed"])
        self.assertFalse(result["retry_performed"])
        self.assertEqual(result["verification_policy"], "any_confident_change")
        self.assertEqual(result["verification_contract"]["schema_version"], 1)
        self.assertEqual(result["verification_contract"]["decision"], "pass")
        self.assertFalse(result["verification_contract"]["retry_performed"])
        self.assertEqual(result["audit"]["outcome"], "verified")
        self.assertEqual(result["audit"]["verification_contract"]["schema_version"], 1)
        self.assertTrue(result["operation_id"].startswith("op_"))
        self.assertEqual(result["operation_root_action"], "click_active_window_uia_element_verified")
        self.assertEqual(result["operation_id"], result["audit"]["operation_id"])
        self.assertEqual(result["operation_id"], result["runtime_permission"]["operation_id"])
        self.assertEqual(result["operation_id"], result["verification"]["operation_id"])
        self.assertEqual([event[0] for event in bridge.events], ["click", "verify"])

    def test_fast_path_verified_click_reuses_fresh_context_and_keeps_verification(self):
        reset_action_audit_for_tests()
        bridge = FakeFastPathBridge()
        result = bridge.click_active_window_uia_element_verified(
            "Notepad",
            name="Generate",
            control_type="button",
            automation_id="generate-button",
            execution_mode="fast",
            settle_ms=250,
        )
        self.assertTrue(result["verification_passed"])
        self.assertEqual(result["execution_mode_requested"], "fast")
        self.assertEqual(result["execution_mode_used"], "fast")
        self.assertIsNone(result["fast_path_fallback_reason"])
        self.assertEqual(result["settle_ms_requested"], 250)
        self.assertEqual(result["settle_ms"], 100)
        self.assertEqual(bridge.fast_context_calls, [(300, False)])
        self.assertEqual(bridge.safe_semantic_click_calls, 0)
        self.assertEqual([event[0] for event in bridge.events], ["click", "verify"])
        self.assertEqual(bridge.events[1][1]["control_limit"], 300)
        self.assertEqual(result["action_result"]["target_source"], "fresh_fast_context")
        self.assertEqual(result["audit"]["input_metadata"]["execution_mode_used"], "fast")
        self.assertFalse(result["retry_performed"])

    def test_fast_path_sensitive_selector_falls_back_to_safe_path(self):
        reset_action_audit_for_tests()
        bridge = FakeFastPathBridge(target_name="Delete", target_automation_id="delete-button")
        result = bridge.click_active_window_uia_element_verified(
            "Notepad",
            name="Delete",

[Showing lines 1-1169 of 1585 (50.0KB limit). Use offset=1170 to continue.]