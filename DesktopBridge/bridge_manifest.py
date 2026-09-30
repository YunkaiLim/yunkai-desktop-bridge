from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from typing import Any

from action_audit import AUDIT_SCHEMA_VERSION, OPERATION_TRACE_SCHEMA_VERSION

_SHARED_ROOT = Path(__file__).resolve().parent.parent
if str(_SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(_SHARED_ROOT))

from yunkai_shared.device_contract import (  # noqa: E402 - shared root bootstrap
    CAPABILITY_MANIFEST_SCHEMA_VERSION,
    CAPABILITY_STATE_SCHEMA_VERSION,
    DEVICE_CONTRACT_SCHEMA_VERSION,
    PERMISSION_STATE_SCHEMA_VERSION,
    PLANNER_ROUTING_SCHEMA_VERSION,
    DeviceIdentity,
    build_device_snapshot_from_legacy_state,
)
from yunkai_shared.runtime_policy import RUNTIME_POLICY_SCHEMA_VERSION  # noqa: E402
from yunkai_shared.verification_contract import CONTRACT_SCHEMA_VERSION  # noqa: E402


BRIDGE_VERSION = "1.8.1"

_CAPABILITY_GROUPS: dict[str, tuple[str, ...]] = {
    "perception": (
        "desktop.screen.capture",
        "desktop.screen.region_capture",
        "desktop.window.active_inspect",
        "desktop.window.list",
        "desktop.uia.inspect",
        "desktop.fast_context",
        "desktop.local_vision_fallback",
    ),
    "interaction": (
        "desktop.window.focus",
        "desktop.mouse.move",
        "desktop.mouse.click",
        "desktop.mouse.drag",
        "desktop.mouse.scroll",
        "desktop.keyboard.type",
        "desktop.keyboard.safe_key",
        "desktop.keyboard.safe_hotkey",
        "desktop.uia.semantic_click",
        "desktop.uia.semantic_text",
        "desktop.secret_input.alias",
    ),
    "verification": (
        "desktop.state_change.verify",
        "desktop.action.verified_uia",
        "desktop.action.expected_postconditions",
        "desktop.action.bounded_observation_stabilization",
    ),
    "observability": (
        "desktop.audit.action",
        "desktop.audit.permission",
        "desktop.operation.correlation",
        "desktop.operation.trace",
        "desktop.operation.trace_stale_catalog_compat",
        "desktop.watchdog.status",
    ),
    "planning": (
        "desktop.planner.routing_hints",
    ),
    "experimental": (
        "desktop.game_input.elevated_experimental",
    ),
}

_FEATURE_FLAGS: dict[str, bool] = {
    "uia_semantics": True,
    "local_vision_fallback": True,
    "verified_uia_actions": True,
    "explicit_fast_path_verified_uia_click": True,
    "expected_post_predicates": True,
    "bounded_observation_stabilization": True,
    "automatic_action_retry": False,
    "operation_correlation": True,
    "operation_trace_full_query": True,
    "operation_trace_stale_catalog_compat": True,
    "dynamic_capability_manifest": True,
    "dynamic_capability_state": True,
    "dynamic_planner_routing_hints": True,
    "unified_device_contract": True,
    "watchdog_status_bridge": True,
    "dpapi_secret_alias_input": True,
    "remote_secret_value_upload": False,
    "secret_target_binding_required": True,
}

_CAPABILITY_REQUIRED_TIERS: dict[str, str] = {
    **{
        capability: "observe"
        for group in ("perception", "observability", "planning")
        for capability in _CAPABILITY_GROUPS[group]
    },
    **{
        capability: "interact"
        for capability in _CAPABILITY_GROUPS["interaction"]
    },
    "desktop.state_change.verify": "observe",
    "desktop.action.verified_uia": "interact",
    "desktop.action.expected_postconditions": "interact",
    "desktop.action.bounded_observation_stabilization": "interact",
    "desktop.game_input.elevated_experimental": "elevated_input",
}

_UIA_SURFACE_CAPABILITIES = {
    "desktop.uia.inspect",
    "desktop.uia.semantic_click",
    "desktop.uia.semantic_text",
    "desktop.action.verified_uia",
    "desktop.action.expected_postconditions",
    "desktop.action.bounded_observation_stabilization",
}

_UIA_PARTIAL_CAPABILITIES = {
    "desktop.action.expected_postconditions",
    "desktop.action.bounded_observation_stabilization",
}

_LOCAL_VISION_CAPABILITIES = {"desktop.local_vision_fallback"}

_SAFETY_INVARIANTS: dict[str, bool] = {
    "arbitrary_shell_exposed": False,
    "file_delete_exposed": False,
    "software_uninstall_exposed": False,
    "shutdown_reboot_exposed": False,
    "registry_modify_exposed": False,
    "raw_process_kill_exposed": False,
    "caller_selectable_runtime_profile": False,
    "caller_selectable_operation_id_for_actions": False,
    "remote_secret_value_exposed": False,
    "remote_secret_upload_exposed": False,
    "secret_target_binding_required": True,
}


def desktop_capability_manifest() -> dict[str, Any]:
    """Return the deterministic, side-effect-free DesktopBridge capability handshake."""
    manifest = {
        "schema_version": CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "bridge": {
            "id": "desktop.windows",
            "name": "Yunkai Desktop Bridge",
            "version": BRIDGE_VERSION,
            "device_class": "desktop",
            "platform": "windows",
        },
        "adapter": {
            "role": "development_debug_adapter",
            "transport": "mcp",
            "transport_is_device_identity": False,
            "tool_catalog_authoritative": False,
        },
        "contract_versions": {
            "device_contract": DEVICE_CONTRACT_SCHEMA_VERSION,
            "capability_manifest": CAPABILITY_MANIFEST_SCHEMA_VERSION,
            "capability_state": CAPABILITY_STATE_SCHEMA_VERSION,
            "permission_state": PERMISSION_STATE_SCHEMA_VERSION,
            "planner_routing": PLANNER_ROUTING_SCHEMA_VERSION,
            "verification": CONTRACT_SCHEMA_VERSION,
            "runtime_policy": RUNTIME_POLICY_SCHEMA_VERSION,
            "action_audit": AUDIT_SCHEMA_VERSION,
            "operation_trace": OPERATION_TRACE_SCHEMA_VERSION,
        },
        "capability_groups": {
            group: list(capabilities)
            for group, capabilities in _CAPABILITY_GROUPS.items()
        },
        "feature_flags": dict(_FEATURE_FLAGS),
        "discovery": {
            "source": "bridge_runtime_manifest",
            "available_via": "get_desktop_fast_context.context.capability_manifest",
            "state_available_via": "get_desktop_fast_context.context.capability_state",
            "routing_available_via": "get_desktop_fast_context.context.planner_routing_hints",
            "watchdog_status_available_via": "get_desktop_fast_context.context.watchdog_status",
            "requires_new_tool_schema": False,
            "schema_cache_tolerant": True,
            "runtime_should_reason_about_capabilities": True,
        },
        "permission_model": {
            "capabilities_are_permissions": False,
            "separate_runtime_policy": True,
            "runtime_policy_manifest_field": "runtime_policy",
            "caller_selectable_profile": False,
        },
        "safety_invariants": dict(_SAFETY_INVARIANTS),
    }
    return deepcopy(manifest)


def desktop_capability_state(
    *,
    semantic_source: str,
    uia_enabled: bool,
    vision_recommended: bool,
    local_vision_status: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> dict[str, Any]:
    """Return current capability availability and separate permission state.

    Availability describes whether the bridge and current desktop surface can use
    a capability. Permission describes whether the locally configured runtime
    profile allows that capability's required tier. The two axes are never
    collapsed into one status.
    """
    semantic_source = str(semantic_source or "sparse").strip().lower()
    if semantic_source not in {"uia", "win32", "sparse"}:
        semantic_source = "sparse"

    local_status = dict(local_vision_status or {})
    local_vision_configured = bool(local_status.get("configured"))
    local_vision_enabled = bool(local_status.get("enabled"))
    local_vision_error = str(local_status.get("error") or "").strip()
    allowed_tiers = {
        str(tier)
        for tier in runtime_policy.get("allowed_tiers", [])
    }

    states: dict[str, dict[str, Any]] = {}
    availability_counts = {"available": 0, "degraded": 0, "unavailable": 0}
    permission_denied_count = 0

    for group, capabilities in _CAPABILITY_GROUPS.items():
        for capability in capabilities:
            availability = "available"
            reason_code = "implemented"
            reason = "Bridge capability is implemented and current prerequisites are satisfied."
            basis = "bridge_runtime"

            if capability in _UIA_SURFACE_CAPABILITIES:
                basis = "current_surface"
                if not uia_enabled:
                    if capability in _UIA_PARTIAL_CAPABILITIES:
                        availability = "degraded"
                        reason_code = "uia_backend_unavailable_partial_fallback"
                        reason = (
                            "Windows UI Automation is unavailable, but non-UIA verification paths "
                            "such as foreground-window predicates remain usable."
                        )
                    else:
                        availability = "unavailable"
                        reason_code = "uia_backend_unavailable"
                        reason = "Windows UI Automation is unavailable for the current bridge process."
                elif semantic_source != "uia":
                    availability = "degraded"
                    reason_code = "uia_surface_sparse"
                    reason = (
                        "UI Automation is reachable, but the current foreground window is not "
                        "UIA-informative; semantic targeting may need Win32 or vision fallback."
                    )
                else:
                    reason_code = "uia_surface_informative"
                    reason = "UI Automation is available and informative for the current foreground window."

            if capability in _LOCAL_VISION_CAPABILITIES:
                basis = "configuration_only"
                if local_vision_error:
                    availability = "unavailable"
                    reason_code = "local_vision_configuration_error"
                    reason = "Local vision configuration is invalid; the fallback is not currently usable."
                elif not local_vision_configured or not local_vision_enabled:
                    availability = "unavailable"
                    reason_code = "local_vision_not_configured"
                    reason = "Local vision fallback is supported but not configured for this runtime."
                else:
                    reason_code = "local_vision_configured"
                    reason = "Local vision fallback is configured and enabled for this runtime."

            required_tier = _CAPABILITY_REQUIRED_TIERS[capability]
            permission_allowed = required_tier in allowed_tiers
            if not permission_allowed:
                permission_denied_count += 1

            availability_counts[availability] += 1
            states[capability] = {
                "group": group,
                "availability": availability,
                "reason_code": reason_code,
                "reason": reason,
                "basis": basis,
                "permission": {
                    "required_tier": required_tier,
                    "state": "allowed" if permission_allowed else "denied",
                    "runtime_profile": runtime_policy.get("runtime_profile"),
                },
            }

    return {
        "schema_version": CAPABILITY_STATE_SCHEMA_VERSION,
        "bridge_id": "desktop.windows",
        "bridge_version": BRIDGE_VERSION,
        "availability_values": ["available", "degraded", "unavailable"],
        "availability_independent_from_permission": True,
        "probe_semantics": {
            "external_health_checks_performed": False,
            "local_vision_availability_basis": "configuration_only",
            "uia_availability_basis": "current_surface",
        },
        "surface": {
            "semantic_source": semantic_source,
            "uia_enabled": bool(uia_enabled),
            "vision_recommended": bool(vision_recommended),
            "local_vision_configured": local_vision_configured,
            "local_vision_enabled": local_vision_enabled,
            "local_vision_error_present": bool(local_vision_error),
        },
        "summary": {
            **availability_counts,
            "total": sum(availability_counts.values()),
            "permission_denied": permission_denied_count,
        },
        "states": states,
    }


def desktop_planner_routing_hints(
    *,
    capability_state: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> dict[str, Any]:
    """Return deterministic, advisory-only planner routing hints.

    Routing may combine current availability with permission state to explain
    whether a path is presently executable, but it never mutates either source
    contract and never performs actions or automatic fallbacks.
    """
    states = dict(capability_state.get("states") or {})
    surface = dict(capability_state.get("surface") or {})
    runtime_profile = runtime_policy.get("runtime_profile")

    def entry(capability_id: str) -> dict[str, Any]:
        return dict(states.get(capability_id) or {})

    def availability(capability_id: str) -> str:
        value = str(entry(capability_id).get("availability") or "unavailable")
        return value if value in {"available", "degraded", "unavailable"} else "unavailable"

    def permission_state(capability_id: str) -> str:
        permission = dict(entry(capability_id).get("permission") or {})
        return "allowed" if permission.get("state") == "allowed" else "denied"

    def usable(capability_id: str) -> bool:
        return availability(capability_id) != "unavailable" and permission_state(capability_id) == "allowed"

    def fully_ready(capability_id: str) -> bool:
        return availability(capability_id) == "available" and permission_state(capability_id) == "allowed"

    def route(
        *,
        status: str,
        preferred_strategy: str,
        reason_code: str,
        reason: str,
        capabilities: list[str],
        fallbacks: list[dict[str, Any]] | None = None,
        constraints: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "preferred_strategy": preferred_strategy,
            "reason_code": reason_code,
            "reason": reason,
            "capability_steps": list(capabilities),
            "fallbacks": list(fallbacks or []),
            "constraints": list(constraints or []),
        }

    routes: dict[str, dict[str, Any]] = {}
    semantic_source = str(surface.get("semantic_source") or "sparse")

    if fully_ready("desktop.uia.inspect"):
        routes["perception"] = route(
            status="ready",
            preferred_strategy="uia_semantic_first",
            reason_code="uia_informative",
            reason="Current foreground surface is UIA-informative; prefer deterministic semantic perception before vision.",
            capabilities=["desktop.fast_context", "desktop.uia.inspect"],
            fallbacks=(
                ([{
                    "strategy": "local_vision_fallback",
                    "when": "semantic context becomes sparse",
                    "capability_steps": ["desktop.local_vision_fallback"],
                }] if usable("desktop.local_vision_fallback") else [])
                + ([{
                    "strategy": "screenshot_reasoning",
                    "when": "semantic and local-vision context are insufficient",
                    "capability_steps": ["desktop.screen.capture"],
                }] if usable("desktop.screen.capture") else [])
            ),
        )
    elif semantic_source == "win32" and usable("desktop.fast_context"):
        routes["perception"] = route(
            status="degraded",
            preferred_strategy="fast_context_win32_semantics",
            reason_code="uia_sparse_win32_informative",
            reason="UIA is not informative on the current surface, but Fast Context still exposes useful Win32 semantics.",
            capabilities=["desktop.fast_context"],
            fallbacks=(
                ([{
                    "strategy": "local_vision_fallback",
                    "when": "Win32 semantics are insufficient",
                    "capability_steps": ["desktop.local_vision_fallback"],
                }] if usable("desktop.local_vision_fallback") else [])
                + ([{
                    "strategy": "screenshot_reasoning",
                    "when": "semantic and local-vision context are insufficient",
                    "capability_steps": ["desktop.screen.capture"],
                }] if usable("desktop.screen.capture") else [])
            ),
        )
    elif usable("desktop.local_vision_fallback"):
        routes["perception"] = route(
            status="degraded",
            preferred_strategy="local_vision_after_sparse_semantics",
            reason_code="semantic_surface_sparse",
            reason="Deterministic semantic layers are sparse; use localhost vision as a perception fallback, not as system-state authority.",
            capabilities=["desktop.fast_context", "desktop.local_vision_fallback"],
            fallbacks=[
                {
                    "strategy": "screenshot_reasoning",
                    "when": "local vision is insufficient or fails",
                    "capability_steps": ["desktop.screen.capture"],
                }
            ],
            constraints=["vision_is_not_authoritative_for_window_identity"],
        )
    elif usable("desktop.screen.capture"):
        routes["perception"] = route(
            status="degraded",
            preferred_strategy="screenshot_reasoning",
            reason_code="semantic_and_local_vision_unavailable",
            reason="Semantic context is sparse and local vision is unavailable; fall back to screenshot reasoning.",
            capabilities=["desktop.fast_context", "desktop.screen.capture"],
            constraints=["prefer_read_only_observation_before_any_action"],
        )
    else:
        routes["perception"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="no_observation_path",
            reason="No permitted observation path is currently available.",
            capabilities=[],
        )

    verified_uia_ready = fully_ready("desktop.action.verified_uia") and fully_ready("desktop.uia.semantic_click")
    if verified_uia_ready:
        routes["semantic_action"] = route(
            status="ready",
            preferred_strategy="verified_uia_single_action",
            reason_code="verified_uia_ready",
            reason="Prefer one guarded semantic UIA action with deterministic verification and expected-post predicates.",
            capabilities=[
                "desktop.uia.semantic_click",
                "desktop.action.verified_uia",
                "desktop.action.expected_postconditions",
                "desktop.operation.correlation",
            ],
            fallbacks=([{
                "strategy": "trusted_coordinate_action_then_verify",
                "when": "UIA selector is unavailable or ambiguous but a trusted coordinate is known",
                "capability_steps": ["desktop.mouse.click", "desktop.state_change.verify"],
            }] if usable("desktop.mouse.click") and usable("desktop.state_change.verify") else []),
            constraints=["single_intended_action", "no_automatic_retry", "verify_before_replanning"],
        )
    elif usable("desktop.mouse.click") and usable("desktop.state_change.verify"):
        routes["semantic_action"] = route(
            status="degraded",
            preferred_strategy="trusted_coordinate_action_then_verify",
            reason_code="semantic_targeting_not_fully_ready",
            reason="Semantic action targeting is degraded or unavailable; only use a trusted coordinate with explicit post-action verification.",
            capabilities=["desktop.mouse.click", "desktop.state_change.verify"],
            constraints=["requires_trusted_coordinates", "single_intended_action", "no_automatic_retry", "verify_before_replanning"],
        )
    else:
        routes["semantic_action"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="interaction_path_not_permitted_or_available",
            reason="No permitted semantic or guarded coordinate interaction path is currently available.",
            capabilities=[],
            constraints=["permission_bypass_forbidden"],
        )

    if fully_ready("desktop.uia.semantic_text") and fully_ready("desktop.action.verified_uia"):
        routes["text_input"] = route(
            status="ready",
            preferred_strategy="verified_uia_text",
            reason_code="verified_uia_text_ready",
            reason="Prefer the focus-checked verified UIA text path for semantic text entry.",
            capabilities=["desktop.uia.semantic_text", "desktop.action.verified_uia", "desktop.state_change.verify"],
            fallbacks=([{
                "strategy": "guarded_window_text_then_verify",
                "when": "semantic edit targeting is unavailable but the foreground target and focus are independently trusted",
                "capability_steps": ["desktop.keyboard.type", "desktop.state_change.verify"],
            }] if usable("desktop.keyboard.type") and usable("desktop.state_change.verify") else []),
            constraints=["password_fields_refused", "focus_confirmation_required", "no_automatic_retry"],
        )
    elif usable("desktop.keyboard.type") and usable("desktop.state_change.verify"):
        routes["text_input"] = route(
            status="degraded",
            preferred_strategy="guarded_window_text_then_verify",
            reason_code="semantic_text_targeting_not_ready",
            reason="UIA text targeting is not fully ready; only use guarded window text when the intended focus is independently trusted.",
            capabilities=["desktop.keyboard.type", "desktop.state_change.verify"],
            constraints=["requires_trusted_foreground_and_focus", "no_automatic_retry", "verify_before_replanning"],
        )
    else:
        routes["text_input"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="text_input_path_not_permitted_or_available",
            reason="No permitted text-input path is currently available.",
            capabilities=[],
            constraints=["permission_bypass_forbidden"],
        )

    if usable("desktop.state_change.verify"):
        if fully_ready("desktop.action.expected_postconditions"):
            routes["verification"] = route(
                status="ready",
                preferred_strategy="state_change_plus_expected_postconditions",
                reason_code="full_verification_path_ready",
                reason="Use deterministic state-change verification plus action-specific expected-post predicates when available.",
                capabilities=["desktop.state_change.verify", "desktop.action.expected_postconditions"],
                constraints=["deterministic_state_is_authoritative", "verification_does_not_trigger_retry"],
            )
        else:
            routes["verification"] = route(
                status="degraded",
                preferred_strategy="state_change_only",
                reason_code="expected_postconditions_not_fully_ready",
                reason="Deterministic state-change verification remains usable, but expected-post coverage is degraded or not permitted.",
                capabilities=["desktop.state_change.verify"],
                constraints=["deterministic_state_is_authoritative", "verification_does_not_trigger_retry"],
            )
    else:
        routes["verification"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="verification_unavailable",
            reason="Deterministic state verification is not currently usable.",
            capabilities=[],
        )

    if fully_ready("desktop.operation.trace"):
        routes["observability"] = route(
            status="ready",
            preferred_strategy="operation_trace_then_audit",
            reason_code="full_trace_ready",
            reason="Prefer the correlated operation trace for one operation and use bounded audit history for broader recent context.",
            capabilities=["desktop.operation.trace", "desktop.audit.action", "desktop.audit.permission"],
            fallbacks=([{
                "strategy": "stale_catalog_trace_compat",
                "when": "the client cannot discover the full trace query tool",
                "capability_steps": ["desktop.operation.trace_stale_catalog_compat", "desktop.audit.action"],
            }] if usable("desktop.operation.trace_stale_catalog_compat") else []),
        )
    elif usable("desktop.operation.trace_stale_catalog_compat"):
        routes["observability"] = route(
            status="degraded",
            preferred_strategy="stale_catalog_trace_compat",
            reason_code="full_trace_query_not_ready",
            reason="Use compact recent operation traces through the audit compatibility path.",
            capabilities=["desktop.operation.trace_stale_catalog_compat", "desktop.audit.action", "desktop.audit.permission"],
        )
    else:
        routes["observability"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="observability_path_unavailable",
            reason="No correlated operation observability path is currently usable.",
            capabilities=[],
        )

    game_availability = availability("desktop.game_input.elevated_experimental")
    game_permission = permission_state("desktop.game_input.elevated_experimental")
    if game_availability != "unavailable" and game_permission == "allowed":
        routes["game_input"] = route(
            status="ready" if game_availability == "available" else "degraded",
            preferred_strategy="elevated_guarded_game_input",
            reason_code="elevated_game_input_ready",
            reason="Experimental game input is available and the current runtime profile permits elevated input.",
            capabilities=["desktop.game_input.elevated_experimental"],
            constraints=["foreground_game_guard_required", "no_permission_fallback", "no_system_level_shortcuts"],
        )
    elif game_permission == "denied":
        routes["game_input"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="elevated_input_permission_denied",
            reason="Game input capability exists, but the current runtime profile does not permit elevated input.",
            capabilities=[],
            constraints=["permission_bypass_forbidden", "do_not_fallback_to_normal_keyboard_to_bypass_policy"],
        )
    else:
        routes["game_input"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="game_input_unavailable",
            reason="Experimental game input is not currently available.",
            capabilities=[],
            constraints=["no_permission_fallback"],
        )

    status_counts = {"ready": 0, "degraded": 0, "blocked": 0}
    for item in routes.values():
        status_counts[item["status"]] += 1

    return {
        "schema_version": PLANNER_ROUTING_SCHEMA_VERSION,
        "bridge_id": "desktop.windows",
        "bridge_version": BRIDGE_VERSION,
        "advisory_only": True,
        "planner_owns_final_selection": True,
        "bridge_auto_executes": False,
        "automatic_fallback_execution": False,
        "permission_bypass_allowed": False,
        "tool_catalog_authoritative": False,
        "capability_ids_are_routing_contract": True,
        "routing_inputs": {
            "capability_state_schema_version": capability_state.get("schema_version"),
            "runtime_policy_schema_version": runtime_policy.get("schema_version"),
            "runtime_profile": runtime_profile,
            "semantic_source": semantic_source,
            "vision_recommended": bool(surface.get("vision_recommended")),
        },
        "summary": {
            **status_counts,
            "total": sum(status_counts.values()),
        },
        "routes": routes,
    }


def desktop_device_snapshot(
    *,
    capability_manifest: dict[str, Any],
    capability_state: dict[str, Any],
    planner_routing_hints: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> dict[str, Any]:
    """Adapt the stable Desktop v1.4 surfaces to Unified Device Contract v0.1.

    The legacy Desktop capability_state intentionally remains unchanged for
    existing clients. The shared compatibility boundary removes its nested
    permission objects and exposes them as a separate permission_state only
    inside the new DeviceSnapshot.
    """

    return build_device_snapshot_from_legacy_state(
        identity=DeviceIdentity(
            device_id="desktop.windows",
            device_class="desktop",
            platform="windows",
            display_name="Yunkai Desktop Bridge",
            adapter_version=BRIDGE_VERSION,
        ),
        adapter={
            "role": "reference_device_adapter",
            "transport": "mcp",
            "transport_is_device_identity": False,
            "tool_catalog_authoritative": False,
            "compatibility_source": "desktop_fast_context_v1.4",
        },
        contract_versions=capability_manifest["contract_versions"],
        capability_manifest=capability_manifest,
        legacy_capability_state=capability_state,
        runtime_policy=runtime_policy,
        planner_routing_hints=planner_routing_hints,
        verification={
            "supported": True,
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "expected_postconditions_supported": True,
            "bounded_observation_stabilization_supported": True,
            "verified_single_action_supported": True,
            "automatic_retry": False,
        },
        observability={
            "audit": {
                "supported": True,
                "schema_version": AUDIT_SCHEMA_VERSION,
                "storage": "memory_only_ring_buffer",
            },
            "operation_trace": {
                "supported": True,
                "schema_version": OPERATION_TRACE_SCHEMA_VERSION,
                "operation_correlation": True,
                "stale_catalog_compatibility": True,
            },
        },
        safety_invariants={
            **_SAFETY_INVARIANTS,
            "verified_uia_single_action": True,
            "expected_post_predicates": True,
            "bounded_observation_stabilization": True,
            "no_automatic_retry": True,
            "legacy_action_authority_unchanged": True,
        },
    )
