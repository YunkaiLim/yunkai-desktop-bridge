from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
import re
from typing import Any, Mapping


DEVICE_CONTRACT_ID = "yunkai.unified_device_contract"
DEVICE_CONTRACT_VERSION = "0.1"
DEVICE_CONTRACT_SCHEMA_VERSION = 1
CAPABILITY_MANIFEST_SCHEMA_VERSION = 1
CAPABILITY_STATE_SCHEMA_VERSION = 1
PERMISSION_STATE_SCHEMA_VERSION = 1
PLANNER_ROUTING_SCHEMA_VERSION = 1

CAPABILITY_AVAILABILITY_VALUES = ("available", "degraded", "unavailable")
PERMISSION_STATE_VALUES = ("allowed", "denied", "unknown")
ROUTING_STATUS_VALUES = ("ready", "degraded", "blocked")

_DEVICE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_CORE_SAFETY_INVARIANTS = {
    "planner_owns_final_selection": True,
    "bridge_auto_executes": False,
    "automatic_fallback_execution": False,
    "permission_bypass_allowed": False,
    "contract_grants_action_authority": False,
}


class DeviceContractError(ValueError):
    """Raised when a Unified Device Contract payload fails closed."""


def _non_empty_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise DeviceContractError(f"{field} must be a non-empty string.")
    return text


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DeviceContractError(f"{field} must be an object.")
    return deepcopy(dict(value))


def _schema_version(value: Any, expected: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise DeviceContractError(f"{field} must be schema version {expected}.")
    return value


def _required_bool(container: Mapping[str, Any], key: str, expected: bool, field: str) -> None:
    if container.get(key) is not expected:
        raise DeviceContractError(f"{field}.{key} must be {str(expected).lower()}.")


@dataclass(frozen=True)
class DeviceIdentity:
    """Adapter-neutral identity for one device endpoint."""

    device_id: str
    device_class: str
    platform: str
    display_name: str
    adapter_version: str

    def __post_init__(self) -> None:
        device_id = _non_empty_text(self.device_id, "device.device_id")
        device_class = _non_empty_text(self.device_class, "device.device_class")
        platform = _non_empty_text(self.platform, "device.platform")
        _non_empty_text(self.display_name, "device.display_name")
        _non_empty_text(self.adapter_version, "device.adapter_version")
        if not _DEVICE_ID_RE.fullmatch(device_id):
            raise DeviceContractError("device.device_id must be a stable lowercase dotted identifier.")
        if device_id.split(".", 1)[0] != device_class:
            raise DeviceContractError("device.device_id must begin with the device_class namespace.")
        if device_class != device_class.casefold() or platform != platform.casefold():
            raise DeviceContractError("device_class and platform must be lowercase identifiers.")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DeviceIdentity":
        data = _mapping(value, "device")
        return cls(
            device_id=_non_empty_text(data.get("device_id"), "device.device_id"),
            device_class=_non_empty_text(data.get("device_class"), "device.device_class"),
            platform=_non_empty_text(data.get("platform"), "device.platform"),
            display_name=_non_empty_text(data.get("display_name"), "device.display_name"),
            adapter_version=_non_empty_text(data.get("adapter_version"), "device.adapter_version"),
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "device_id": self.device_id,
            "device_class": self.device_class,
            "platform": self.platform,
            "display_name": self.display_name,
            "adapter_version": self.adapter_version,
        }


@dataclass(frozen=True)
class DeviceSnapshot:
    """Read-only validated model whose serialized form is the planner contract."""

    _payload: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DeviceSnapshot":
        return cls(validate_device_snapshot(value))

    def as_dict(self) -> dict[str, Any]:
        return deepcopy(dict(self._payload))


def _capabilities_from_manifest(
    manifest: Mapping[str, Any],
    identity: DeviceIdentity,
) -> tuple[dict[str, Any], dict[str, str]]:
    source = _mapping(manifest, "capability_manifest")
    _schema_version(
        source.get("schema_version"),
        CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "capability_manifest.schema_version",
    )

    groups_value = source.get("capability_groups", source.get("groups"))
    groups = _mapping(groups_value, "capability_manifest.capability_groups")
    capability_groups: dict[str, list[str]] = {}
    capability_to_group: dict[str, str] = {}
    expected_namespace = identity.device_class + "."

    for group_name, raw_ids in sorted(groups.items()):
        group = _non_empty_text(group_name, "capability_manifest group")
        if not isinstance(raw_ids, (list, tuple)):
            raise DeviceContractError(f"capability group {group} must be an array.")
        normalized_ids: list[str] = []
        for raw_id in raw_ids:
            capability_id = _non_empty_text(raw_id, f"capability_manifest.{group} capability")
            if not _CAPABILITY_ID_RE.fullmatch(capability_id):
                raise DeviceContractError(f"Malformed capability id: {capability_id}.")
            if not capability_id.startswith(expected_namespace):
                raise DeviceContractError(
                    f"Capability {capability_id} is outside the {identity.device_class} namespace."
                )
            if capability_id in capability_to_group:
                raise DeviceContractError(f"Duplicate capability id: {capability_id}.")
            capability_to_group[capability_id] = group
            normalized_ids.append(capability_id)
        capability_groups[group] = sorted(normalized_ids)

    if not capability_to_group:
        raise DeviceContractError("capability_manifest must declare at least one capability.")

    normalized = {
        "schema_version": CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "device_id": identity.device_id,
        "namespace": identity.device_class,
        "capability_groups": capability_groups,
        "capabilities": {
            capability_id: {"group": capability_to_group[capability_id]}
            for capability_id in sorted(capability_to_group)
        },
        "feature_flags": {
            str(key): bool(value)
            for key, value in sorted(dict(source.get("feature_flags") or {}).items())
        },
    }
    return normalized, capability_to_group


def split_legacy_capability_state(
    capability_state: Mapping[str, Any],
    *,
    device_id: str,
    capabilities: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split Desktop v1.4-style nested permission data into independent axes."""

    source = _mapping(capability_state, "capability_state")
    _schema_version(
        source.get("schema_version"),
        CAPABILITY_STATE_SCHEMA_VERSION,
        "capability_state.schema_version",
    )
    raw_states = _mapping(source.get("states"), "capability_state.states")
    if set(raw_states) != set(capabilities):
        raise DeviceContractError("capability_state entries must exactly match the manifest.")

    availability_states: dict[str, Any] = {}
    permission_states: dict[str, Any] = {}
    availability_counts = {value: 0 for value in CAPABILITY_AVAILABILITY_VALUES}
    permission_counts = {value: 0 for value in PERMISSION_STATE_VALUES}

    for capability_id in sorted(capabilities):
        raw = _mapping(raw_states[capability_id], f"capability_state.states.{capability_id}")
        permission = _mapping(raw.pop("permission", None), f"permission_state.states.{capability_id}")
        availability = str(raw.get("availability") or "")
        if availability not in CAPABILITY_AVAILABILITY_VALUES:
            raise DeviceContractError(f"Invalid availability for {capability_id}: {availability}.")
        permission_value = str(permission.get("state") or "")
        if permission_value not in PERMISSION_STATE_VALUES:
            raise DeviceContractError(f"Invalid permission state for {capability_id}: {permission_value}.")

        availability_states[capability_id] = {
            "availability": availability,
            "reason_code": _non_empty_text(
                raw.get("reason_code"), f"capability_state.states.{capability_id}.reason_code"
            ),
            "reason": _non_empty_text(
                raw.get("reason"), f"capability_state.states.{capability_id}.reason"
            ),
            "basis": _non_empty_text(
                raw.get("basis"), f"capability_state.states.{capability_id}.basis"
            ),
        }
        permission_states[capability_id] = {
            "required_tier": _non_empty_text(
                permission.get("required_tier"),
                f"permission_state.states.{capability_id}.required_tier",
            ),
            "state": permission_value,
            "runtime_profile": _non_empty_text(
                permission.get("runtime_profile"),
                f"permission_state.states.{capability_id}.runtime_profile",
            ),
        }
        availability_counts[availability] += 1
        permission_counts[permission_value] += 1

    availability_surface = {
        "schema_version": CAPABILITY_STATE_SCHEMA_VERSION,
        "device_id": device_id,
        "availability_values": list(CAPABILITY_AVAILABILITY_VALUES),
        "availability_independent_from_permission": True,
        "states": availability_states,
        "summary": {**availability_counts, "total": len(availability_states)},
        "adapter_context": {
            "probe_semantics": deepcopy(dict(source.get("probe_semantics") or {})),
            "surface": deepcopy(dict(source.get("surface") or {})),
        },
    }
    permission_surface = {
        "schema_version": PERMISSION_STATE_SCHEMA_VERSION,
        "device_id": device_id,
        "permission_values": list(PERMISSION_STATE_VALUES),
        "separate_from_availability": True,
        "states": permission_states,
        "summary": {**permission_counts, "total": len(permission_states)},
    }
    return availability_surface, permission_surface


def _normalize_capability_state(
    value: Mapping[str, Any],
    *,
    identity: DeviceIdentity,
    capabilities: Mapping[str, str],
) -> dict[str, Any]:
    state = _mapping(value, "capability_state")
    _schema_version(
        state.get("schema_version"),
        CAPABILITY_STATE_SCHEMA_VERSION,
        "capability_state.schema_version",
    )
    raw_states = _mapping(state.get("states"), "capability_state.states")
    if set(raw_states) != set(capabilities):
        raise DeviceContractError("capability_state entries must exactly match the manifest.")

    states: dict[str, Any] = {}
    counts = {item: 0 for item in CAPABILITY_AVAILABILITY_VALUES}
    for capability_id in sorted(capabilities):
        entry = _mapping(raw_states[capability_id], f"capability_state.states.{capability_id}")
        if "permission" in entry:
            raise DeviceContractError(
                "Unified capability_state cannot contain permission; use permission_state."
            )
        availability = str(entry.get("availability") or "")
        if availability not in CAPABILITY_AVAILABILITY_VALUES:
            raise DeviceContractError(f"Invalid availability for {capability_id}: {availability}.")
        states[capability_id] = {
            "availability": availability,
            "reason_code": _non_empty_text(
                entry.get("reason_code"), f"capability_state.states.{capability_id}.reason_code"
            ),
            "reason": _non_empty_text(
                entry.get("reason"), f"capability_state.states.{capability_id}.reason"
            ),
            "basis": _non_empty_text(
                entry.get("basis"), f"capability_state.states.{capability_id}.basis"
            ),
        }
        counts[availability] += 1

    return {
        "schema_version": CAPABILITY_STATE_SCHEMA_VERSION,
        "device_id": identity.device_id,
        "availability_values": list(CAPABILITY_AVAILABILITY_VALUES),
        "availability_independent_from_permission": True,
        "states": states,
        "summary": {**counts, "total": len(states)},
        "adapter_context": deepcopy(dict(state.get("adapter_context") or {})),
    }


def _normalize_permission_state(
    value: Mapping[str, Any],
    *,
    identity: DeviceIdentity,
    capabilities: Mapping[str, str],
) -> dict[str, Any]:
    permission = _mapping(value, "permission_state")
    _schema_version(
        permission.get("schema_version"),
        PERMISSION_STATE_SCHEMA_VERSION,
        "permission_state.schema_version",
    )
    raw_states = _mapping(permission.get("states"), "permission_state.states")
    if set(raw_states) != set(capabilities):
        raise DeviceContractError("permission_state entries must exactly match the manifest.")

    states: dict[str, Any] = {}
    counts = {item: 0 for item in PERMISSION_STATE_VALUES}
    for capability_id in sorted(capabilities):
        entry = _mapping(raw_states[capability_id], f"permission_state.states.{capability_id}")
        state = str(entry.get("state") or "")
        if state not in PERMISSION_STATE_VALUES:
            raise DeviceContractError(f"Invalid permission state for {capability_id}: {state}.")
        states[capability_id] = {
            "required_tier": _non_empty_text(
                entry.get("required_tier"),
                f"permission_state.states.{capability_id}.required_tier",
            ),
            "state": state,
            "runtime_profile": _non_empty_text(
                entry.get("runtime_profile"),
                f"permission_state.states.{capability_id}.runtime_profile",
            ),
        }
        counts[state] += 1

    return {
        "schema_version": PERMISSION_STATE_SCHEMA_VERSION,
        "device_id": identity.device_id,
        "permission_values": list(PERMISSION_STATE_VALUES),
        "separate_from_availability": True,
        "states": states,
        "summary": {**counts, "total": len(states)},
    }


def _normalize_runtime_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    policy = _mapping(value, "runtime_policy")
    _schema_version(policy.get("schema_version"), 1, "runtime_policy.schema_version")
    _non_empty_text(policy.get("runtime_profile"), "runtime_policy.runtime_profile")
    allowed_tiers = policy.get("allowed_tiers")
    if not isinstance(allowed_tiers, list) or not all(isinstance(item, str) for item in allowed_tiers):
        raise DeviceContractError("runtime_policy.allowed_tiers must be an array of strings.")
    if policy.get("model_selectable_profile") is not False or policy.get("self_escalation") is not False:
        raise DeviceContractError("runtime_policy must forbid model selection and self escalation.")
    return policy


def _normalize_routing(
    value: Mapping[str, Any],
    *,
    identity: DeviceIdentity,
) -> dict[str, Any]:
    routing = _mapping(value, "planner_routing_hints")
    _schema_version(
        routing.get("schema_version"),
        PLANNER_ROUTING_SCHEMA_VERSION,
        "planner_routing_hints.schema_version",
    )
    _required_bool(routing, "advisory_only", True, "planner_routing_hints")
    _required_bool(routing, "planner_owns_final_selection", True, "planner_routing_hints")
    _required_bool(routing, "bridge_auto_executes", False, "planner_routing_hints")
    _required_bool(routing, "automatic_fallback_execution", False, "planner_routing_hints")
    _required_bool(routing, "permission_bypass_allowed", False, "planner_routing_hints")
    routes = _mapping(routing.get("routes"), "planner_routing_hints.routes")
    normalized_routes: dict[str, Any] = {}
    counts = {item: 0 for item in ROUTING_STATUS_VALUES}
    for route_name, raw_entry in sorted(routes.items()):
        name = _non_empty_text(route_name, "planner route name")
        entry = _mapping(raw_entry, f"planner_routing_hints.routes.{name}")
        status = str(entry.get("status") or "")
        if status not in ROUTING_STATUS_VALUES:
            raise DeviceContractError(f"Invalid routing status for {name}: {status}.")
        capability_steps = entry.get("capability_steps")
        fallbacks = entry.get("fallbacks", [])
        constraints = entry.get("constraints", [])
        if not isinstance(capability_steps, list) or not all(
            isinstance(item, str) for item in capability_steps
        ):
            raise DeviceContractError(f"Route {name} capability_steps must be an array of strings.")
        if not isinstance(fallbacks, list) or not all(isinstance(item, Mapping) for item in fallbacks):
            raise DeviceContractError(f"Route {name} fallbacks must be an array of objects.")
        if not isinstance(constraints, list) or not all(isinstance(item, str) for item in constraints):
            raise DeviceContractError(f"Route {name} constraints must be an array of strings.")
        normalized_routes[name] = {
            "status": status,
            "preferred_strategy": _non_empty_text(
                entry.get("preferred_strategy"),
                f"planner_routing_hints.routes.{name}.preferred_strategy",
            ),
            "reason_code": _non_empty_text(
                entry.get("reason_code"),
                f"planner_routing_hints.routes.{name}.reason_code",
            ),
            "reason": _non_empty_text(
                entry.get("reason"), f"planner_routing_hints.routes.{name}.reason"
            ),
            "capability_steps": list(capability_steps),
            "fallbacks": [deepcopy(dict(item)) for item in fallbacks],
            "constraints": list(constraints),
        }
        counts[status] += 1

    return {
        "schema_version": PLANNER_ROUTING_SCHEMA_VERSION,
        "device_id": identity.device_id,
        "advisory_only": True,
        "planner_owns_final_selection": True,
        "bridge_auto_executes": False,
        "automatic_fallback_execution": False,
        "permission_bypass_allowed": False,
        "routing_inputs": deepcopy(dict(routing.get("routing_inputs") or {})),
        "summary": {**counts, "total": len(normalized_routes)},
        "routes": normalized_routes,
    }


def _validate_route_capabilities(snapshot: Mapping[str, Any]) -> None:
    capabilities = set(snapshot["capability_manifest"]["capabilities"])
    availability = snapshot["capability_state"]["states"]
    permissions = snapshot["permission_state"]["states"]
    routes = snapshot["planner_routing_hints"]["routes"]

    def require_known(capability_id: str, field: str) -> None:
        if capability_id not in capabilities:
            raise DeviceContractError(f"{field} references unknown capability {capability_id}.")

    for route_name, route in routes.items():
        steps = route["capability_steps"]
        if route["status"] == "blocked" and steps:
            raise DeviceContractError(f"Blocked route {route_name} cannot recommend capability steps.")
        for capability_id in steps:
            require_known(capability_id, f"route {route_name}")
            if availability[capability_id]["availability"] == "unavailable":
                raise DeviceContractError(
                    f"Route {route_name} cannot recommend unavailable capability {capability_id}."
                )
            if permissions[capability_id]["state"] != "allowed":
                raise DeviceContractError(
                    f"Route {route_name} cannot bypass permission for {capability_id}."
                )

        for fallback in route["fallbacks"]:
            fallback_steps = fallback.get("capability_steps")
            if not isinstance(fallback_steps, list) or not all(
                isinstance(item, str) for item in fallback_steps
            ):
                raise DeviceContractError(
                    f"Route {route_name} fallback capability_steps must be an array of strings."
                )
            for capability_id in fallback_steps:
                require_known(capability_id, f"route {route_name} fallback")
                if availability[capability_id]["availability"] != "available":
                    raise DeviceContractError(
                        f"Fallbacks require currently available capability {capability_id}."
                    )
                if permissions[capability_id]["state"] != "allowed":
                    raise DeviceContractError(
                        f"Fallbacks require permitted capability {capability_id}."
                    )


def validate_device_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a v0.1 snapshot and return a defensive JSON-safe copy."""

    snapshot = _mapping(value, "device_snapshot")
    _schema_version(
        snapshot.get("schema_version"),
        DEVICE_CONTRACT_SCHEMA_VERSION,
        "device_snapshot.schema_version",
    )
    contract = _mapping(snapshot.get("contract"), "device_snapshot.contract")
    if contract.get("id") != DEVICE_CONTRACT_ID or contract.get("version") != DEVICE_CONTRACT_VERSION:
        raise DeviceContractError("Unknown Unified Device Contract id or version.")
    _schema_version(
        contract.get("schema_version"),
        DEVICE_CONTRACT_SCHEMA_VERSION,
        "device_snapshot.contract.schema_version",
    )
    identity = DeviceIdentity.from_mapping(_mapping(snapshot.get("device"), "device_snapshot.device"))

    manifest, capabilities = _capabilities_from_manifest(
        _mapping(snapshot.get("capability_manifest"), "device_snapshot.capability_manifest"),
        identity,
    )
    state = _normalize_capability_state(
        _mapping(snapshot.get("capability_state"), "device_snapshot.capability_state"),
        identity=identity,
        capabilities=capabilities,
    )
    permission = _normalize_permission_state(
        _mapping(snapshot.get("permission_state"), "device_snapshot.permission_state"),
        identity=identity,
        capabilities=capabilities,
    )
    runtime_policy = _normalize_runtime_policy(
        _mapping(snapshot.get("runtime_policy"), "device_snapshot.runtime_policy")
    )
    routing = _normalize_routing(
        _mapping(snapshot.get("planner_routing_hints"), "device_snapshot.planner_routing_hints"),
        identity=identity,
    )

    allowed_tiers = set(runtime_policy["allowed_tiers"])
    runtime_profile = runtime_policy["runtime_profile"]
    for capability_id, entry in permission["states"].items():
        if entry["runtime_profile"] != runtime_profile:
            raise DeviceContractError(
                f"Permission profile mismatch for {capability_id}: {entry['runtime_profile']}."
            )
        permitted_by_tier = entry["required_tier"] in allowed_tiers
        if entry["state"] == "allowed" and not permitted_by_tier:
            raise DeviceContractError(f"Permission state for {capability_id} contradicts runtime policy.")
        if entry["state"] == "denied" and permitted_by_tier:
            raise DeviceContractError(f"Permission state for {capability_id} contradicts runtime policy.")

    adapter = _mapping(snapshot.get("adapter"), "device_snapshot.adapter")
    _non_empty_text(adapter.get("role"), "device_snapshot.adapter.role")
    _non_empty_text(adapter.get("transport"), "device_snapshot.adapter.transport")
    _required_bool(adapter, "transport_is_device_identity", False, "device_snapshot.adapter")

    versions = _mapping(snapshot.get("contract_versions"), "device_snapshot.contract_versions")
    required_versions = {
        "device_contract": DEVICE_CONTRACT_SCHEMA_VERSION,
        "capability_manifest": CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "capability_state": CAPABILITY_STATE_SCHEMA_VERSION,
        "permission_state": PERMISSION_STATE_SCHEMA_VERSION,
        "planner_routing": PLANNER_ROUTING_SCHEMA_VERSION,
    }
    for key, expected in required_versions.items():
        _schema_version(versions.get(key), expected, f"device_snapshot.contract_versions.{key}")

    verification = _mapping(snapshot.get("verification"), "device_snapshot.verification")
    if not isinstance(verification.get("supported"), bool):
        raise DeviceContractError("device_snapshot.verification.supported must be boolean.")
    if verification.get("automatic_retry") is not False:
        raise DeviceContractError("Verification metadata must forbid automatic retry.")

    observability = _mapping(snapshot.get("observability"), "device_snapshot.observability")
    for key in ("audit", "operation_trace"):
        metadata = _mapping(observability.get(key), f"device_snapshot.observability.{key}")
        if not isinstance(metadata.get("supported"), bool):
            raise DeviceContractError(f"observability.{key}.supported must be boolean.")

    safety = _mapping(snapshot.get("safety_invariants"), "device_snapshot.safety_invariants")
    for key, expected in _CORE_SAFETY_INVARIANTS.items():
        _required_bool(safety, key, expected, "device_snapshot.safety_invariants")

    normalized = {
        "schema_version": DEVICE_CONTRACT_SCHEMA_VERSION,
        "contract": {
            "id": DEVICE_CONTRACT_ID,
            "version": DEVICE_CONTRACT_VERSION,
            "schema_version": DEVICE_CONTRACT_SCHEMA_VERSION,
        },
        "device": identity.as_dict(),
        "adapter": adapter,
        "contract_versions": {str(key): value for key, value in sorted(versions.items())},
        "capability_manifest": manifest,
        "capability_state": state,
        "permission_state": permission,
        "runtime_policy": runtime_policy,
        "planner_routing_hints": routing,
        "verification": verification,
        "observability": observability,
        "safety_invariants": {str(key): value for key, value in sorted(safety.items())},
    }
    _validate_route_capabilities(normalized)
    try:
        json.dumps(normalized, ensure_ascii=False, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise DeviceContractError(f"Device snapshot is not JSON serializable: {exc}") from exc
    return deepcopy(normalized)


def build_device_snapshot(
    *,
    identity: DeviceIdentity | Mapping[str, Any],
    adapter: Mapping[str, Any],
    contract_versions: Mapping[str, Any],
    capability_manifest: Mapping[str, Any],
    capability_state: Mapping[str, Any],
    permission_state: Mapping[str, Any],
    runtime_policy: Mapping[str, Any],
    planner_routing_hints: Mapping[str, Any],
    verification: Mapping[str, Any],
    observability: Mapping[str, Any],
    safety_invariants: Mapping[str, Any],
) -> dict[str, Any]:
    """Build and validate a deterministic adapter-neutral DeviceSnapshot."""

    device = identity if isinstance(identity, DeviceIdentity) else DeviceIdentity.from_mapping(identity)
    versions = {
        "device_contract": DEVICE_CONTRACT_SCHEMA_VERSION,
        "capability_manifest": CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "capability_state": CAPABILITY_STATE_SCHEMA_VERSION,
        "permission_state": PERMISSION_STATE_SCHEMA_VERSION,
        "planner_routing": PLANNER_ROUTING_SCHEMA_VERSION,
        **dict(contract_versions),
    }
    safety = {**_CORE_SAFETY_INVARIANTS, **dict(safety_invariants)}
    payload = {
        "schema_version": DEVICE_CONTRACT_SCHEMA_VERSION,
        "contract": {
            "id": DEVICE_CONTRACT_ID,
            "version": DEVICE_CONTRACT_VERSION,
            "schema_version": DEVICE_CONTRACT_SCHEMA_VERSION,
        },
        "device": device.as_dict(),
        "adapter": deepcopy(dict(adapter)),
        "contract_versions": versions,
        "capability_manifest": deepcopy(dict(capability_manifest)),
        "capability_state": deepcopy(dict(capability_state)),
        "permission_state": deepcopy(dict(permission_state)),
        "runtime_policy": deepcopy(dict(runtime_policy)),
        "planner_routing_hints": deepcopy(dict(planner_routing_hints)),
        "verification": deepcopy(dict(verification)),
        "observability": deepcopy(dict(observability)),
        "safety_invariants": safety,
    }
    return validate_device_snapshot(payload)


def build_device_snapshot_from_legacy_state(
    *,
    identity: DeviceIdentity | Mapping[str, Any],
    adapter: Mapping[str, Any],
    contract_versions: Mapping[str, Any],
    capability_manifest: Mapping[str, Any],
    legacy_capability_state: Mapping[str, Any],
    runtime_policy: Mapping[str, Any],
    planner_routing_hints: Mapping[str, Any],
    verification: Mapping[str, Any],
    observability: Mapping[str, Any],
    safety_invariants: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility boundary for bridges whose legacy state embeds permission."""

    device = identity if isinstance(identity, DeviceIdentity) else DeviceIdentity.from_mapping(identity)
    normalized_manifest, capabilities = _capabilities_from_manifest(capability_manifest, device)
    capability_state, permission_state = split_legacy_capability_state(
        legacy_capability_state,
        device_id=device.device_id,
        capabilities=capabilities,
    )
    return build_device_snapshot(
        identity=device,
        adapter=adapter,
        contract_versions=contract_versions,
        capability_manifest=normalized_manifest,
        capability_state=capability_state,
        permission_state=permission_state,
        runtime_policy=runtime_policy,
        planner_routing_hints=planner_routing_hints,
        verification=verification,
        observability=observability,
        safety_invariants=safety_invariants,
    )


def device_contract_manifest() -> dict[str, Any]:
    """Return the static v0.1 contract handshake without any device state."""

    return {
        "id": DEVICE_CONTRACT_ID,
        "version": DEVICE_CONTRACT_VERSION,
        "schema_version": DEVICE_CONTRACT_SCHEMA_VERSION,
        "availability_values": list(CAPABILITY_AVAILABILITY_VALUES),
        "permission_values": list(PERMISSION_STATE_VALUES),
        "routing_values": list(ROUTING_STATUS_VALUES),
        "axes": [
            "capability_manifest",
            "capability_state",
            "permission_state",
            "planner_routing_hints",
        ],
        "side_effect_free": True,
        "json_serializable": True,
        "adapter_neutral": True,
        "model_neutral": True,
        "transport_neutral": True,
    }
