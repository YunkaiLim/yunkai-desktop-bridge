from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


CONTRACT_SCHEMA_VERSION = 1
VERIFICATION_POLICIES = frozenset(
    {
        "any_confident_change",
        "semantic_or_window",
        "semantic_only",
        "window_only",
        "visual_only",
    }
)

_POLICY_REASONS = {
    "any_confident_change": "semantic/surface change or confident visual change",
    "semantic_or_window": "semantic signature or surface identity change",
    "semantic_only": "semantic signature change",
    "window_only": "surface identity change",
    "visual_only": "confident visual change",
}


class VerificationContractError(ValueError):
    """Raised when a shared verification contract request is invalid."""


def normalize_verification_policy(value: str | None) -> str:
    policy = str(value or "any_confident_change").strip().casefold()
    if policy not in VERIFICATION_POLICIES:
        raise VerificationContractError(
            "Unsupported verification policy. Allowed: " + ", ".join(sorted(VERIFICATION_POLICIES))
        )
    return policy


def _normalized_signals(signals: Mapping[str, Any]) -> dict[str, bool]:
    semantic_changed = bool(signals.get("semantic_changed"))
    surface_identity_changed = bool(
        signals.get("surface_identity_changed")
        or signals.get("window_identity_changed")
    )
    visual_change_confident = bool(signals.get("visual_change_confident"))
    state_change_detected = bool(
        signals.get("state_change_detected")
        or semantic_changed
        or surface_identity_changed
        or visual_change_confident
    )
    return {
        "state_change_detected": state_change_detected,
        "semantic_changed": semantic_changed,
        "surface_identity_changed": surface_identity_changed,
        "visual_change_confident": visual_change_confident,
    }


def evaluate_verification_policy(
    signals: Mapping[str, Any],
    verification_policy: str | None = None,
) -> dict[str, Any]:
    """Evaluate one bounded shared verification policy against normalized signals.

    The function is deterministic and side-effect free. Device bridges remain
    responsible for collecting their own semantic/surface/visual signals.
    """

    policy = normalize_verification_policy(verification_policy)
    normalized = _normalized_signals(signals)

    if policy == "any_confident_change":
        passed = normalized["state_change_detected"]
    elif policy == "semantic_or_window":
        passed = normalized["semantic_changed"] or normalized["surface_identity_changed"]
    elif policy == "semantic_only":
        passed = normalized["semantic_changed"]
    elif policy == "window_only":
        passed = normalized["surface_identity_changed"]
    else:
        passed = normalized["visual_change_confident"]

    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "verification_policy": policy,
        "policy_passed": bool(passed),
        "policy_reason": _POLICY_REASONS[policy],
        "signals": normalized,
    }


def combine_verification_result(
    policy_result: Mapping[str, Any],
    postconditions: Mapping[str, Any] | None = None,
    *,
    retry_performed: bool = False,
) -> dict[str, Any]:
    """Combine policy and postcondition results with fail-closed AND semantics."""

    if retry_performed:
        raise VerificationContractError(
            "Shared verification contract does not permit automatic retry results."
        )

    policy = dict(policy_result)
    policy_passed = bool(policy.get("policy_passed"))

    post = deepcopy(dict(postconditions or {}))
    if not post:
        post = {
            "configured": False,
            "postconditions_passed": True,
            "checks": [],
        }
    configured = bool(post.get("configured"))
    checks = list(post.get("checks") or [])
    if configured and "postconditions_passed" not in post:
        raise VerificationContractError(
            "Configured postconditions must include postconditions_passed."
        )
    postconditions_passed = bool(post.get("postconditions_passed", not configured))

    verification_passed = bool(policy_passed and postconditions_passed)
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "decision": "pass" if verification_passed else "fail",
        "verification_policy": policy.get("verification_policy"),
        "policy_passed": policy_passed,
        "postconditions_configured": configured,
        "postconditions_passed": postconditions_passed,
        "verification_passed": verification_passed,
        "retry_performed": False,
        "policy": policy,
        "postconditions": {
            **post,
            "configured": configured,
            "postconditions_passed": postconditions_passed,
            "checks": checks,
        },
    }


def contract_manifest() -> dict[str, Any]:
    """Return a compact versioned manifest for Runtime/bridge compatibility checks."""

    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "verification_policies": sorted(VERIFICATION_POLICIES),
        "postcondition_combination": "all_required_and",
        "final_combination": "policy_and_postconditions",
        "automatic_retry": False,
        "device_actions": False,
        "side_effect_free": True,
    }
