from __future__ import annotations

from typing import Any


RUNTIME_POLICY_SCHEMA_VERSION = 1
PERMISSION_TIERS = ("observe", "interact", "elevated_input")
RUNTIME_PROFILES = frozenset({"observe_only", "standard", "elevated_game"})

_PROFILE_TIERS: dict[str, frozenset[str]] = {
    "observe_only": frozenset({"observe"}),
    "standard": frozenset({"observe", "interact"}),
    "elevated_game": frozenset(PERMISSION_TIERS),
}


class RuntimePolicyError(ValueError):
    """Raised when a runtime profile or permission tier is invalid."""


def normalize_runtime_profile(value: str | None) -> str:
    profile = str(value or "standard").strip().casefold()
    if profile not in RUNTIME_PROFILES:
        raise RuntimePolicyError(
            "Unsupported runtime profile. Allowed: " + ", ".join(sorted(RUNTIME_PROFILES))
        )
    return profile


def normalize_permission_tier(value: str) -> str:
    tier = str(value or "").strip().casefold()
    if tier not in PERMISSION_TIERS:
        raise RuntimePolicyError(
            "Unsupported permission tier. Allowed: " + ", ".join(PERMISSION_TIERS)
        )
    return tier


def evaluate_runtime_permission(
    runtime_profile: str | None,
    required_tier: str,
) -> dict[str, Any]:
    """Evaluate one fixed bridge-assigned permission tier against a runtime profile.

    This function is deterministic and side-effect free. Device bridges assign
    the required tier for each action internally; callers cannot use this helper
    to grant themselves a capability.
    """

    profile = normalize_runtime_profile(runtime_profile)
    tier = normalize_permission_tier(required_tier)
    allowed = tier in _PROFILE_TIERS[profile]
    return {
        "schema_version": RUNTIME_POLICY_SCHEMA_VERSION,
        "runtime_profile": profile,
        "required_tier": tier,
        "allowed": bool(allowed),
        "decision": "allow" if allowed else "deny",
        "reason": (
            f"runtime profile {profile} permits {tier}"
            if allowed
            else f"runtime profile {profile} does not permit {tier}"
        ),
        "self_escalation": False,
        "side_effect_free": True,
    }


def runtime_policy_manifest(runtime_profile: str | None = None) -> dict[str, Any]:
    """Return a versioned profile manifest for bridge/runtime compatibility checks."""

    profile = normalize_runtime_profile(runtime_profile)
    allowed = _PROFILE_TIERS[profile]
    return {
        "schema_version": RUNTIME_POLICY_SCHEMA_VERSION,
        "runtime_profile": profile,
        "permission_tiers": list(PERMISSION_TIERS),
        "allowed_tiers": [tier for tier in PERMISSION_TIERS if tier in allowed],
        "denied_tiers": [tier for tier in PERMISSION_TIERS if tier not in allowed],
        "profiles": {
            name: [tier for tier in PERMISSION_TIERS if tier in tiers]
            for name, tiers in sorted(_PROFILE_TIERS.items())
        },
        "default_profile": "standard",
        "profile_source": "bridge_runtime_configuration",
        "model_selectable_profile": False,
        "self_escalation": False,
        "side_effect_free": True,
    }
