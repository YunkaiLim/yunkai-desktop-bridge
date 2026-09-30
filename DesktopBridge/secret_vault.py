from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid
from typing import Any


_SCHEMA_VERSION = 1
_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_DESCRIPTION = "Yunkai DesktopBridge Secret Vault"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class SecretVaultError(RuntimeError):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_vault_path() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    base = Path(root) if root else Path.home() / "AppData" / "Local"
    return base / "Yunkai" / "DesktopBridge" / "secret-vault.json"


def normalize_alias(alias: str) -> str:
    value = str(alias or "").strip().lower()
    if not _ALIAS_RE.fullmatch(value):
        raise SecretVaultError("Secret alias must match [a-z][a-z0-9_.-]{0,63}.")
    return value


def _validate_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise SecretVaultError("Secret value must not be empty.")
    if len(secret) > 8192:
        raise SecretVaultError("Secret value is limited to 8192 characters.")
    if any(char in secret for char in ("\x00", "\r", "\n")):
        raise SecretVaultError("Secret value must be a single line without NUL characters.")
    return secret


def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, ctypes.Array[Any]]:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _entropy(alias: str) -> bytes:
    return f"Yunkai DesktopBridge SecretVault v1|{alias}".encode("utf-8")


def _protect(data: bytes, alias: str) -> bytes:
    if os.name != "nt":
        raise SecretVaultError("Windows DPAPI is only available on Windows.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, in_buffer = _blob_from_bytes(data)
    entropy_blob, entropy_buffer = _blob_from_bytes(_entropy(alias))
    out_blob = DATA_BLOB()
    _ = in_buffer, entropy_buffer
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        _DESCRIPTION,
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretVaultError(f"CryptProtectData failed with Windows error {ctypes.get_last_error()}.")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _unprotect(data: bytes, alias: str) -> bytes:
    if os.name != "nt":
        raise SecretVaultError("Windows DPAPI is only available on Windows.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, in_buffer = _blob_from_bytes(data)
    entropy_blob, entropy_buffer = _blob_from_bytes(_entropy(alias))
    out_blob = DATA_BLOB()
    description = ctypes.c_wchar_p()
    _ = in_buffer, entropy_buffer
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        ctypes.byref(description),
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretVaultError(f"CryptUnprotectData failed with Windows error {ctypes.get_last_error()}.")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)
        if description:
            kernel32.LocalFree(description)


@dataclass(frozen=True)
class SecretAliasInfo:
    alias: str
    created_at: str
    updated_at: str

    def as_dict(self) -> dict[str, str]:
        return {"alias": self.alias, "created_at": self.created_at, "updated_at": self.updated_at}


class SecretVault:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else _default_vault_path()

    def list_aliases(self) -> list[SecretAliasInfo]:
        data = self._read()
        entries = data.get("entries", {})
        result: list[SecretAliasInfo] = []
        for alias in sorted(entries):
            entry = entries.get(alias)
            if not isinstance(entry, dict):
                continue
            result.append(
                SecretAliasInfo(
                    alias=alias,
                    created_at=str(entry.get("created_at") or ""),
                    updated_at=str(entry.get("updated_at") or ""),
                )
            )
        return result

    def metadata(self) -> dict[str, Any]:
        data = self._read()
        aliases = self.list_aliases()
        entries = data.get("entries", {})
        safe_aliases: list[dict[str, Any]] = []
        for item in aliases:
            entry = entries.get(item.alias) if isinstance(entries, dict) else None
            targets = list(entry.get("targets", [])) if isinstance(entry, dict) and isinstance(entry.get("targets"), list) else []
            safe_aliases.append({
                **item.as_dict(),
                "target_count": len(targets),
                "targets": [self._safe_target(target) for target in targets if isinstance(target, dict)],
            })
        return {
            "schema_version": _SCHEMA_VERSION,
            "storage": "windows_dpapi_current_user",
            "vault_path_exposed": False,
            "secret_values_exposed": False,
            "remote_secret_upload_allowed": False,
            "remote_secret_read_allowed": False,
            "remote_secret_delete_allowed": False,
            "target_binding_required": True,
            "count": len(aliases),
            "aliases": safe_aliases,
        }

    def set_secret(self, alias: str, secret: str) -> SecretAliasInfo:
        normalized = normalize_alias(alias)
        value = _validate_secret(secret)
        data = self._read()
        entries = dict(data.get("entries", {}))
        prior = entries.get(normalized) if isinstance(entries.get(normalized), dict) else {}
        now = _utc_now()
        ciphertext = base64.b64encode(_protect(value.encode("utf-8"), normalized)).decode("ascii")
        entries[normalized] = {
            "ciphertext": ciphertext,
            "created_at": str(prior.get("created_at") or now),
            "updated_at": now,
            "targets": list(prior.get("targets", [])) if isinstance(prior.get("targets"), list) else [],
        }
        self._write({"schema_version": _SCHEMA_VERSION, "entries": entries})
        return SecretAliasInfo(normalized, entries[normalized]["created_at"], now)

    def get_secret(self, alias: str) -> str:
        normalized = normalize_alias(alias)
        data = self._read()
        entry = data.get("entries", {}).get(normalized)
        if not isinstance(entry, dict) or not isinstance(entry.get("ciphertext"), str):
            raise SecretVaultError(f"Secret alias '{normalized}' does not exist.")
        try:
            protected = base64.b64decode(entry["ciphertext"], validate=True)
            return _unprotect(protected, normalized).decode("utf-8")
        except SecretVaultError:
            raise
        except Exception as exc:
            raise SecretVaultError(f"Secret alias '{normalized}' could not be decrypted.") from exc

    def bind_target(
        self,
        alias: str,
        *,
        window_title: str,
        name: str | None = None,
        automation_id: str | None = None,
    ) -> dict[str, str | None]:
        normalized = normalize_alias(alias)
        title = str(window_title or "").strip()
        name_value = str(name or "").strip() or None
        automation_value = str(automation_id or "").strip() or None
        if not title or len(title) > 500:
            raise SecretVaultError("Bound window title must be 1-500 characters.")
        if not name_value and not automation_value:
            raise SecretVaultError("Bound target requires name and/or automation_id.")
        if name_value and len(name_value) > 500:
            raise SecretVaultError("Bound target name is too long.")
        if automation_value and len(automation_value) > 500:
            raise SecretVaultError("Bound target automation_id is too long.")
        data = self._read()
        entries = dict(data.get("entries", {}))
        entry = entries.get(normalized)
        if not isinstance(entry, dict) or not isinstance(entry.get("ciphertext"), str):
            raise SecretVaultError(f"Secret alias '{normalized}' does not exist.")
        target = {"window_title": title, "name": name_value, "automation_id": automation_value}
        targets = [item for item in entry.get("targets", []) if isinstance(item, dict)] if isinstance(entry.get("targets"), list) else []
        target_key = self._target_key(target)
        if not any(self._target_key(item) == target_key for item in targets):
            targets.append(target)
        entry = {**entry, "targets": targets, "updated_at": _utc_now()}
        entries[normalized] = entry
        self._write({"schema_version": _SCHEMA_VERSION, "entries": entries})
        return self._safe_target(target)

    def resolve_for_target(
        self,
        alias: str,
        *,
        window_title: str,
        name: str | None = None,
        automation_id: str | None = None,
    ) -> str:
        normalized = normalize_alias(alias)
        requested = {
            "window_title": str(window_title or "").strip(),
            "name": str(name or "").strip() or None,
            "automation_id": str(automation_id or "").strip() or None,
        }
        if not requested["window_title"] or (not requested["name"] and not requested["automation_id"]):
            raise SecretVaultError("Remote secret input requires an exact pre-bound window and UIA selector.")
        data = self._read()
        entry = data.get("entries", {}).get(normalized)
        if not isinstance(entry, dict):
            raise SecretVaultError(f"Secret alias '{normalized}' does not exist.")
        targets = entry.get("targets", []) if isinstance(entry.get("targets"), list) else []
        requested_key = self._target_key(requested)
        if not any(isinstance(target, dict) and self._target_key(target) == requested_key for target in targets):
            raise SecretVaultError(
                f"Secret alias '{normalized}' is not authorized for the requested window/input target. Bind it locally first."
            )
        return self.get_secret(normalized)

    def delete_secret(self, alias: str) -> bool:
        normalized = normalize_alias(alias)
        data = self._read()
        entries = dict(data.get("entries", {}))
        existed = normalized in entries
        entries.pop(normalized, None)
        if existed:
            self._write({"schema_version": _SCHEMA_VERSION, "entries": entries})
        return existed

    @staticmethod
    def _target_key(target: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(target.get("window_title") or "").strip().casefold(),
            str(target.get("name") or "").strip().casefold(),
            str(target.get("automation_id") or "").strip().casefold(),
        )

    @staticmethod
    def _safe_target(target: dict[str, Any]) -> dict[str, str | None]:
        return {
            "window_title": str(target.get("window_title") or "")[:500],
            "name": str(target.get("name") or "")[:500] or None,
            "automation_id": str(target.get("automation_id") or "")[:500] or None,
        }

    def _read(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": _SCHEMA_VERSION, "entries": {}}
        except Exception as exc:
            raise SecretVaultError("Secret vault metadata is unreadable or invalid.") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != _SCHEMA_VERSION:
            raise SecretVaultError("Unsupported secret vault schema version.")
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            raise SecretVaultError("Secret vault entries are invalid.")
        return raw

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
