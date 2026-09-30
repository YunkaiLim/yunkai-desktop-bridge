"""Desktop-only process ownership. No port or ancestry grants stop authority."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
import uuid


COMPONENT = "yunkai.desktopbridge"
EPOCH_ENV = "DESKTOPBRIDGE_RUNTIME_EPOCH"
MARKER_ENV = "DESKTOPBRIDGE_OWNER_MARKER"
_ID = re.compile(r"^[0-9a-f]{32}$")
ROUTING_ENV = {
    "CONTROL_PLANE_TUNNEL_ID", "CONTROL_PLANE_POLL_CHANNELS", "MCP_COMMAND",
    "MCP_STDIO_SEND_INITIALIZED_NOTIFICATION", "HEALTH_LISTEN_ADDR",
}


class OwnershipError(RuntimeError):
    pass


def independent_environment(source: dict[str, str], *, clear_routes: bool = False) -> dict[str, str]:
    return {
        key: value for key, value in source.items()
        if not key.upper().startswith(("DEVSPACE_", "YUNKAI_DEVSPACE_", "DESKTOPBRIDGE_"))
        and not (clear_routes and key.upper() in ROUTING_ENV)
    }


def detached_creation_flags() -> int:
    return subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def state_root() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Yunkai" / "DesktopBridge" / "lifecycle"


def _read(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            content = stream.read(65537)
        if len(content) > 65536:
            raise ValueError("oversized")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError("not object")
        return value
    except (OSError, UnicodeError, ValueError) as exc:
        raise OwnershipError("OWNERSHIP_RECORD_UNREADABLE") from exc


def _write(path: Path, value: dict[str, Any], *, immutable: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    if immutable:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != data:
            raise OwnershipError("OWNERSHIP_RECORD_READBACK_FAILED")
    else:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if temporary.read_bytes() != data:
            raise OwnershipError("OWNERSHIP_RECORD_READBACK_FAILED")
        os.replace(temporary, path)


@contextmanager
def state_lock(root: Path):
    import msvcrt
    root.mkdir(parents=True, exist_ok=True)
    with (root / "lifecycle.lock").open("a+b") as stream:
        stream.seek(0)
        if not stream.read(1):
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        deadline = time.monotonic() + 2.0
        while True:
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise OwnershipError("LIFECYCLE_BUSY") from exc
                time.sleep(0.025)  # Only retry metadata locking, never process actions.
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel


def _identity_from_handle(kernel, handle, pid: int) -> dict[str, Any] | None:
    exit_code = wintypes.DWORD()
    if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        raise OwnershipError("PROCESS_OBSERVATION_FAILED")
    if exit_code.value != 259:
        return None
    creation, exit_time, system, user = (wintypes.FILETIME() for _ in range(4))
    size = wintypes.DWORD(32768)
    executable = ctypes.create_unicode_buffer(size.value)
    if not kernel.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(system), ctypes.byref(user)):
        raise OwnershipError("PROCESS_OBSERVATION_FAILED")
    if not kernel.QueryFullProcessImageNameW(handle, 0, executable, ctypes.byref(size)):
        raise OwnershipError("PROCESS_EXECUTABLE_UNREADABLE")
    return {"pid": pid, "creationToken": str((creation.dwHighDateTime << 32) | creation.dwLowDateTime), "executable": os.path.normcase(executable.value)}


def observe_process(pid: int) -> dict[str, Any] | None:
    kernel = _kernel()
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return None
        raise OwnershipError("PROCESS_OBSERVATION_DENIED")
    try:
        return _identity_from_handle(kernel, handle, pid)
    finally:
        kernel.CloseHandle(handle)


def identity_matches(expected: dict[str, Any], live: dict[str, Any] | None) -> bool:
    return live is not None and all(expected.get(key) == live.get(key) for key in ("pid", "creationToken", "executable"))


def terminate_owned(expected: dict[str, Any]) -> None:
    """Revalidate and terminate through the SAME handle, eliminating PID reuse races."""
    kernel = _kernel()
    handle = kernel.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, expected["pid"])
    if not handle:
        if ctypes.get_last_error() == 87:
            return
        raise OwnershipError("OWNED_PROCESS_ACCESS_DENIED")
    try:
        if not identity_matches(expected, _identity_from_handle(kernel, handle, expected["pid"])):
            return  # Original generation is gone. Never claim its replacement.
        if not kernel.TerminateProcess(handle, 0):
            raise OwnershipError("OWNED_PROCESS_STOP_FAILED")
        if kernel.WaitForSingleObject(handle, 5000) != 0:
            raise OwnershipError("OWNED_PROCESS_STOP_TIMEOUT")
    finally:
        kernel.CloseHandle(handle)


def _envelope(epoch: str, marker: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "component": COMPONENT, "runtimeEpoch": epoch, "ownerMarker": marker}


def _validate_envelope(value: dict[str, Any], epoch: str, marker: str) -> None:
    if any(value.get(key) != expected for key, expected in _envelope(epoch, marker).items()):
        raise OwnershipError("OWNERSHIP_ENVELOPE_MISMATCH")


def _record(directory: Path, launch: dict[str, Any], role: str, identity: dict[str, Any]) -> None:
    record = {**_envelope(launch["runtimeEpoch"], launch["ownerMarker"]), "role": role, **identity}
    name = f"host-{identity['pid']}-{identity['creationToken']}.json" if role == "host" else f"{role}.json"
    _write(directory / name, record)


def register_host() -> None:
    epoch, marker = os.environ.get(EPOCH_ENV), os.environ.get(MARKER_ENV)
    if not epoch and not marker:
        return  # Ephemeral stdio clients do not acquire production lifecycle authority.
    if not epoch or not marker or not _ID.fullmatch(epoch) or not _ID.fullmatch(marker):
        raise OwnershipError("INVALID_HOST_OWNER_MARKER")
    root = state_root()
    with state_lock(root):
        directory = root / epoch
        launch = _read(directory / "launch.json")
        _validate_envelope(launch, epoch, marker)
        if (directory / "stop-requested.json").exists():
            raise OwnershipError("EXPLICIT_STOP_IN_PROGRESS")
        tunnel = _read(directory / "tunnel.json")
        _validate_envelope(tunnel, epoch, marker)
        if tunnel.get("role") != "tunnel" or tunnel.get("executable") != launch["executables"]["tunnel"]:
            raise OwnershipError("HOST_TUNNEL_OWNERSHIP_UNPROVEN")
        if not identity_matches(tunnel, observe_process(tunnel["pid"])):
            raise OwnershipError("HOST_TUNNEL_GENERATION_ABSENT")
        identity = observe_process(os.getpid())
        if not identity or identity["executable"] != launch["executables"]["host"]:
            raise OwnershipError("HOST_EXECUTABLE_MISMATCH")
        _record(directory, launch, "host", identity)


def _record_failed_launch(directory: Path, launch: dict[str, Any], *, child_started: bool) -> None:
    receipt = {**_envelope(launch["runtimeEpoch"], launch["ownerMarker"]), "reason": "LAUNCH_FAILED", "childStarted": child_started, "childExitConfirmed": True, "hostsCouldServe": False}
    for attempt in range(3):
        try:
            _write(directory / "launch-failure.json", receipt, immutable=False)
            return
        except OSError:
            if attempt == 2:
                raise
            time.sleep(0.025)  # Metadata publication only; never repeat process creation.


def launch_tunnel(tunnel_path: Path, *, root: Path | None = None) -> int:
    root = root or state_root()
    executable = str(tunnel_path.resolve(strict=True))
    with state_lock(root):
        if (root / "current.json").exists():
            raise OwnershipError("EXPLICIT_STOP_REQUIRED_FOR_PREVIOUS_GENERATION")
        epoch, marker = uuid.uuid4().hex, uuid.uuid4().hex
        directory = root / epoch
        launch = {**_envelope(epoch, marker), "executables": {"launcher": os.path.normcase(sys.executable), "host": os.path.normcase(sys.executable), "tunnel": os.path.normcase(executable)}}
        _write(directory / "launch.json", launch)
        identity = observe_process(os.getpid())
        if not identity:
            raise OwnershipError("LAUNCHER_IDENTITY_UNAVAILABLE")
        _record(directory, launch, "launcher", identity)
        # Durable claim precedes any child creation. Even a crash in the spawn /
        # publication gap prevents another launch from claiming the same slot.
        _write(root / "current.json", _envelope(epoch, marker), immutable=False)
        child_env = independent_environment(dict(os.environ))
        child_env[EPOCH_ENV], child_env[MARKER_ENV] = epoch, marker
        process = None
        try:
            process = subprocess.Popen([executable, "run", "--log.level=info", "--log.format=struct-text"], cwd=str(Path(__file__).resolve().parent), env=child_env, creationflags=detached_creation_flags())
            tunnel_identity = observe_process(process.pid)
            if not tunnel_identity:
                raise OwnershipError("TUNNEL_EXITED_BEFORE_OWNERSHIP_PUBLICATION")
            _record(directory, launch, "tunnel", tunnel_identity)
        except Exception as exc:
            # Roll back only this exact, just-created child through Popen's
            # retained Windows process handle. No name/port/PID-tree authority.
            exit_confirmed = process is None
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            process.terminate()
                        except OSError:
                            pass  # A raced exit must still be proven by wait.
                    process.wait(timeout=5)
                    exit_confirmed = True
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if exit_confirmed:
                _record_failed_launch(directory, launch, child_started=process is not None)
                raise OwnershipError("LAUNCH_FAILED_EXACT_CHILD_EXIT_CONFIRMED") from exc
            raise OwnershipError("LAUNCH_FAILED_CHILD_EXIT_UNPROVEN") from exc
        finally:
            child_env.pop("CONTROL_PLANE_API_KEY", None)
            os.environ.pop("CONTROL_PLANE_API_KEY", None)
    return int(process.wait())


def load_records(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    current = _read(root / "current.json")
    epoch, marker = current.get("runtimeEpoch"), current.get("ownerMarker")
    if not isinstance(epoch, str) or not isinstance(marker, str) or not _ID.fullmatch(epoch) or not _ID.fullmatch(marker):
        raise OwnershipError("INVALID_CURRENT_GENERATION")
    _validate_envelope(current, epoch, marker)
    directory = root / epoch
    launch = _read(directory / "launch.json")
    _validate_envelope(launch, epoch, marker)
    failure_path = directory / "launch-failure.json"
    failed_before_serving = False
    if failure_path.exists():
        failure = _read(failure_path)
        _validate_envelope(failure, epoch, marker)
        failed_before_serving = failure.get("reason") == "LAUNCH_FAILED" and failure.get("childExitConfirmed") is True and failure.get("hostsCouldServe") is False
        if not failed_before_serving:
            raise OwnershipError("FAILED_LAUNCH_EXIT_UNPROVEN")
    paths = [directory / "launcher.json", *([] if failed_before_serving else [directory / "tunnel.json"]), *directory.glob("host-*.json")]
    if len(paths) > 258:
        raise OwnershipError("OWNERSHIP_RECORD_LIMIT")
    records = []
    for path in paths:
        record = _read(path)
        _validate_envelope(record, epoch, marker)
        role = record.get("role")
        expected_role = "host" if path.name.startswith("host-") else path.stem
        if role != expected_role or role not in {"launcher", "host", "tunnel"}:
            raise OwnershipError("INVALID_PROCESS_ROLE")
        if type(record.get("pid")) is not int or record["pid"] <= 0 or not isinstance(record.get("creationToken"), str) or not record["creationToken"].isdigit():
            raise OwnershipError("INVALID_PROCESS_IDENTITY")
        if not isinstance(record.get("executable"), str) or not os.path.isabs(record["executable"]) or record["executable"] != launch.get("executables", {}).get(role):
            raise OwnershipError("PROCESS_EXECUTABLE_MISMATCH")
        records.append(record)
    return current, records


def owned_live_records(records, observer=observe_process):
    # Complete observation before taking any action. Denied observation fails closed.
    live_records = []
    for record in records:
        live = observer(record["pid"])
        if live and live.get("creationToken") == record["creationToken"] and not identity_matches(record, live):
            raise OwnershipError("LIVE_EXECUTABLE_IDENTITY_MISMATCH")
        if identity_matches(record, live):
            live_records.append(record)
    return live_records


def stop_tunnel(*, root: Path | None = None, observer=observe_process, terminator=terminate_owned) -> dict[str, Any]:
    root = root or state_root()
    with state_lock(root):
        if not (root / "current.json").exists():
            raise OwnershipError("LEGACY_OR_MISSING_OWNERSHIP_NO_PROCESSES_TOUCHED")
        current, records = load_records(root)
        live = owned_live_records(records, observer)
        directory = root / current["runtimeEpoch"]
        if not (directory / "stop-requested.json").exists():
            _write(directory / "stop-requested.json", current)
        # Stop the tunnel first to prevent respawns. Registered hosts remain exact targets.
        for record in sorted(live, key=lambda item: {"tunnel": 0, "host": 1, "launcher": 2}[item["role"]]):
            terminator(record)
        if owned_live_records(records, observer):
            raise OwnershipError("OWNED_GENERATION_STILL_RUNNING")
        if _read(root / "current.json") != current:
            raise OwnershipError("CURRENT_GENERATION_CHANGED")
        (root / "current.json").unlink()
        return {"status": "STOPPED", "component": COMPONENT, "runtimeEpoch": current["runtimeEpoch"], "ownedTargets": len(live), "ancestryUsedAsOwnership": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("launch", "stop"))
    parser.add_argument("--tunnel")
    args = parser.parse_args()
    try:
        if args.action == "launch":
            if not args.tunnel:
                raise OwnershipError("TUNNEL_EXECUTABLE_REQUIRED")
            return launch_tunnel(Path(args.tunnel))
        print(json.dumps(stop_tunnel()))
        return 0
    except (OwnershipError, OSError) as exc:
        reason = str(exc) if isinstance(exc, OwnershipError) else type(exc).__name__
        print(json.dumps({"status": "STOP_INCOMPLETE" if args.action == "stop" else "START_FAILED", "reason": reason}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
