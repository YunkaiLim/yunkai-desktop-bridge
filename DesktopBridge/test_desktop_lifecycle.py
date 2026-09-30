from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import desktop_lifecycle as lifecycle


class DesktopLifecycleTests(unittest.TestCase):
    def fixture(self, root: Path):
        epoch, marker = "a" * 32, "b" * 32
        envelope = lifecycle._envelope(epoch, marker)
        launch = {**envelope, "executables": {"launcher": r"c:\fixture\python.exe", "host": r"c:\fixture\python.exe", "tunnel": r"c:\fixture\tunnel-client.exe"}}
        directory = root / epoch
        lifecycle._write(directory / "launch.json", launch)
        lifecycle._write(root / "current.json", envelope)
        records = []
        for index, role in enumerate(("launcher", "tunnel", "host"), start=100):
            identity = {"pid": index, "creationToken": str(index * 1000), "executable": launch["executables"][role]}
            lifecycle._record(directory, launch, role, identity)
            records.append({**envelope, "role": role, **identity})
        return records

    def test_explicit_stop_only_registered_generation_not_ollama_or_conhost(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = self.fixture(root)
            live = {record["pid"]: record for record in records}
            live[12808] = {"pid": 12808, "creationToken": "111", "executable": "ollama.exe", "parentPid": 100}
            live[17360] = {"pid": 17360, "creationToken": "222", "executable": "conhost.exe", "parentPid": 12808}
            touched = []

            def terminate(record):
                touched.append(record["pid"])
                del live[record["pid"]]

            result = lifecycle.stop_tunnel(root=root, observer=live.get, terminator=terminate)
            self.assertEqual(result["status"], "STOPPED")
            self.assertEqual(touched, [101, 102, 100])
            self.assertEqual(set(live), {12808, 17360})
            self.assertFalse((root / "current.json").exists())

    def test_stale_generation_reconciles_without_terminating_pid_replacements(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = self.fixture(root)
            replacement = {**records[0], "creationToken": "999999", "executable": "ollama.exe"}
            touched = []
            result = lifecycle.stop_tunnel(root=root, observer=lambda pid: replacement if pid == 100 else None, terminator=touched.append)
            self.assertEqual(result["ownedTargets"], 0)
            self.assertEqual(touched, [])
            self.assertFalse((root / "current.json").exists())

    def test_legacy_missing_ownership_never_uses_port_or_process_name(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(lifecycle.OwnershipError, "LEGACY_OR_MISSING"):
                lifecycle.stop_tunnel(root=Path(directory), observer=lambda _: self.fail("must not observe unknown PIDs"), terminator=lambda _: self.fail("must not stop"))

    def test_cross_component_and_owner_marker_mismatch_fail_before_any_action(self):
        for field, value in (("component", "yunkai.devspace"), ("ownerMarker", "c" * 32), ("runtimeEpoch", "d" * 32)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / ("a" * 32) / "tunnel.json"
                record = json.loads(path.read_text())
                record[field] = value
                path.write_text(json.dumps(record))
                with self.assertRaisesRegex(lifecycle.OwnershipError, "OWNERSHIP_ENVELOPE_MISMATCH"):
                    lifecycle.stop_tunnel(root=root, terminator=lambda _: self.fail("must not stop"))
                self.assertTrue((root / "current.json").exists())

    def test_observation_denial_prevents_partial_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = self.fixture(root)

            def observe(pid):
                if pid == 102:
                    raise lifecycle.OwnershipError("PROCESS_OBSERVATION_DENIED")
                return next(record for record in records if record["pid"] == pid)

            with self.assertRaisesRegex(lifecycle.OwnershipError, "OBSERVATION_DENIED"):
                lifecycle.stop_tunnel(root=root, observer=observe, terminator=lambda _: self.fail("must not partially stop"))
            self.assertTrue((root / "current.json").exists())

    def test_same_creation_with_wrong_executable_is_not_stale_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = self.fixture(root)
            live = {record["pid"]: record for record in records}
            live[101] = {**live[101], "executable": "ollama.exe"}
            with self.assertRaisesRegex(lifecycle.OwnershipError, "LIVE_EXECUTABLE_IDENTITY_MISMATCH"):
                lifecycle.stop_tunnel(root=root, observer=live.get, terminator=lambda _: self.fail("must not stop"))

    def test_incomplete_or_corrupt_records_are_preserved(self):
        for malformed in (None, b"\0" * 64, b"[]", b"x" * 65537):
            with self.subTest(malformed=type(malformed).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                record_path = root / ("a" * 32) / "tunnel.json"
                if malformed is None:
                    record_path.unlink()
                else:
                    record_path.write_bytes(malformed)
                with self.assertRaises(lifecycle.OwnershipError):
                    lifecycle.stop_tunnel(root=root, terminator=lambda _: self.fail("must not stop"))
                self.assertTrue((root / "current.json").exists())

    def test_environment_isolation_preserves_desktop_profile_and_key_only_in_memory(self):
        env = {"DEVSPACE_RUNTIME_EPOCH": "foreign", "devspace_ownership_directory": "foreign", "YUNKAI_DEVSPACE_OWNER": "foreign", "MCP_COMMAND": "node devspace_stdio.mjs", "CONTROL_PLANE_POLL_CHANNELS": "main", "DESKTOPBRIDGE_OWNER_MARKER": "stale", "CONTROL_PLANE_API_KEY": "fixture-only", "YUNKAI_DESKTOP_RUNTIME_PROFILE": "standard"}
        clean = lifecycle.independent_environment(env, clear_routes=True)
        self.assertEqual(clean, {"CONTROL_PLANE_API_KEY": "fixture-only", "YUNKAI_DESKTOP_RUNTIME_PROFILE": "standard"})
        self.assertIn("DEVSPACE_RUNTIME_EPOCH", env)
        self.assertEqual(lifecycle.detached_creation_flags(), subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)

    def test_host_registration_is_opt_in_and_refuses_foreign_envelope(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(lifecycle, "observe_process", side_effect=AssertionError("ephemeral host must not register")):
                lifecycle.register_host()
        with patch.dict(os.environ, {lifecycle.EPOCH_ENV: "not-epoch", lifecycle.MARKER_ENV: "x"}, clear=True):
            with self.assertRaisesRegex(lifecycle.OwnershipError, "INVALID_HOST_OWNER_MARKER"):
                lifecycle.register_host()

    def test_real_current_process_observation_is_read_only(self):
        identity = lifecycle.observe_process(os.getpid())
        self.assertEqual(identity["pid"], os.getpid())
        self.assertEqual(identity["executable"], os.path.normcase(sys.executable))
        self.assertTrue(identity["creationToken"].isdigit())

    def test_launch_publishes_separate_identities_and_never_relaunches_existing_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            executable = Path(directory) / "tunnel-client.exe"
            executable.write_bytes(b"fixture-only-never-executed")
            process = Mock(pid=4242)
            process.wait.return_value = 0
            captured = {}

            def popen(command, **kwargs):
                captured.update({"command": command, **kwargs, "env": dict(kwargs["env"])})
                return process

            def observe(pid):
                return {"pid": pid, "creationToken": str(pid * 1000), "executable": os.path.normcase(str(executable.resolve()) if pid == 4242 else sys.executable)}

            with patch.dict(os.environ, {"CONTROL_PLANE_API_KEY": "fixture-only", "DEVSPACE_RUNTIME_EPOCH": "foreign"}):
                with patch.object(lifecycle.subprocess, "Popen", side_effect=popen) as spawn, patch.object(lifecycle, "observe_process", side_effect=observe):
                    self.assertEqual(lifecycle.launch_tunnel(executable, root=root), 0)
                    with self.assertRaisesRegex(lifecycle.OwnershipError, "EXPLICIT_STOP_REQUIRED"):
                        lifecycle.launch_tunnel(executable, root=root)
                    self.assertEqual(spawn.call_count, 1)
                    self.assertNotIn("CONTROL_PLANE_API_KEY", os.environ)
            current, records = lifecycle.load_records(root)
            self.assertEqual({record["role"] for record in records}, {"launcher", "tunnel"})
            self.assertEqual(captured["env"][lifecycle.EPOCH_ENV], current["runtimeEpoch"])
            self.assertNotIn("DEVSPACE_RUNTIME_EPOCH", captured["env"])
            self.assertEqual(captured["creationflags"], lifecycle.detached_creation_flags())
            self.assertNotIn("fixture-only", " ".join(captured["command"]))

    def test_host_registers_own_identity_and_stop_marker_blocks_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = self.fixture(root)
            current = lifecycle._read(root / "current.json")
            identity = {"pid": 103, "creationToken": "103000", "executable": records[2]["executable"]}
            with patch.dict(os.environ, {lifecycle.EPOCH_ENV: current["runtimeEpoch"], lifecycle.MARKER_ENV: current["ownerMarker"]}):
                with patch.object(lifecycle, "state_root", return_value=root), patch.object(lifecycle, "observe_process", side_effect=lambda pid: records[1] if pid == 101 else identity):
                    lifecycle.register_host()
                    self.assertTrue((root / current["runtimeEpoch"] / "host-103-103000.json").is_file())
                    lifecycle._write(root / current["runtimeEpoch"] / "stop-requested.json", current)
                    with self.assertRaisesRegex(lifecycle.OwnershipError, "EXPLICIT_STOP_IN_PROGRESS"):
                        lifecycle.register_host()

    def test_current_publication_failure_precedes_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            executable = Path(directory) / "tunnel-client.exe"
            executable.write_bytes(b"fixture")
            original_write = lifecycle._write

            def write(path, value, **kwargs):
                if path.name == "current.json":
                    raise PermissionError("fixture")
                original_write(path, value, **kwargs)

            with patch.object(lifecycle, "_write", side_effect=write), patch.object(lifecycle.subprocess, "Popen") as spawn:
                with self.assertRaises(PermissionError):
                    lifecycle.launch_tunnel(executable, root=root)
                spawn.assert_not_called()

    def test_tunnel_publication_failure_rolls_back_exact_child_and_reconciles_receipt(self):
        for rollback_succeeds in (True, False):
            with self.subTest(rollback_succeeds=rollback_succeeds), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "state"
                executable = Path(directory) / "tunnel-client.exe"
                executable.write_bytes(b"fixture")
                process = Mock(pid=4242)
                process.poll.return_value = None
                if not rollback_succeeds:
                    process.wait.side_effect = subprocess.TimeoutExpired("fixture", 5)
                original_write = lifecycle._write

                def write(path, value, **kwargs):
                    if path.name == "tunnel.json":
                        raise PermissionError("fixture-publication-denied")
                    original_write(path, value, **kwargs)

                def observe(pid):
                    return {"pid": pid, "creationToken": str(pid * 1000), "executable": os.path.normcase(str(executable) if pid == 4242 else sys.executable)}

                with patch.object(lifecycle, "_write", side_effect=write), patch.object(lifecycle.subprocess, "Popen", return_value=process) as spawn, patch.object(lifecycle, "observe_process", side_effect=observe):
                    with self.assertRaisesRegex(lifecycle.OwnershipError, "EXIT_CONFIRMED" if rollback_succeeds else "EXIT_UNPROVEN"):
                        lifecycle.launch_tunnel(executable, root=root)
                    self.assertTrue((root / "current.json").exists())
                    with self.assertRaisesRegex(lifecycle.OwnershipError, "EXPLICIT_STOP_REQUIRED"):
                        lifecycle.launch_tunnel(executable, root=root)
                    self.assertEqual(spawn.call_count, 1)
                process.terminate.assert_called_once_with()
                process.wait.assert_called_once_with(timeout=5)
                if rollback_succeeds:
                    result = lifecycle.stop_tunnel(root=root, observer=lambda _: None, terminator=lambda _: self.fail("stale receipt needs no termination"))
                    self.assertEqual(result["ownedTargets"], 0)
                else:
                    with self.assertRaises(lifecycle.OwnershipError):
                        lifecycle.stop_tunnel(root=root, observer=lambda _: None, terminator=lambda _: self.fail("uncertain startup must stay closed"))
                    self.assertTrue((root / "current.json").exists())

    def test_spawn_failure_has_durable_reconcilable_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            executable = Path(directory) / "tunnel-client.exe"
            executable.write_bytes(b"fixture")
            with patch.object(lifecycle.subprocess, "Popen", side_effect=OSError("fixture-create-denied")):
                with self.assertRaisesRegex(lifecycle.OwnershipError, "EXIT_CONFIRMED"):
                    lifecycle.launch_tunnel(executable, root=root)
            current = lifecycle._read(root / "current.json")
            receipt = lifecycle._read(root / current["runtimeEpoch"] / "launch-failure.json")
            self.assertFalse(receipt["childStarted"])
            self.assertEqual(lifecycle.stop_tunnel(root=root, observer=lambda _: None, terminator=lambda _: self.fail("nothing to terminate"))["status"], "STOPPED")

    def test_termination_revalidates_same_handle_and_never_kills_pid_reuse(self):
        expected = {"pid": 4242, "creationToken": "10000", "executable": r"c:\fixture\python.exe"}
        for live in (expected, {**expected, "creationToken": "99999"}, None):
            with self.subTest(live=live):
                kernel = Mock()
                kernel.OpenProcess.return_value = 123
                kernel.TerminateProcess.return_value = True
                kernel.WaitForSingleObject.return_value = 0
                with patch.object(lifecycle, "_kernel", return_value=kernel), patch.object(lifecycle, "_identity_from_handle", return_value=live) as observation:
                    lifecycle.terminate_owned(expected)
                observation.assert_called_once_with(kernel, 123, 4242)
                kernel.CloseHandle.assert_called_once_with(123)
                if live == expected:
                    kernel.TerminateProcess.assert_called_once_with(123, 0)
                else:
                    kernel.TerminateProcess.assert_not_called()

    def test_secure_launcher_uses_separate_console_and_explicit_stop_only(self):
        root = Path(__file__).resolve().parent
        start = (root / "Start-DesktopBridge-SecureTunnel.ps1").read_text(encoding="utf-8-sig")
        stop = (root / "Stop-DesktopBridge-Tunnel.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("-WindowStyle Hidden -PassThru", start)
        self.assertIn("desktop_lifecycle.py", start)
        self.assertIn("desktop_lifecycle.py", stop)
        for unsafe in ("Stop-Process", "Get-NetTCPConnection", "ParentProcessId", "taskkill"):
            self.assertNotIn(unsafe, stop)


class DesktopLifecycleStdioTests(unittest.IsolatedAsyncioTestCase):
    async def test_registered_stdio_restart_keeps_38_tools_and_read_only_uia_response(self):
        project = Path(__file__).resolve().parent
        catalogs = []
        identities = []
        with tempfile.TemporaryDirectory() as directory:
            for epoch in ("1" * 32, "2" * 32):
                marker = "3" * 32
                root = Path(directory) / "Yunkai" / "DesktopBridge" / "lifecycle"
                launch = {**lifecycle._envelope(epoch, marker), "executables": {"host": os.path.normcase(sys.executable), "tunnel": os.path.normcase(sys.executable)}}
                lifecycle._write(root / epoch / "launch.json", launch)
                lifecycle._record(root / epoch, launch, "tunnel", lifecycle.observe_process(os.getpid()))
                env = lifecycle.independent_environment(dict(os.environ), clear_routes=True)
                env.pop("CONTROL_PLANE_API_KEY", None)
                env.update({"LOCALAPPDATA": directory, lifecycle.EPOCH_ENV: epoch, lifecycle.MARKER_ENV: marker})
                params = StdioServerParameters(command=sys.executable, args=[str(project / "server_stdio.py")], cwd=str(project), env=env)
                async with stdio_client(params) as streams:
                    async with ClientSession(*streams) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        self.assertEqual(len(tools.tools), 38)
                        catalogs.append([(tool.name, tool.input_schema) for tool in tools.tools])
                        result = await session.call_tool("get_uia_status", {})
                        self.assertFalse(result.is_error)
                        payload = json.loads(result.content[0].text)
                        self.assertTrue(payload["ok"])
                        self.assertTrue(payload["enabled"])
                        records = list((root / epoch).glob("host-*.json"))
                        self.assertEqual(len(records), 1)
                        record = lifecycle._read(records[0])
                        self.assertTrue(lifecycle.identity_matches(record, lifecycle.observe_process(record["pid"])))
                        identities.append((record["pid"], record["creationToken"]))
            self.assertEqual(catalogs[0], catalogs[1])
            self.assertNotEqual(identities[0], identities[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
