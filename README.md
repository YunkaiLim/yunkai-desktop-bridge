# Yunkai Desktop Bridge

A local-first Windows MCP bridge for guarded desktop perception and interaction.

This repository is a sanitized public-source export of the DesktopBridge used in the Yunkai project. It keeps the control boundaries that matter: semantic/read-only inspection first, bounded input actions, local runtime policy, deterministic verification, metadata-only action audit, and no arbitrary shell.

## Highlights

- Windows virtual-desktop and active-window screenshots
- Microsoft UI Automation (UIA) semantic inspection
- Win32 control fallback
- guarded mouse and keyboard input
- verified UIA click/text actions with expected-post predicates
- bounded game-input mode behind a separate local permission tier
- localhost-only optional vision fallback
- local DPAPI-backed secret aliases; secret values are never accepted as remote MCP arguments
- capability manifest, runtime permission state, routing hints, device snapshot, and action trace surfaces

## Deliberate non-capabilities

The public MCP surface does not expose arbitrary shell/PowerShell/cmd execution, file deletion, software uninstall, shutdown/reboot, registry modification, unrestricted process kill, or remote secret upload.

## Public export boundary

This repository does **not** contain private tunnel IDs, runtime credentials, owner-specific configuration, caches, backups, local verification evidence, or tunnel-client binaries. Machine-specific DevSpace routing code is intentionally excluded from this public bridge.

The shared contract modules required by the bridge are included under `yunkai_shared/`.

## Requirements

- Windows 10/11
- Python 3.10+
- Microsoft UI Automation (built into Windows)
- Python dependencies in `requirements.txt`

## Quick start

```powershell
git clone https://github.com/YunkaiLim/yunkai-desktop-bridge.git
cd yunkai-desktop-bridge
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd DesktopBridge
python server_stdio.py
```

For the local HTTP entry point:

```powershell
cd DesktopBridge
python server.py
```

Optional localhost vision can be configured by copying `DesktopBridge/desktopbridge_vision.example.json` to `desktopbridge_vision.json` and selecting a compatible local vision model.

## Tests

From `DesktopBridge/`:

```powershell
python -m unittest
```

During public-release preparation on 2026-09-30, the selected public test set passed **95 tests**, including stdio MCP discovery and screenshot/content checks.

A passing unit suite is not proof of live acceptance on every Windows build or MCP host. Perform target-machine acceptance separately.

## Security model

Read `SECURITY.md` before enabling side-effecting tools. Keep runtime permissions local, preserve foreground-window and semantic-target guards, and do not remove verification simply to reduce latency.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

Third-party components are not relicensed by this repository; see `THIRD_PARTY_NOTICES.md`.

This project is independent source code and is not an official OpenAI product.
