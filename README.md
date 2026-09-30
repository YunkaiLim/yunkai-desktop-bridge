# Yunkai Desktop Bridge

A local-first Windows MCP bridge for guarded desktop perception and interaction.

This repository is a sanitized public-source export of the DesktopBridge used in the Yunkai project. It intentionally keeps the safety boundaries that matter: semantic/read-only inspection first, bounded input actions, local runtime policy, deterministic verification, metadata-only action audit, and no arbitrary shell.

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

This repository does **not** contain private tunnel IDs, runtime credentials, owner-specific configuration, caches, backups, local verification evidence, or tunnel-client binaries. Secure-tunnel/autostart wrappers from the private workspace are also omitted from this first public source release.

The shared contract modules required by the bridge are included under `yunkai_shared/`.

## Requirements

- Windows 10/11
- Python 3.11+
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

For the local HTTP entry point used by the original bridge:

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

The private working tree passed its current unit suite before this public export. The public repository is a source export, not a claim that every Windows build or MCP host has been acceptance-tested.

## Security model

Read `SECURITY.md` before enabling side-effecting tools. Keep runtime permissions local, preserve foreground-window and semantic-target guards, and do not remove verification to reduce latency.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

This project is independent source code and is not an official OpenAI product.
