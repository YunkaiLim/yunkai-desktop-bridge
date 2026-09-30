from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.utilities.types import Image
from mcp.types import ToolAnnotations

from bridge_manifest import BRIDGE_VERSION
from desktop_bridge import DesktopBridge
from text_chunks import LOGICAL_TEXT_MAX_CHARS
from local_vision import LocalVisionAdapter, LocalVisionConfig, local_vision_status
from secret_vault import SecretVault
from uia_native import uia_status
from watchdog_status import get_watchdog_status as read_watchdog_status


server = MCPServer(
    name="Yunkai Desktop Bridge",
    title="Yunkai Desktop Bridge",
    description="Safely view and interact with the authorized local Windows desktop.",
    instructions=(
        "Use read-only tools first to understand the desktop state. "
        "Only perform focus/mouse/keyboard actions when the user asks for them. "
        "Runtime profiles are enforced locally: standard permits normal interaction, elevated_game is required for Game Mode input. "
        "Use execution_mode=fast for verified semantic clicks only when the user explicitly asks for Fast Path; sensitive or ineligible targets fall back to safe mode. "
        "No arbitrary shell, PowerShell, cmd, delete, uninstall, shutdown, registry, or process-kill tools are exposed."
    ),
    version=BRIDGE_VERSION,
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
ACTION = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)


def _bridge() -> DesktopBridge:
    return DesktopBridge()


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _err(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error": str(exc)}


@server.tool(name="get_desktop_screen_info", annotations=READ_ONLY)
def get_desktop_screen_info() -> dict[str, Any]:
    """Return the Windows virtual desktop origin and size, including multi-monitor layouts."""
    try:
        left, top, width, height = _bridge().virtual_screen()
        return {
            "ok": True,
            "left": left,
            "top": top,
            "width": width,
            "height": height,
            "right": left + width,
            "bottom": top + height,
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_desktop_screenshot", annotations=READ_ONLY, structured_output=False)
def get_desktop_screenshot() -> Image | dict[str, Any]:
    """Capture the complete Windows virtual desktop as a PNG image."""
    try:
        return Image(data=_bridge().screenshot_png(), format="png")
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_desktop_region_screenshot", annotations=READ_ONLY, structured_output=False)
def get_desktop_region_screenshot(left: int, top: int, right: int, bottom: int) -> Image | dict[str, Any]:
    """Capture one validated virtual-desktop region as PNG."""
    try:
        return Image(data=_bridge().screenshot_region_png(left, top, right, bottom), format="png")
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_desktop_active_window", annotations=READ_ONLY)
def get_desktop_active_window() -> dict[str, Any]:
    """Return title, handle, process id, and rectangle for the foreground Windows window."""
    try:
        return {"ok": True, "window": _bridge().active_window().as_dict()}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_desktop_active_window_screenshot", annotations=READ_ONLY, structured_output=False)
def get_desktop_active_window_screenshot() -> Image | dict[str, Any]:
    """Capture only the current foreground window rectangle as PNG for lower-latency perception."""
    try:
        png, _width, _height, _window = _bridge().active_window_screenshot_png()
        return Image(data=png, format="png")
    except Exception as exc:
        return _err(exc)


@server.tool(name="list_desktop_windows", annotations=READ_ONLY)
def list_desktop_windows(title_contains: str | None = None, limit: int = 100) -> dict[str, Any]:
    """List visible top-level Windows windows, optionally filtering by title text."""
    try:
        windows = _bridge().list_windows(title_contains=title_contains, limit=limit)
        return {"ok": True, "count": len(windows), "windows": [window.as_dict() for window in windows]}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_uia_status", annotations=READ_ONLY)
def get_uia_status() -> dict[str, Any]:
    """Return whether the dependency-free Windows UIAutomationCore backend is available."""
    return {"ok": True, **uia_status()}


@server.tool(name="list_active_window_uia_elements", annotations=READ_ONLY)
def list_active_window_uia_elements(
    limit: int = 120,
    max_depth: int = 12,
    actionable_only: bool = False,
    name_contains: str | None = None,
    control_type: str | None = None,
) -> dict[str, Any]:
    """List/filter Microsoft UI Automation elements in the foreground window without invoking them."""
    try:
        bridge = _bridge()
        window = bridge.active_window()
        elements, truncated = bridge.list_uia_elements(
            hwnd=window.hwnd,
            limit=limit,
            max_depth=max_depth,
        )
        needle = (name_contains or "").strip().casefold()
        type_filter = (control_type or "").strip().casefold()
        if actionable_only:
            elements = [element for element in elements if element.get("actionable")]
        if needle:
            elements = [element for element in elements if needle in str(element.get("name", "")).casefold()]
        if type_filter:
            elements = [
                element
                for element in elements
                if str(element.get("control_type", "")).casefold() == type_filter
            ]
        return {
            "ok": True,
            "window": window.as_dict(),
            "count": len(elements),
            "truncated": truncated,
            "actionable_only": bool(actionable_only),
            "name_contains": name_contains,
            "control_type": control_type,
            "elements": elements,
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="list_active_window_controls", annotations=READ_ONLY)
def list_active_window_controls(
    text_contains: str | None = None,
    limit: int = 100,
    include_empty_text: bool = False,
) -> dict[str, Any]:
    """List visible Win32 child controls in the foreground window for low-cost semantic inspection."""
    try:
        bridge = _bridge()
        window = bridge.active_window()
        controls, truncated = bridge.list_window_controls(
            hwnd=window.hwnd,
            text_contains=text_contains,
            limit=limit,
            include_empty_text=include_empty_text,
        )
        return {
            "ok": True,
            "window": window.as_dict(),
            "count": len(controls),
            "truncated": truncated,
            "controls": [control.as_dict() for control in controls],
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_desktop_fast_context", annotations=READ_ONLY)
def get_desktop_fast_context(
    control_limit: int = 80,
    include_visual_hash: bool = False,
    use_vision: bool = True,
    force_vision: bool = False,
) -> dict[str, Any]:
    """Return capability manifest/state/routing hints plus semantic context; use localhost vision only when needed."""
    try:
        bridge = _bridge()
        context = bridge.fast_context(
            control_limit=control_limit,
            include_visual_hash=include_visual_hash,
        )
        try:
            context["watchdog_status"] = read_watchdog_status(recent_alert_limit=5)
        except Exception as watchdog_exc:
            context["watchdog_status"] = {"ok": False, "error": str(watchdog_exc)}
        try:
            context["secret_vault"] = SecretVault().metadata()
        except Exception as secret_exc:
            context["secret_vault"] = {
                "schema_version": 1,
                "secret_values_exposed": False,
                "count": 0,
                "aliases": [],
                "error": str(secret_exc),
            }
        status = local_vision_status(_project_root())
        should_use_vision = bool(use_vision and (force_vision or context.get("vision_recommended")))
        vision: dict[str, Any] = {
            "used": False,
            "recommended": bool(context.get("vision_recommended")),
            "enabled": bool(status.get("enabled")),
            "configured": bool(status.get("configured")),
        }
        if status.get("error"):
            vision["error"] = status["error"]

        if should_use_vision and status.get("enabled"):
            config = LocalVisionConfig.load(_project_root())
            if config is not None:
                png, width, height, window = bridge.active_window_screenshot_png()
                try:
                    result = LocalVisionAdapter(config).analyze_png(
                        png,
                        width=width,
                        height=height,
                        ui_hint={
                            "window_title": window.title,
                            "uia_elements": context.get("uia_elements", []),
                            "controls": context.get("controls", []),
                        },
                    )
                    vision = {
                        "used": True,
                        "recommended": bool(context.get("vision_recommended")),
                        "enabled": True,
                        **result,
                    }
                except Exception as vision_exc:
                    vision["error"] = str(vision_exc)
        elif should_use_vision and not status.get("enabled") and not vision.get("error"):
            vision["reason"] = "Local vision is recommended for this window but is not configured."
        elif not use_vision:
            vision["reason"] = "Local vision was disabled by the caller for this read."

        return {"ok": True, "context": context, "vision": vision}
    except Exception as exc:
        return _err(exc)


@server.tool(name="verify_desktop_state_change", annotations=READ_ONLY)
def verify_desktop_state_change(
    previous_semantic_signature: str,
    previous_visual_dhash: str | None = None,
    previous_window_hwnd: int | None = None,
    previous_window_title: str | None = None,
    control_limit: int = 80,
) -> dict[str, Any]:
    """Compare the current semantic/visual desktop state with a prior Fast Context token after an action."""
    try:
        return {
            "ok": True,
            **_bridge().verify_state_change(
                previous_semantic_signature=previous_semantic_signature,
                previous_visual_dhash=previous_visual_dhash,
                previous_window_hwnd=previous_window_hwnd,
                previous_window_title=previous_window_title,
                control_limit=control_limit,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_recent_desktop_action_audit", annotations=READ_ONLY)
def get_recent_desktop_action_audit(
    limit: int = 20,
    action: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    """Return correlated action results plus runtime-permission decisions; typed text content is never stored."""
    try:
        return {
            "ok": True,
            **_bridge().recent_action_audit(
                limit=limit,
                action=action,
                outcome=outcome,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_desktop_operation_trace", annotations=READ_ONLY)
def get_desktop_operation_trace(operation_id: str) -> dict[str, Any]:
    """Reconstruct one recorded operation across permission decisions, action result, and verification evidence."""
    try:
        return {"ok": True, **_bridge().operation_trace(operation_id)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_yunkai_watchdog_status", annotations=READ_ONLY)
def get_yunkai_watchdog_status(recent_alert_limit: int = 10) -> dict[str, Any]:
    """Return the local Yunkai Watchdog status, active incident, quota flag, and bounded recent alerts without UI transcripts."""
    try:
        return read_watchdog_status(recent_alert_limit=recent_alert_limit)
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_secret_alias_into_active_window_uia", annotations=ACTION)
def type_secret_alias_into_active_window_uia(
    alias: str,
    expected_window_title: str,
    name: str | None = None,
    automation_id: str | None = None,
    replace_existing: bool = True,
) -> dict[str, Any]:
    """Resolve one locally stored DPAPI secret alias and type it into one exact UIA edit control; secret values never enter MCP arguments/results."""
    secret: str | None = None
    try:
        vault = SecretVault()
        secret = vault.resolve_for_target(
            alias,
            window_title=expected_window_title,
            name=name,
            automation_id=automation_id,
        )
        return {
            "ok": True,
            **_bridge().type_secret_into_active_window_uia(
                secret,
                alias,
                expected_window_title,
                name=name,
                automation_id=automation_id,
                replace_existing=replace_existing,
            ),
        }
    except Exception as exc:
        return _err(exc)
    finally:
        secret = None


@server.tool(name="get_desktop_cursor_position", annotations=READ_ONLY)
def get_desktop_cursor_position() -> dict[str, Any]:
    """Return the current mouse cursor position in virtual-desktop coordinates."""
    try:
        return {"ok": True, **_bridge().cursor_position()}
    except Exception as exc:
        return _err(exc)


@server.tool(name="focus_desktop_window", annotations=ACTION)
def focus_desktop_window(hwnd: int) -> dict[str, Any]:
    """Bring one existing visible window to the foreground by handle; does not launch or close apps."""
    try:
        return {"ok": True, **_bridge().focus_window(hwnd)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="move_desktop_mouse", annotations=ACTION)
def move_desktop_mouse(x: int, y: int) -> dict[str, Any]:
    """Move the Windows mouse cursor to one validated virtual-desktop coordinate."""
    try:
        return {"ok": True, **_bridge().move_mouse(x, y)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="click_desktop", annotations=ACTION)
def click_desktop(x: int, y: int, button: str = "left", clicks: int = 1) -> dict[str, Any]:
    """Left/right click or double-click one validated desktop coordinate."""
    try:
        return {"ok": True, **_bridge().click(x, y, button=button, clicks=clicks)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="click_active_window_relative", annotations=ACTION)
def click_active_window_relative(
    x_ratio: float,
    y_ratio: float,
    expected_window_title: str,
    button: str = "left",
    clicks: int = 1,
) -> dict[str, Any]:
    """Click a 0.0-1.0 relative point inside the foreground window, guarded by its expected title."""
    try:
        return {
            "ok": True,
            **_bridge().click_active_window_relative(
                x_ratio,
                y_ratio,
                expected_window_title,
                button=button,
                clicks=clicks,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="click_active_window_uia_element", annotations=ACTION)
def click_active_window_uia_element(
    expected_window_title: str,
    name: str | None = None,
    control_type: str | None = None,
    automation_id: str | None = None,
    button: str = "left",
    clicks: int = 1,
) -> dict[str, Any]:
    """Click one uniquely matched actionable UIA element, guarded by the active window title."""
    try:
        return {
            "ok": True,
            **_bridge().click_active_window_uia_element(
                expected_window_title,
                name=name,
                control_type=control_type,
                automation_id=automation_id,
                button=button,
                clicks=clicks,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_active_window_uia_text", annotations=ACTION)
def type_active_window_uia_text(
    text: Annotated[str, Field(max_length=LOGICAL_TEXT_MAX_CHARS)],
    expected_window_title: str,
    name: str | None = None,
    automation_id: str | None = None,
    replace_existing: bool = False,
) -> dict[str, Any]:
    """Type into one uniquely matched UIA edit control; password edits are refused."""
    try:
        return {
            "ok": True,
            **_bridge().type_active_window_uia_text(
                text,
                expected_window_title,
                name=name,
                automation_id=automation_id,
                replace_existing=replace_existing,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="click_active_window_uia_element_verified", annotations=ACTION)
def click_active_window_uia_element_verified(
    expected_window_title: str,
    name: str | None = None,
    control_type: str | None = None,
    automation_id: str | None = None,
    button: str = "left",
    clicks: int = 1,
    settle_ms: int = 250,
    control_limit: int = 80,
    verification_policy: str = "any_confident_change",
    execution_mode: str = "safe",
    expected_post_element_name: str | None = None,
    expected_post_element_control_type: str | None = None,
    expected_post_element_automation_id: str | None = None,
    expected_post_element_present: bool | None = None,
    expected_post_window_title_contains: str | None = None,
) -> dict[str, Any]:
    """Perform one guarded UIA click and verify it. Fast mode is explicit opt-in and falls back safe for sensitive/ineligible targets."""
    try:
        return {
            "ok": True,
            **_bridge().click_active_window_uia_element_verified(
                expected_window_title,
                name=name,
                control_type=control_type,
                automation_id=automation_id,
                button=button,
                clicks=clicks,
                settle_ms=settle_ms,
                control_limit=control_limit,
                verification_policy=verification_policy,
                execution_mode=execution_mode,
                expected_post_element_name=expected_post_element_name,
                expected_post_element_control_type=expected_post_element_control_type,
                expected_post_element_automation_id=expected_post_element_automation_id,
                expected_post_element_present=expected_post_element_present,
                expected_post_window_title_contains=expected_post_window_title_contains,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_active_window_uia_text_verified", annotations=ACTION)
def type_active_window_uia_text_verified(
    text: Annotated[str, Field(max_length=LOGICAL_TEXT_MAX_CHARS)],
    expected_window_title: str,
    name: str | None = None,
    automation_id: str | None = None,
    replace_existing: bool = False,
    settle_ms: int = 250,
    control_limit: int = 80,
    verification_policy: str = "any_confident_change",
    expected_post_element_name: str | None = None,
    expected_post_element_control_type: str | None = None,
    expected_post_element_automation_id: str | None = None,
    expected_post_element_present: bool | None = None,
    expected_post_window_title_contains: str | None = None,
) -> dict[str, Any]:
    """Perform one guarded UIA text input, then require both verification policy and optional expected-post predicates; never auto-retry."""
    try:
        return {
            "ok": True,
            **_bridge().type_active_window_uia_text_verified(
                text,
                expected_window_title,
                name=name,
                automation_id=automation_id,
                replace_existing=replace_existing,
                settle_ms=settle_ms,
                control_limit=control_limit,
                verification_policy=verification_policy,
                expected_post_element_name=expected_post_element_name,
                expected_post_element_control_type=expected_post_element_control_type,
                expected_post_element_automation_id=expected_post_element_automation_id,
                expected_post_element_present=expected_post_element_present,
                expected_post_window_title_contains=expected_post_window_title_contains,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="drag_desktop", annotations=ACTION)
def drag_desktop(
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration_ms: int = 500,
) -> dict[str, Any]:
    """Left-button drag between two validated desktop coordinates."""
    try:
        return {
            "ok": True,
            **_bridge().drag(start_x, start_y, end_x, end_y, duration_ms=duration_ms),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="scroll_desktop", annotations=ACTION)
def scroll_desktop(delta: int, x: int | None = None, y: int | None = None) -> dict[str, Any]:
    """Scroll up/down at the current cursor or an optional validated desktop coordinate."""
    try:
        return {"ok": True, **_bridge().scroll(delta, x=x, y=y)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_desktop_text", annotations=ACTION)
def type_desktop_text(text: Annotated[str, Field(max_length=LOGICAL_TEXT_MAX_CHARS)]) -> dict[str, Any]:
    """Type Unicode text into the currently focused desktop control using Windows SendInput."""
    try:
        return {"ok": True, **_bridge().type_text(text)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_active_window_text", annotations=ACTION)
def type_active_window_text(text: Annotated[str, Field(max_length=LOGICAL_TEXT_MAX_CHARS)], expected_window_title: str) -> dict[str, Any]:
    """Type Unicode text only when the foreground title matches the expected window."""
    try:
        return {"ok": True, **_bridge().type_active_window_text(text, expected_window_title)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="press_desktop_key", annotations=ACTION)
def press_desktop_key(key: str) -> dict[str, Any]:
    """Press one safe navigation/editing key; destructive/system keys are not exposed."""
    try:
        return {"ok": True, **_bridge().press_key(key)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="press_active_window_key", annotations=ACTION)
def press_active_window_key(key: str, expected_window_title: str) -> dict[str, Any]:
    """Press one allowlisted desktop navigation/editing key only when the foreground title matches."""
    try:
        return {"ok": True, **_bridge().press_active_window_key(key, expected_window_title)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="game_key_down", annotations=ACTION)
def game_key_down(
    key: str,
    expected_window_title: str,
    backend: str = "SCAN",
) -> dict[str, Any]:
    """Press and keep one allowlisted game key down using SCAN, VK, or LEGACY input; MESSAGE is tap/hold-only."""
    try:
        return {"ok": True, **_bridge().game_key_down(key, expected_window_title, backend=backend)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="game_key_up", annotations=ACTION)
def game_key_up(key: str, backend: str = "SCAN") -> dict[str, Any]:
    """Release one allowlisted game key using the same backend used for key-down."""
    try:
        return {"ok": True, **_bridge().game_key_up(key, backend=backend)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="tap_game_key", annotations=ACTION)
def tap_game_key(
    key: str,
    expected_window_title: str,
    duration_ms: int = 60,
    backend: str = "SCAN",
) -> dict[str, Any]:
    """Tap one allowlisted game key using SCAN, VK, LEGACY, or bounded MESSAGE input."""
    try:
        return {
            "ok": True,
            **_bridge().tap_game_key(
                key,
                expected_window_title,
                duration_ms=duration_ms,
                backend=backend,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="hold_game_keys", annotations=ACTION)
def hold_game_keys(
    keys: list[str],
    expected_window_title: str,
    duration_ms: int = 500,
    backend: str = "SCAN",
) -> dict[str, Any]:
    """Hold 1-4 allowlisted game keys using SCAN, VK, LEGACY, or bounded MESSAGE, then always release them."""
    try:
        return {
            "ok": True,
            **_bridge().hold_game_keys(
                keys,
                expected_window_title,
                duration_ms=duration_ms,
                backend=backend,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="release_game_keys", annotations=ACTION)
def release_game_keys() -> dict[str, Any]:
    """Release every allowlisted Game Mode key to recover safely from a stuck movement/input state."""
    try:
        return {"ok": True, **_bridge().release_game_keys()}
    except Exception as exc:
        return _err(exc)


@server.tool(name="tap_game_mouse", annotations=ACTION)
def tap_game_mouse(
    button: str,
    expected_window_title: str,
    clicks: int = 1,
    interval_ms: int = 80,
) -> dict[str, Any]:
    """Tap the current left/right mouse button position 1-12 times without moving the cursor, guarded by foreground title."""
    try:
        return {
            "ok": True,
            **_bridge().tap_game_mouse(
                button,
                expected_window_title,
                clicks=clicks,
                interval_ms=interval_ms,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="hold_game_mouse", annotations=ACTION)
def hold_game_mouse(
    button: str,
    expected_window_title: str,
    duration_ms: int = 400,
) -> dict[str, Any]:
    """Hold the current left/right mouse button for 20-2000 ms, guarded by foreground title, then always release it."""
    try:
        return {
            "ok": True,
            **_bridge().hold_game_mouse(button, expected_window_title, duration_ms=duration_ms),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="press_desktop_hotkey", annotations=ACTION)
def press_desktop_hotkey(hotkey: str) -> dict[str, Any]:
    """Press one allowlisted hotkey such as CTRL+C, CTRL+V, CTRL+F, ALT+TAB, or SHIFT+TAB."""
    try:
        return {"ok": True, **_bridge().hotkey(hotkey)}
    except Exception as exc:
        return _err(exc)


if __name__ == "__main__":
    import os

    host = os.environ.get("DESKTOPBRIDGE_HOST", "127.0.0.1")
    port = int(os.environ.get("DESKTOPBRIDGE_PORT", "8792"))
    server.run(
        transport="streamable-http",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )
