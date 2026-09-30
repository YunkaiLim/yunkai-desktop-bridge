from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
import unittest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from bridge_manifest import BRIDGE_VERSION


async def main() -> None:
    root = Path(__file__).resolve().parent
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(root / "server_stdio.py")],
        cwd=str(root),
        env=dict(os.environ),
    )

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            print("TOOLS", ",".join(names))
            assert "get_desktop_screenshot" in names
            assert "get_desktop_active_window" in names
            assert "get_desktop_fast_context" in names
            assert "get_recent_desktop_action_audit" in names
            assert "get_desktop_operation_trace" in names
            assert "get_yunkai_watchdog_status" in names
            assert "type_secret_alias_into_active_window_uia" in names
            assert len(names) == 38
            assert "get_uia_status" in names
            assert "list_active_window_uia_elements" in names
            assert "list_active_window_controls" in names
            assert "click_desktop" in names
            assert "click_active_window_relative" in names
            assert "click_active_window_uia_element" in names
            assert "type_active_window_text" in names
            assert "type_active_window_uia_text" in names
            verified_click_tool = next(
                tool for tool in tools.tools if tool.name == "click_active_window_uia_element_verified"
            )
            assert "execution_mode" in verified_click_tool.input_schema.get("properties", {})
            secret_tool = next(tool for tool in tools.tools if tool.name == "type_secret_alias_into_active_window_uia")
            secret_properties = secret_tool.input_schema.get("properties", {})
            assert "alias" in secret_properties
            assert "expected_window_title" in secret_properties
            assert "secret" not in secret_properties
            assert "api_key" not in secret_properties
            assert "token" not in secret_properties
            assert all("shell" not in name.lower() for name in names)
            assert all("delete" not in name.lower() for name in names)
            assert all("shutdown" not in name.lower() for name in names)

            screen = await session.call_tool("get_desktop_screen_info", {})
            print("SCREEN_CONTENT_ITEMS", len(screen.content))

            active = await session.call_tool("get_desktop_active_window", {})
            print("ACTIVE_WINDOW_CONTENT_ITEMS", len(active.content))

            uia_status_result = await session.call_tool("get_uia_status", {})
            print("UIA_STATUS_CONTENT_ITEMS", len(uia_status_result.content))
            assert not uia_status_result.is_error

            uia_elements = await session.call_tool(
                "list_active_window_uia_elements",
                {"limit": 30, "max_depth": 10, "actionable_only": False},
            )
            print("UIA_ELEMENTS_CONTENT_ITEMS", len(uia_elements.content))
            assert not uia_elements.is_error

            fast_context = await session.call_tool(
                "get_desktop_fast_context",
                {"control_limit": 20, "use_vision": False},
            )
            print("FAST_CONTEXT_CONTENT_ITEMS", len(fast_context.content))
            assert not fast_context.is_error
            fast_context_text = "\n".join(
                getattr(item, "text", "")
                for item in fast_context.content
                if getattr(item, "type", None) == "text"
            )
            assert "capability_manifest" in fast_context_text
            assert "capability_state" in fast_context_text
            assert "planner_routing_hints" in fast_context_text
            assert "watchdog_status" in fast_context_text
            assert "secret_vault" in fast_context_text
            assert "secret_values_exposed" in fast_context_text
            assert "device_snapshot" in fast_context_text
            assert "yunkai.unified_device_contract" in fast_context_text
            assert "desktop.windows" in fast_context_text
            assert BRIDGE_VERSION in fast_context_text
            assert "explicit_fast_path_verified_uia_click" in fast_context_text
            assert "requires_new_tool_schema" in fast_context_text
            assert "availability_independent_from_permission" in fast_context_text
            assert "permission_denied" in fast_context_text
            assert "planner_owns_final_selection" in fast_context_text
            assert "automatic_fallback_execution" in fast_context_text

            audit = await session.call_tool(
                "get_recent_desktop_action_audit",
                {"limit": 5},
            )
            print("ACTION_AUDIT_CONTENT_ITEMS", len(audit.content))
            assert not audit.is_error

            trace = await session.call_tool(
                "get_desktop_operation_trace",
                {"operation_id": "op_00000000000000000000"},
            )
            print("OPERATION_TRACE_CONTENT_ITEMS", len(trace.content))
            assert not trace.is_error

            watchdog = await session.call_tool(
                "get_yunkai_watchdog_status",
                {"recent_alert_limit": 5},
            )
            print("WATCHDOG_STATUS_CONTENT_ITEMS", len(watchdog.content))
            assert not watchdog.is_error

            screenshot = await session.call_tool("get_desktop_screenshot", {})
            image_items = [item for item in screenshot.content if getattr(item, "type", None) == "image"]
            print("SCREENSHOT_IMAGE_ITEMS", len(image_items))
            assert image_items, "Expected desktop screenshot tool to return MCP image content"
            assert image_items[0].mime_type == "image/png"


class StdioMcpTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_mcp_surface(self) -> None:
        await main()


if __name__ == "__main__":
    asyncio.run(main())
