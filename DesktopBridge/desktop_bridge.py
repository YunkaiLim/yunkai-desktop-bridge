from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
import re
import sys
import time
from functools import wraps
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from PIL import ImageGrab
import win32api
import win32con
import win32gui
import win32process

from action_audit import (
    append_action_audit,
    append_action_completion_if_missing,
    append_permission_decision,
    new_operation_id,
    operation_trace,
    recent_action_audit,
)
from bridge_manifest import (
    desktop_capability_manifest,
    desktop_capability_state,
    desktop_device_snapshot,
    desktop_planner_routing_hints,
)
from local_vision import local_vision_status
from text_chunks import (
    LOGICAL_TEXT_MAX_CHARS,
    SENDINPUT_BATCH_UTF16_UNITS,
    SENDINPUT_BATCH_PAUSE_SECONDS,
    UI_TEXT_CHUNK_CHARS,
    plan_text_chunks,
)
from uia_native import NativeUIAutomation, UIAutomationError

_SHARED_ROOT = Path(__file__).resolve().parent.parent
if str(_SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(_SHARED_ROOT))

from yunkai_shared.runtime_policy import (  # noqa: E402 - shared root bootstrap
    RuntimePolicyError,
    evaluate_runtime_permission,
    normalize_runtime_profile,
    runtime_policy_manifest,
)
from yunkai_shared.verification_contract import (  # noqa: E402 - shared root bootstrap
    VERIFICATION_POLICIES,
    VerificationContractError,
    combine_verification_result,
    evaluate_verification_policy as evaluate_shared_verification_policy,
    normalize_verification_policy as normalize_shared_verification_policy,
)


class DesktopBridgeError(RuntimeError):
    pass


def _operation_scoped(method=None, *, permission_decision_required: bool = True):
    """Correlate and complete one top-level bridge action without logging inputs."""

    def decorate(action_method):
        @wraps(action_method)
        def wrapped(self, *args, **kwargs):
            existing_id = getattr(self, "_operation_id", None)
            is_root = not bool(existing_id)
            if is_root:
                operation_id = new_operation_id()
                operation_root_action = action_method.__name__
                self._operation_id = operation_id
                self._operation_root_action = operation_root_action
            else:
                operation_id = str(existing_id)
                operation_root_action = str(
                    getattr(self, "_operation_root_action", action_method.__name__)
                )

            try:
                result = action_method(self, *args, **kwargs)
                if isinstance(result, dict):
                    result.setdefault("operation_id", operation_id)
                    result.setdefault("operation_root_action", operation_root_action)
                if is_root:
                    result_status = result.get("status") if isinstance(result, dict) else None
                    reported_action = result.get("action") if isinstance(result, dict) else None
                    append_action_completion_if_missing(
                        {
                            "operation_id": operation_id,
                            "operation_root_action": operation_root_action,
                            "action": operation_root_action,
                            "outcome": "succeeded",
                            "completion_source": "operation_scope",
                            "permission_decision_required": bool(permission_decision_required),
                            "effect_status": "reported_success",
                            "result_metadata": {
                                "status": str(result_status)[:40] if result_status is not None else None,
                                "reported_action": (
                                    str(reported_action)[:120]
                                    if reported_action is not None
                                    else None
                                ),
                            },
                            "input_metadata": {
                                "metadata_only": True,
                                "content_logged": False,
                                **({
                                    "characters_total": result["characters"],
                                    "chunk_count": result["chunk_count"],
                                    "chunk_size_policy": result["chunk_size_policy"],
                                } if isinstance(result, dict) and all(
                                    key in result for key in ("characters", "chunk_count", "chunk_size_policy")
                                ) else {}),
                            },
                            "verification_passed": None,
                            "retry_performed": False,
                        }
                    )
                return result
            except Exception as exc:
                if is_root:
                    append_action_completion_if_missing(
                        {
                            "operation_id": operation_id,
                            "operation_root_action": operation_root_action,
                            "action": operation_root_action,
                            "outcome": (
                                "refused" if isinstance(exc, DesktopBridgeError) else "error"
                            ),
                            "completion_source": "operation_scope",
                            "permission_decision_required": bool(permission_decision_required),
                            "effect_status": "not_confirmed_after_failure",
                            "input_metadata": {
                                "metadata_only": True,
                                "content_logged": False,
                            },
                            "failure": {
                                "type": type(exc).__name__[:120],
                                "stage": "operation_did_not_return_success",
                                "message_logged": False,
                            },
                            "verification_passed": None,
                            "retry_performed": False,
                        }
                    )
                raise
            finally:
                if is_root:
                    self._operation_id = None
                    self._operation_root_action = None

        return wrapped

    if method is None:
        return decorate
    return decorate(method)


SAFE_KEYS: dict[str, int] = {
    "BACKSPACE": win32con.VK_BACK,
    "TAB": win32con.VK_TAB,
    "ENTER": win32con.VK_RETURN,
    "ESCAPE": win32con.VK_ESCAPE,
    "SPACE": win32con.VK_SPACE,
    "LEFT": win32con.VK_LEFT,
    "UP": win32con.VK_UP,
    "RIGHT": win32con.VK_RIGHT,
    "DOWN": win32con.VK_DOWN,
    "HOME": win32con.VK_HOME,
    "END": win32con.VK_END,
    "PAGEUP": win32con.VK_PRIOR,
    "PAGEDOWN": win32con.VK_NEXT,
}

VISUAL_VERIFY_HAMMING_THRESHOLD = 8
UIA_ACTION_PRE_INPUT_DELAY_SECONDS = 0.08
POST_ACTION_OBSERVATION_MAX_ATTEMPTS = 4
POST_ACTION_OBSERVATION_INTERVAL_SECONDS = 0.20
DESKTOP_RUNTIME_PROFILE_ENV = "YUNKAI_DESKTOP_RUNTIME_PROFILE"
DESKTOP_EXECUTION_MODES = frozenset({"safe", "fast"})
FAST_PATH_SETTLE_MAX_MS = 100
FAST_PATH_MIN_CONTEXT_LIMIT = 300
FAST_PATH_SAFE_CONTROL_TYPES = frozenset({"button", "link", "tab", "checkbox", "radio", "listitem", "treeitem"})
FAST_PATH_SENSITIVE_TERMS = (
    "delete", "remove", "erase", "clear", "reset", "uninstall", "format", "overwrite", "replace", "save",
    "pay", "payment", "purchase", "buy", "checkout", "order", "transfer", "send", "submit", "confirm",
    "approve", "allow", "grant", "permission", "install", "update", "restart", "reboot", "shutdown", "close",
    "quit", "exit", "terminate", "kill", "logout", "log out", "sign out", "revoke", "disconnect", "upload",
    "publish", "deploy", "merge", "secret", "password", "credential", "api key",
    "删除", "移除", "清除", "清空", "重置", "卸载", "格式化", "覆盖", "替换", "保存", "付款", "支付",
    "购买", "下单", "结账", "转账", "发送", "提交", "确认", "批准", "允许", "授权", "权限", "安装",
    "更新", "重启", "关机", "关闭", "退出", "注销", "撤销", "断开", "上传", "发布", "部署", "合并",
    "密钥", "密码", "凭据",
)


SAFE_HOTKEYS: dict[str, tuple[int, ...]] = {
    "CTRL+A": (win32con.VK_CONTROL, ord("A")),
    "CTRL+C": (win32con.VK_CONTROL, ord("C")),
    "CTRL+V": (win32con.VK_CONTROL, ord("V")),
    "CTRL+X": (win32con.VK_CONTROL, ord("X")),
    "CTRL+Z": (win32con.VK_CONTROL, ord("Z")),
    "CTRL+Y": (win32con.VK_CONTROL, ord("Y")),
    "CTRL+F": (win32con.VK_CONTROL, ord("F")),
    "ALT+TAB": (win32con.VK_MENU, win32con.VK_TAB),
    "SHIFT+TAB": (win32con.VK_SHIFT, win32con.VK_TAB),
}

# Game Mode intentionally excludes CTRL, ALT, WIN, DELETE, and other
# system-level modifier inputs. F1-F4 are allowed only behind the strict
# foreground-game guard because ZZZ uses them as in-game menu shortcuts.
SAFE_GAME_KEYS: dict[str, int] = {
    "W": ord("W"),
    "A": ord("A"),
    "S": ord("S"),
    "D": ord("D"),
    "E": ord("E"),
    "Q": ord("Q"),
    "F": ord("F"),
    "R": ord("R"),
    "V": ord("V"),
    "C": ord("C"),
    "M": ord("M"),
    "N": ord("N"),
    "P": ord("P"),
    "J": ord("J"),
    "O": ord("O"),
    "TAB": win32con.VK_TAB,
    "ENTER": win32con.VK_RETURN,
    "ESCAPE": win32con.VK_ESCAPE,
    "SPACE": win32con.VK_SPACE,
    "SHIFT": win32con.VK_SHIFT,
    "F1": win32con.VK_F1,
    "F2": win32con.VK_F2,
    "F3": win32con.VK_F3,
    "F4": win32con.VK_F4,
    "1": ord("1"),
    "2": ord("2"),
    "3": ord("3"),
    "4": ord("4"),
}

GAME_INPUT_BACKENDS = {"SCAN", "VK", "LEGACY", "MESSAGE"}
DEFAULT_GAME_INPUT_BACKEND = "SCAN"
_GAME_KEYS_DOWN: set[tuple[str, str]] = set()


@dataclass(frozen=True)
class DesktopWindow:
    hwnd: int
    title: str
    process_id: int
    rect: tuple[int, int, int, int]
    visible: bool
    minimized: bool

    def as_dict(self) -> dict[str, Any]:
        left, top, right, bottom = self.rect
        return {
            "hwnd": self.hwnd,
            "title": self.title,
            "process_id": self.process_id,
            "rect": [left, top, right, bottom],
            "width": max(0, right - left),
            "height": max(0, bottom - top),
            "visible": self.visible,
            "minimized": self.minimized,
        }


@dataclass(frozen=True)
class DesktopControl:
    hwnd: int
    parent_hwnd: int
    text: str
    class_name: str
    role: str
    rect: tuple[int, int, int, int]
    visible: bool
    enabled: bool
    control_id: int

    def as_dict(self) -> dict[str, Any]:
        left, top, right, bottom = self.rect
        return {
            "hwnd": self.hwnd,
            "parent_hwnd": self.parent_hwnd,
            "text": self.text,
            "class_name": self.class_name,
            "role": self.role,
            "control_id": self.control_id,
            "rect": [left, top, right, bottom],
            "width": max(0, right - left),
            "height": max(0, bottom - top),
            "visible": self.visible,
            "enabled": self.enabled,
        }


class DesktopBridge:
    """A deliberately limited Windows desktop bridge.

    There is no public arbitrary shell/PowerShell/cmd execution, file deletion,
    app uninstall, shutdown, registry, or raw process-termination capability.
    """

    def runtime_profile(self) -> str:
        """Return the fixed local runtime profile; callers cannot select it per action."""
        configured = getattr(self, "_runtime_profile_override", None)
        if configured is None:
            configured = os.environ.get(DESKTOP_RUNTIME_PROFILE_ENV)
        try:
            return normalize_runtime_profile(configured)
        except RuntimePolicyError as exc:
            raise DesktopBridgeError(str(exc)) from exc

    def runtime_policy(self) -> dict[str, Any]:
        try:
            return runtime_policy_manifest(self.runtime_profile())
        except RuntimePolicyError as exc:
            raise DesktopBridgeError(str(exc)) from exc

    @staticmethod
    def capability_manifest() -> dict[str, Any]:
        return desktop_capability_manifest()

    def _operation_metadata(self, fallback_action: str) -> dict[str, str]:
        operation_id = getattr(self, "_operation_id", None)
        root_action = getattr(self, "_operation_root_action", None)
        if not operation_id:
            operation_id = new_operation_id()
        if not root_action:
            root_action = fallback_action
        return {
            "operation_id": str(operation_id),
            "operation_root_action": str(root_action)[:120],
        }

    def _require_permission_tier(self, required_tier: str, *, action: str) -> dict[str, Any]:
        try:
            result = evaluate_runtime_permission(self.runtime_profile(), required_tier)
        except RuntimePolicyError as exc:
            raise DesktopBridgeError(str(exc)) from exc

        operation = self._operation_metadata(action)
        result = {**result, **operation}
        append_permission_decision(
            {
                **operation,
                "action": str(action)[:120],
                "outcome": "allowed" if result["allowed"] else "denied",
                "runtime_profile": result["runtime_profile"],
                "required_tier": result["required_tier"],
                "allowed": bool(result["allowed"]),
                "decision": result["decision"],
                "reason": str(result["reason"])[:300],
                "policy_schema_version": result["schema_version"],
                "profile_source": "bridge_runtime_configuration",
                "model_selectable_profile": False,
                "self_escalation": False,
            }
        )

        if not result["allowed"]:
            raise DesktopBridgeError(
                f"Runtime policy refused {action}: profile {result['runtime_profile']} "
                f"does not permit {result['required_tier']}."
            )
        return result

    def virtual_screen(self) -> tuple[int, int, int, int]:
        left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
        top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
        width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
        height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
        if width <= 0 or height <= 0:
            raise DesktopBridgeError("Windows reported an invalid virtual desktop size.")
        return int(left), int(top), int(width), int(height)

    def screenshot_png(self) -> bytes:
        image = ImageGrab.grab(all_screens=True)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def clamp_region_to_virtual_screen(
        self,
        left: int,
        top: int,
        right: int,
        bottom: int,
    ) -> tuple[int, int, int, int]:
        """Clamp a window rectangle to the visible virtual desktop.

        Maximized Windows apps can report frame/shadow bounds a few pixels beyond
        the monitor. Window screenshots should crop those invisible margins rather
        than fail, while the public arbitrary-region screenshot remains strict.
        """
        left, top, right, bottom = map(int, (left, top, right, bottom))
        vleft, vtop, vwidth, vheight = self.virtual_screen()
        vright, vbottom = vleft + vwidth, vtop + vheight
        clipped = (
            max(left, vleft),
            max(top, vtop),
            min(right, vright),
            min(bottom, vbottom),
        )
        if clipped[2] <= clipped[0] or clipped[3] <= clipped[1]:
            raise DesktopBridgeError("Window rectangle does not overlap the visible virtual desktop.")
        return clipped

    def screenshot_region_png(self, left: int, top: int, right: int, bottom: int) -> bytes:
        left, top, right, bottom = map(int, (left, top, right, bottom))
        if right <= left or bottom <= top:
            raise DesktopBridgeError("Screenshot region must have positive width and height.")
        vleft, vtop, vwidth, vheight = self.virtual_screen()
        vright, vbottom = vleft + vwidth, vtop + vheight
        if left < vleft or top < vtop or right > vright or bottom > vbottom:
            raise DesktopBridgeError(
                f"Region [{left},{top},{right},{bottom}] is outside virtual desktop "
                f"[{vleft},{vtop},{vright},{vbottom}]."
            )
        image = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def active_window_screenshot_png(self) -> tuple[bytes, int, int, DesktopWindow]:
        window = self.active_window()
        left, top, right, bottom = self.clamp_region_to_virtual_screen(*window.rect)
        return (
            self.screenshot_region_png(left, top, right, bottom),
            right - left,
            bottom - top,
            window,
        )

    @staticmethod
    def _window_from_hwnd(hwnd: int) -> DesktopWindow:
        if not win32gui.IsWindow(hwnd):
            raise DesktopBridgeError(f"Window handle {hwnd} does not exist.")
        title = win32gui.GetWindowText(hwnd)
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        try:
            rect = tuple(int(v) for v in win32gui.GetWindowRect(hwnd))
        except Exception:
            rect = (0, 0, 0, 0)
        return DesktopWindow(
            hwnd=int(hwnd),
            title=title,
            process_id=int(pid),
            rect=rect,
            visible=bool(win32gui.IsWindowVisible(hwnd)),
            minimized=bool(win32gui.IsIconic(hwnd)),
        )

    def active_window(self) -> DesktopWindow:
        hwnd = win32gui.GetForegroundWindow()
        if not hwnd:
            raise DesktopBridgeError("No foreground window is available.")
        return self._window_from_hwnd(hwnd)

    def list_windows(self, title_contains: str | None = None, limit: int = 100) -> list[DesktopWindow]:
        needle = (title_contains or "").casefold().strip()
        limit = max(1, min(300, int(limit)))
        result: list[DesktopWindow] = []

        def callback(hwnd: int, _extra: Any) -> bool:
            if len(result) >= limit:
                return False
            if not win32gui.IsWindowVisible(hwnd):
                return True
            title = win32gui.GetWindowText(hwnd).strip()
            if not title:
                return True
            if needle and needle not in title.casefold():
                return True
            result.append(self._window_from_hwnd(hwnd))
            return True

        win32gui.EnumWindows(callback, None)
        return result

    @staticmethod
    def _infer_control_role(class_name: str) -> str:
        value = class_name.casefold()
        if "button" in value:
            return "button"
        if "edit" in value:
            return "text_input"
        if "combobox" in value:
            return "combo_box"
        if "listbox" in value or "listview" in value:
            return "list"
        if "treeview" in value:
            return "tree"
        if "toolbar" in value:
            return "toolbar"
        if "tabcontrol" in value:
            return "tab_control"
        if "scrollbar" in value:
            return "scrollbar"
        if "static" in value:
            return "label"
        return "control"

    @staticmethod
    def _keep_textless_control(class_name: str) -> bool:
        return DesktopBridge._infer_control_role(class_name) in {
            "button",
            "text_input",
            "combo_box",
            "list",
            "tree",
            "toolbar",
            "tab_control",
            "scrollbar",
        }

    def list_window_controls(
        self,
        hwnd: int | None = None,
        text_contains: str | None = None,
        limit: int = 100,
        include_empty_text: bool = False,
    ) -> tuple[list[DesktopControl], bool]:
        root = self.active_window() if hwnd is None else self._window_from_hwnd(int(hwnd))
        needle = (text_contains or "").casefold().strip()
        limit = max(1, min(500, int(limit)))
        result: list[DesktopControl] = []
        truncated = False

        def callback(child_hwnd: int, _extra: Any) -> bool:
            nonlocal truncated
            if len(result) >= limit:
                truncated = True
                return False
            if not win32gui.IsWindowVisible(child_hwnd):
                return True
            try:
                text = win32gui.GetWindowText(child_hwnd).strip()
            except Exception:
                text = ""
            try:
                class_name = win32gui.GetClassName(child_hwnd).strip()
            except Exception:
                class_name = ""
            if not include_empty_text and not text and not self._keep_textless_control(class_name):
                return True
            searchable = f"{text} {class_name}".casefold()
            if needle and needle not in searchable:
                return True
            try:
                rect = tuple(int(v) for v in win32gui.GetWindowRect(child_hwnd))
            except Exception:
                rect = (0, 0, 0, 0)
            try:
                control_id = int(win32gui.GetDlgCtrlID(child_hwnd))
            except Exception:
                control_id = 0
            try:
                parent_hwnd = int(win32gui.GetParent(child_hwnd) or root.hwnd)
            except Exception:
                parent_hwnd = root.hwnd
            result.append(
                DesktopControl(
                    hwnd=int(child_hwnd),
                    parent_hwnd=parent_hwnd,
                    text=text,
                    class_name=class_name,
                    role=self._infer_control_role(class_name),
                    rect=rect,
                    visible=True,
                    enabled=bool(win32gui.IsWindowEnabled(child_hwnd)),
                    control_id=control_id,
                )
            )
            return True

        win32gui.EnumChildWindows(root.hwnd, callback, None)
        return result, truncated

    def list_uia_elements(
        self,
        hwnd: int | None = None,
        limit: int = 120,
        max_depth: int = 12,
    ) -> tuple[list[dict[str, Any]], bool]:
        root = self.active_window() if hwnd is None else self._window_from_hwnd(int(hwnd))
        limit = max(1, min(500, int(limit)))
        max_depth = max(0, min(30, int(max_depth)))
        elements = NativeUIAutomation().list_window_elements(
            root.hwnd,
            limit=limit,
            max_depth=max_depth,
        )
        return [element.as_dict() for element in elements], len(elements) >= limit

    @staticmethod
    def _compact_uia_elements(
        elements: list[dict[str, Any]],
        limit: int,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(200, int(limit)))

        def visible(element: dict[str, Any]) -> bool:
            rect = element.get("rect") or [0, 0, 0, 0]
            return (
                not bool(element.get("offscreen"))
                and len(rect) == 4
                and int(rect[2]) > int(rect[0])
                and int(rect[3]) > int(rect[1])
            )

        def compact(element: dict[str, Any]) -> dict[str, Any]:
            result = {
                "name": "" if element.get("is_password") else str(element.get("name", ""))[:500],
                "control_type": str(element.get("control_type", ""))[:100],
                "automation_id": str(element.get("automation_id", ""))[:300],
                "class_name": str(element.get("class_name", ""))[:300],
                "framework_id": str(element.get("framework_id", ""))[:100],
                "rect": list(element.get("rect") or [0, 0, 0, 0]),
                "enabled": bool(element.get("enabled")),
                "offscreen": bool(element.get("offscreen")),
                "depth": int(element.get("depth", 0)),
                "actionable": bool(element.get("actionable")),
            }
            aria_role = str(element.get("aria_role", ""))[:200]
            if aria_role:
                result["aria_role"] = aria_role
            return result

        visible_elements = [element for element in elements if visible(element)]

        def rank(element: dict[str, Any]) -> tuple[int, int]:
            score = 0
            name = str(element.get("name", ""))
            control_type = str(element.get("control_type", ""))
            depth = int(element.get("depth", 0))
            if element.get("actionable"):
                score += 100
            if name:
                score += 20
            if control_type in {"edit", "button", "hyperlink", "checkbox", "radio_button", "combobox", "tab_item", "list_item"}:
                score += 15
            if control_type in {"edit", "document"}:
                score += 15
            # Chromium/Electron page accessibility tends to live deeper than
            # browser chrome. Depth is therefore a useful generic tie-breaker
            # without hard-coding a browser-specific y coordinate.
            score += min(depth, 20) * 4
            if name.casefold() in {"close", "minimize", "restore", "maximize"}:
                score -= 100
            return score, depth

        semantic_candidates = [
            element
            for element in visible_elements
            if element.get("name")
            or element.get("actionable")
            or element.get("control_type") in {"document", "window", "pane", "toolbar", "tab", "menu_bar"}
        ]
        semantic_candidates.sort(key=rank, reverse=True)

        selected: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for element in semantic_candidates:
            key = (
                element.get("control_type"),
                element.get("name"),
                tuple(element.get("rect") or []),
                element.get("automation_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            selected.append(compact(element))
            if len(selected) >= limit:
                break
        return selected

    def active_window_visual_hash(self, hash_size: int = 8) -> str:
        hash_size = max(4, min(16, int(hash_size)))
        window = self.active_window()
        left, top, right, bottom = self.clamp_region_to_virtual_screen(*window.rect)
        image = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)
        grayscale = image.convert("L").resize((hash_size + 1, hash_size))
        pixels = list(grayscale.getdata())
        value = 0
        bit_count = 0
        stride = hash_size + 1
        for row in range(hash_size):
            offset = row * stride
            for column in range(hash_size):
                value = (value << 1) | int(pixels[offset + column] > pixels[offset + column + 1])
                bit_count += 1
        width = max(1, (bit_count + 3) // 4)
        return f"{value:0{width}x}"

    def fast_context(
        self,
        control_limit: int = 80,
        include_visual_hash: bool = False,
    ) -> dict[str, Any]:
        window = self.active_window()
        left, top, width, height = self.virtual_screen()
        controls, truncated = self.list_window_controls(
            hwnd=window.hwnd,
            limit=control_limit,
            include_empty_text=False,
        )
        control_dicts = [control.as_dict() for control in controls]

        uia_error = ""
        uia_raw: list[dict[str, Any]] = []
        uia_truncated = False
        try:
            # Read somewhat more than the compact response limit so we can rank
            # actionable/named elements before trimming the context payload.
            uia_raw, uia_truncated = self.list_uia_elements(
                hwnd=window.hwnd,
                limit=max(120, min(300, int(control_limit) * 2)),
                max_depth=16,
            )
        except (UIAutomationError, OSError, RuntimeError) as exc:
            uia_error = str(exc)
        uia_elements = self._compact_uia_elements(uia_raw, control_limit)
        uia_actionable_count = sum(1 for element in uia_elements if element.get("actionable"))
        uia_informative_count = sum(
            1
            for element in uia_elements
            if element.get("name") or element.get("actionable")
        )

        semantic_payload = {
            "window": window.as_dict(),
            "uia_elements": uia_elements,
            "controls": control_dicts,
        }
        semantic_signature = hashlib.sha256(
            json.dumps(semantic_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]

        uia_informative = uia_informative_count >= 5 or uia_actionable_count >= 3
        win32_informative = len(controls) > 3
        semantic_sparse = not (uia_informative or win32_informative)
        if uia_informative:
            semantic_source = "uia"
            vision_reason = "Microsoft UI Automation exposes enough named/actionable elements for a semantic-first attempt."
        elif win32_informative:
            semantic_source = "win32"
            vision_reason = "Win32 child controls are informative enough for a semantic-first attempt."
        else:
            semantic_source = "sparse"
            vision_reason = "UI Automation and Win32 controls are both sparse; screenshot vision is recommended."

        runtime_policy = self.runtime_policy()
        capability_state = desktop_capability_state(
            semantic_source=semantic_source,
            uia_enabled=not bool(uia_error),
            vision_recommended=semantic_sparse,
            local_vision_status=local_vision_status(Path(__file__).resolve().parent),
            runtime_policy=runtime_policy,
        )
        planner_routing_hints = desktop_planner_routing_hints(
            capability_state=capability_state,
            runtime_policy=runtime_policy,
        )
        capability_manifest = self.capability_manifest()
        device_snapshot = desktop_device_snapshot(
            capability_manifest=capability_manifest,
            capability_state=capability_state,
            planner_routing_hints=planner_routing_hints,
            runtime_policy=runtime_policy,
        )

        result: dict[str, Any] = {
            "capability_manifest": capability_manifest,
            "capability_state": capability_state,
            "planner_routing_hints": planner_routing_hints,
            "runtime_policy": runtime_policy,
            "device_snapshot": device_snapshot,
            "active_window": window.as_dict(),
            "cursor": self.cursor_position(),
            "virtual_screen": {
                "left": left,
                "top": top,
                "width": width,
                "height": height,
                "right": left + width,
                "bottom": top + height,
            },
            "semantic_source": semantic_source,
            "uia_enabled": not bool(uia_error),
            "uia_elements": uia_elements,
            "uia_count": len(uia_raw),
            "uia_returned_count": len(uia_elements),
            "uia_actionable_count": uia_actionable_count,
            "uia_truncated": uia_truncated,
            "controls": control_dicts,
            "control_count": len(controls),
            "controls_truncated": truncated,
            "semantic_signature": semantic_signature,
            "vision_recommended": semantic_sparse,
            "vision_reason": vision_reason,
        }
        if uia_error:
            result["uia_error"] = uia_error
        if include_visual_hash:
            result["visual_dhash"] = self.active_window_visual_hash()
        return result

    @staticmethod
    def _hex_hamming_distance(left: str, right: str) -> int:
        left_value = str(left or "").strip().lower()
        right_value = str(right or "").strip().lower()
        if not left_value or not right_value or len(left_value) != len(right_value):
            raise DesktopBridgeError("Visual hashes must be non-empty hexadecimal strings of equal length.")
        if not re.fullmatch(r"[0-9a-f]+", left_value) or not re.fullmatch(r"[0-9a-f]+", right_value):
            raise DesktopBridgeError("Visual hashes must contain hexadecimal characters only.")
        return (int(left_value, 16) ^ int(right_value, 16)).bit_count()

    def verify_state_change(
        self,
        previous_semantic_signature: str,
        previous_visual_dhash: str | None = None,
        previous_window_hwnd: int | None = None,
        previous_window_title: str | None = None,
        control_limit: int = 80,
    ) -> dict[str, Any]:
        previous_signature = str(previous_semantic_signature or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{24}", previous_signature):
            raise DesktopBridgeError("previous_semantic_signature must be the 24-character hex signature returned by Fast Context.")

        use_visual_hash = bool(str(previous_visual_dhash or "").strip())
        current = self.fast_context(
            control_limit=control_limit,
            include_visual_hash=use_visual_hash,
        )
        active = current["active_window"]
        semantic_changed = current["semantic_signature"] != previous_signature

        window_hwnd_changed: bool | None = None
        if previous_window_hwnd is not None:
            window_hwnd_changed = int(active["hwnd"]) != int(previous_window_hwnd)

        window_title_changed: bool | None = None
        if previous_window_title is not None:
            window_title_changed = str(active["title"]) != str(previous_window_title)

        visual_changed: bool | None = None
        visual_change_confident: bool | None = None
        visual_hamming_distance: int | None = None
        current_visual_dhash = current.get("visual_dhash")
        if use_visual_hash:
            previous_hash = str(previous_visual_dhash or "").strip().lower()
            visual_hamming_distance = self._hex_hamming_distance(previous_hash, str(current_visual_dhash))
            visual_changed = visual_hamming_distance > 0
            visual_change_confident = visual_hamming_distance >= VISUAL_VERIFY_HAMMING_THRESHOLD

        window_identity_changed = bool(window_hwnd_changed or window_title_changed)
        state_change_detected = bool(
            semantic_changed
            or window_identity_changed
            or visual_change_confident is True
        )

        return {
            "status": "ok",
            "action": "verify_state_change",
            "state_change_detected": state_change_detected,
            "semantic_changed": semantic_changed,
            "visual_changed": visual_changed,
            "visual_change_confident": visual_change_confident,
            "visual_hamming_distance": visual_hamming_distance,
            "visual_hamming_threshold": VISUAL_VERIFY_HAMMING_THRESHOLD,
            "window_identity_changed": window_identity_changed,
            "window_hwnd_changed": window_hwnd_changed,
            "window_title_changed": window_title_changed,
            "previous": {
                "semantic_signature": previous_signature,
                "visual_dhash": str(previous_visual_dhash or "").strip().lower() or None,
                "window_hwnd": int(previous_window_hwnd) if previous_window_hwnd is not None else None,
                "window_title": previous_window_title,
            },
            "current": {
                "semantic_signature": current["semantic_signature"],
                "visual_dhash": current_visual_dhash,
                "window_hwnd": active["hwnd"],
                "window_title": active["title"],
                "semantic_source": current.get("semantic_source"),
                "uia_actionable_count": current.get("uia_actionable_count", 0),
                "control_count": current.get("control_count", 0),
            },
        }

    @staticmethod
    def _normalize_verification_policy(value: str | None) -> str:
        try:
            return normalize_shared_verification_policy(value)
        except VerificationContractError as exc:
            raise DesktopBridgeError(
                "Unsupported verification_policy. Allowed: " + ", ".join(sorted(VERIFICATION_POLICIES))
            ) from exc

    @staticmethod
    def _normalize_execution_mode(value: str | None) -> str:
        mode = str(value or "safe").strip().casefold()
        if mode not in DESKTOP_EXECUTION_MODES:
            raise DesktopBridgeError(
                "Unsupported execution_mode. Allowed: " + ", ".join(sorted(DESKTOP_EXECUTION_MODES))
            )
        return mode

    @staticmethod
    def _fast_path_sensitive_selector_reason(
        *,
        name: str | None = None,
        automation_id: str | None = None,
    ) -> str | None:
        selector_text = " ".join(
            part for part in (str(name or "").strip(), str(automation_id or "").strip()) if part
        ).casefold()
        if not selector_text:
            return None
        for term in FAST_PATH_SENSITIVE_TERMS:
            if term.casefold() in selector_text:
                return f"sensitive_selector:{term}"
        return None

    @classmethod
    def _fast_path_preflight_reason(
        cls,
        *,
        name: str | None,
        control_type: str | None,
        automation_id: str | None,
        button: str,
        clicks: int,
        verification_policy: str,
    ) -> str | None:
        if str(button or "left").strip().casefold() != "left" or int(clicks) != 1:
            return "fast_path_is_limited_to_one_left_click"
        if verification_policy == "visual_only":
            return "visual_only_verification_requires_safe_path"
        requested_type = str(control_type or "").strip().casefold()
        if requested_type and requested_type not in FAST_PATH_SAFE_CONTROL_TYPES:
            return "control_type_not_fast_safe"
        return cls._fast_path_sensitive_selector_reason(name=name, automation_id=automation_id)

    @classmethod
    def _select_fast_context_uia_element(
        cls,
        context: dict[str, Any],
        *,
        name: str | None = None,
        control_type: str | None = None,
        automation_id: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        name_value = str(name or "").strip()
        automation_value = str(automation_id or "").strip()
        type_value = str(control_type or "").strip().casefold()
        if not name_value and not automation_value:
            return None, "selector_requires_name_or_automation_id"
        if len(name_value) > 500 or len(automation_value) > 500 or len(type_value) > 100:
            raise DesktopBridgeError("UIA selector is too long.")
        if bool(context.get("uia_truncated")):
            return None, "uia_snapshot_truncated"
        if int(context.get("uia_count") or 0) > int(context.get("uia_returned_count") or 0):
            return None, "uia_snapshot_not_complete"

        matches: list[dict[str, Any]] = []
        for element in list(context.get("uia_elements") or []):
            if name_value and str(element.get("name", "")).casefold() != name_value.casefold():
                continue
            if automation_value and str(element.get("automation_id", "")).casefold() != automation_value.casefold():
                continue
            if type_value and str(element.get("control_type", "")).casefold() != type_value:
                continue
            matches.append(element)

        if not matches:
            return None, "target_not_in_fast_context"
        if len(matches) != 1:
            return None, "target_ambiguous_in_fast_context"
        element = matches[0]
        if not element.get("actionable"):
            return None, "target_not_actionable_in_fast_context"
        if element.get("is_password"):
            return None, "password_target_requires_safe_path"
        actual_type = str(element.get("control_type", "")).strip().casefold()
        if actual_type not in FAST_PATH_SAFE_CONTROL_TYPES:
            return None, "matched_control_type_not_fast_safe"
        sensitive_reason = cls._fast_path_sensitive_selector_reason(
            name=str(element.get("name", "")),
            automation_id=str(element.get("automation_id", "")),
        )
        if sensitive_reason:
            return None, sensitive_reason
        return element, None

    def _click_fast_context_uia_element(
        self,
        expected_window_title: str,
        *,
        context: dict[str, Any],
        element: dict[str, Any],
    ) -> dict[str, Any]:
        expected_hwnd = int(dict(context.get("active_window") or {}).get("hwnd") or 0)
        window = self._require_active_title(expected_window_title)
        if not expected_hwnd or int(window.hwnd) != expected_hwnd:
            raise DesktopBridgeError("Fast path aborted because the foreground window changed after observation.")
        blocked_names = {"close", "minimize", "restore", "maximize"}
        if str(element.get("name", "")).strip().casefold() in blocked_names:
            raise DesktopBridgeError("Window-level Close/Minimize/Restore/Maximize controls are not exposed through UIA actions.")
        x, y = self._uia_element_click_point(window, element)
        time.sleep(UIA_ACTION_PRE_INPUT_DELAY_SECONDS)
        window_after_delay = self._require_active_title(expected_window_title)
        if int(window_after_delay.hwnd) != expected_hwnd:
            raise DesktopBridgeError("Fast path aborted because the foreground window changed before input.")
        result = self.click(x, y, button="left", clicks=1)
        return {
            **result,
            "action": "click_active_window_uia_element",
            "window": window.title,
            "matched_element": self._compact_uia_elements([element], 1)[0],
            "target_source": "fresh_fast_context",
        }

    @classmethod
    def evaluate_verification_policy(
        cls,
        verification: dict[str, Any],
        verification_policy: str | None = None,
    ) -> dict[str, Any]:
        policy = cls._normalize_verification_policy(verification_policy)
        shared = evaluate_shared_verification_policy(
            {
                "state_change_detected": bool(verification.get("state_change_detected")),
                "semantic_changed": bool(verification.get("semantic_changed")),
                "surface_identity_changed": bool(verification.get("window_identity_changed")),
                "visual_change_confident": bool(verification.get("visual_change_confident")),
            },
            policy,
        )
        signals = dict(shared.get("signals") or {})
        return {
            "schema_version": shared.get("schema_version"),
            "verification_policy": shared["verification_policy"],
            "policy_passed": bool(shared["policy_passed"]),
            "policy_reason": str(shared["policy_reason"]).replace("surface identity", "foreground window identity"),
            "signals": {
                "state_change_detected": bool(signals.get("state_change_detected")),
                "semantic_changed": bool(signals.get("semantic_changed")),
                "window_identity_changed": bool(signals.get("surface_identity_changed")),
                "visual_change_confident": bool(signals.get("visual_change_confident")),
            },
        }

    @staticmethod
    def _normalize_expected_post_request(
        *,
        expected_element_name: str | None = None,
        expected_element_control_type: str | None = None,
        expected_element_automation_id: str | None = None,
        expected_element_present: bool | None = None,
        expected_window_title_contains: str | None = None,
    ) -> dict[str, Any]:
        name_value = str(expected_element_name or "").strip()
        type_value = str(expected_element_control_type or "").strip().casefold()
        automation_value = str(expected_element_automation_id or "").strip()
        title_value = str(expected_window_title_contains or "").strip()
        if len(name_value) > 500 or len(type_value) > 100 or len(automation_value) > 500:
            raise DesktopBridgeError("Expected-post UIA selector is too long.")
        if len(title_value) > 200:
            raise DesktopBridgeError("expected_post_window_title_contains must be at most 200 characters.")

        selector_configured = bool(name_value or type_value or automation_value)
        if expected_element_present is not None and not selector_configured:
            raise DesktopBridgeError(
                "expected_post_element_present requires an expected-post UIA selector."
            )
        normalized_present = expected_element_present
        if selector_configured and normalized_present is None:
            normalized_present = True
        return {
            "name": name_value,
            "control_type": type_value,
            "automation_id": automation_value,
            "element_present": normalized_present,
            "window_title_contains": title_value,
            "selector_configured": selector_configured,
        }

    def evaluate_expected_postconditions(
        self,
        *,
        expected_element_name: str | None = None,
        expected_element_control_type: str | None = None,
        expected_element_automation_id: str | None = None,
        expected_element_present: bool | None = None,
        expected_window_title_contains: str | None = None,
    ) -> dict[str, Any]:
        request = self._normalize_expected_post_request(
            expected_element_name=expected_element_name,
            expected_element_control_type=expected_element_control_type,
            expected_element_automation_id=expected_element_automation_id,
            expected_element_present=expected_element_present,
            expected_window_title_contains=expected_window_title_contains,
        )
        name_value = str(request["name"])
        type_value = str(request["control_type"])
        automation_value = str(request["automation_id"])
        title_value = str(request["window_title_contains"])
        selector_configured = bool(request["selector_configured"])
        expected_element_present = request["element_present"]

        checks: list[dict[str, Any]] = []
        if not selector_configured and not title_value:
            return {
                "configured": False,
                "postconditions_passed": True,
                "checks": [],
            }

        window = self.active_window()

        if selector_configured:
            elements, truncated = self.list_uia_elements(
                hwnd=window.hwnd,
                limit=500,
                max_depth=24,
            )
            matches: list[dict[str, Any]] = []
            for element in elements:
                if name_value and str(element.get("name", "")).casefold() != name_value.casefold():
                    continue
                if type_value:
                    observed_type = str(element.get("control_type", "")).casefold()
                    observed_role = str(element.get("aria_role", "")).casefold()
                    requested_type = type_value.casefold()
                    # Chromium exposes HTML headings through Windows UIA as
                    # ControlType.Text with aria_role="heading". Treat that
                    # narrow semantic mapping as equivalent for expected-post
                    # verification so a real <h1>/<h2> does not become a false
                    # negative. Other control types retain exact matching.
                    if observed_type != requested_type and not (
                        requested_type == "heading" and observed_role == "heading"
                    ):
                        continue
                if automation_value and str(element.get("automation_id", "")).casefold() != automation_value.casefold():
                    continue
                matches.append(element)
            observed_present = bool(matches)
            expected_present = bool(expected_element_present)
            if expected_present:
                presence_passed = observed_present
            else:
                # A bounded/truncated tree cannot prove absence safely.
                presence_passed = (not observed_present) and (not truncated)
            checks.append(
                {
                    "kind": "uia_element_presence",
                    "passed": bool(presence_passed),
                    "expected_present": expected_present,
                    "observed_present": observed_present,
                    "matched_count": len(matches),
                    "tree_truncated": bool(truncated),
                    "absence_proven": bool((not expected_present) and (not observed_present) and (not truncated)),
                    "selector": {
                        "name": name_value[:300] or None,
                        "control_type": type_value[:100] or None,
                        "automation_id": automation_value[:300] or None,
                    },
                }
            )

        if title_value:
            observed_title = window.title
            checks.append(
                {
                    "kind": "window_title_contains",
                    "passed": title_value.casefold() in observed_title.casefold(),
                    "expected_contains": title_value[:200],
                    "observed_title": observed_title[:300],
                }
            )

        configured = bool(checks)
        passed = all(bool(check.get("passed")) for check in checks) if configured else True
        return {
            "configured": configured,
            "postconditions_passed": bool(passed),
            "checks": checks,
        }

    def _observe_verification_contract(
        self,
        *,
        before: dict[str, Any],
        verification_policy: str,
        control_limit: int,
        expected_element_name: str | None = None,
        expected_element_control_type: str | None = None,
        expected_element_automation_id: str | None = None,
        expected_element_present: bool | None = None,
        expected_window_title_contains: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Read-only bounded re-observation after one action; never repeats input."""
        attempts = 0
        waited_ms = 0
        verification: dict[str, Any] = {}
        policy_result: dict[str, Any] = {}
        postconditions: dict[str, Any] = {}
        contract_result: dict[str, Any] = {}

        for attempt in range(1, POST_ACTION_OBSERVATION_MAX_ATTEMPTS + 1):
            attempts = attempt
            verification = self.verify_state_change(
                previous_semantic_signature=before["semantic_signature"],

[Showing lines 1-1229 of 2644 (50.0KB limit). Use offset=1230 to continue.]