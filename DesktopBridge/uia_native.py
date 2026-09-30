from __future__ import annotations

import ctypes
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator


HRESULT = ctypes.c_long
BOOL = ctypes.c_int
HWND = ctypes.c_void_p
BSTR = ctypes.c_void_p

S_OK = 0
S_FALSE = 1
RPC_E_CHANGED_MODE = 0x80010106
CLSCTX_INPROC_SERVER = 0x1
COINIT_MULTITHREADED = 0x0

CLSID_CUIAUTOMATION = "ff48dba4-60ef-4201-aa87-54103eef594e"
IID_IUIAUTOMATION = "30cbe57d-d9d0-452a-ab13-7ac5ac4825ee"


CONTROL_TYPES: dict[int, str] = {
    50000: "button",
    50001: "calendar",
    50002: "checkbox",
    50003: "combobox",
    50004: "edit",
    50005: "hyperlink",
    50006: "image",
    50007: "list_item",
    50008: "list",
    50009: "menu",
    50010: "menu_bar",
    50011: "menu_item",
    50012: "progress_bar",
    50013: "radio_button",
    50014: "scroll_bar",
    50015: "slider",
    50016: "spinner",
    50017: "status_bar",
    50018: "tab",
    50019: "tab_item",
    50020: "text",
    50021: "toolbar",
    50022: "tooltip",
    50023: "tree",
    50024: "tree_item",
    50025: "custom",
    50026: "group",
    50027: "thumb",
    50028: "data_grid",
    50029: "data_item",
    50030: "document",
    50031: "split_button",
    50032: "window",
    50033: "pane",
    50034: "header",
    50035: "header_item",
    50036: "table",
    50037: "title_bar",
    50038: "separator",
    50039: "semantic_zoom",
    50040: "app_bar",
}

ACTIONABLE_CONTROL_TYPES = {
    "button",
    "checkbox",
    "combobox",
    "edit",
    "hyperlink",
    "list_item",
    "menu_item",
    "radio_button",
    "slider",
    "spinner",
    "tab_item",
    "tree_item",
    "split_button",
}


class UIAutomationError(RuntimeError):
    pass


class UIARect(ctypes.Structure):
    # IUIAutomationElement::CurrentBoundingRectangle returns a Win32 RECT
    # (left, top, right, bottom), not the provider-side UIA_RECT doubles.
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


@dataclass(frozen=True)
class UIAElement:
    name: str
    control_type_id: int
    control_type: str
    automation_id: str
    class_name: str
    framework_id: str
    help_text: str
    aria_role: str
    aria_properties: str
    rect: tuple[int, int, int, int]
    enabled: bool
    offscreen: bool
    is_password: bool
    has_keyboard_focus: bool
    keyboard_focusable: bool
    native_window_handle: int
    depth: int

    @property
    def actionable(self) -> bool:
        left, top, right, bottom = self.rect
        return (
            self.control_type in ACTIONABLE_CONTROL_TYPES
            and self.enabled
            and not self.offscreen
            and right > left
            and bottom > top
        )

    def as_dict(self) -> dict[str, Any]:
        left, top, right, bottom = self.rect
        return {
            "name": self.name,
            "control_type_id": self.control_type_id,
            "control_type": self.control_type,
            "automation_id": self.automation_id,
            "class_name": self.class_name,
            "framework_id": self.framework_id,
            "help_text": self.help_text,
            "aria_role": self.aria_role,
            "aria_properties": self.aria_properties,
            "rect": [left, top, right, bottom],
            "width": max(0, right - left),
            "height": max(0, bottom - top),
            "enabled": self.enabled,
            "offscreen": self.offscreen,
            "is_password": self.is_password,
            "has_keyboard_focus": self.has_keyboard_focus,
            "keyboard_focusable": self.keyboard_focusable,
            "native_window_handle": self.native_window_handle,
            "depth": self.depth,
            "actionable": self.actionable,
        }


class NativeUIAutomation:
    """Minimal read-only Microsoft UI Automation client using UIAutomationCore COM.

    This intentionally avoids third-party dependencies. It only reads the
    Control View tree and current element properties; it does not invoke UIA
    patterns or mutate application state.
    """

    def __init__(self) -> None:
        self._ole32 = ctypes.OleDLL("ole32")
        self._oleaut32 = ctypes.OleDLL("oleaut32")
        self._oleaut32.SysFreeString.argtypes = [BSTR]
        self._oleaut32.SysFreeString.restype = None

    @staticmethod
    def _guid_buffer(value: str) -> ctypes.Array[ctypes.c_char]:
        return ctypes.create_string_buffer(uuid.UUID(value).bytes_le)

    @staticmethod
    def _u32(hr: int) -> int:
        return int(hr) & 0xFFFFFFFF

    @contextmanager
    def _apartment(self) -> Iterator[None]:
        hr = int(self._ole32.CoInitializeEx(None, COINIT_MULTITHREADED))
        code = self._u32(hr)
        should_uninitialize = code in {S_OK, S_FALSE}
        if code not in {S_OK, S_FALSE, RPC_E_CHANGED_MODE}:
            raise UIAutomationError(f"CoInitializeEx failed with HRESULT 0x{code:08X}.")
        try:
            yield
        finally:
            if should_uninitialize:
                self._ole32.CoUninitialize()

    @staticmethod
    def _method(pointer: ctypes.c_void_p, index: int, restype: Any, *argtypes: Any) -> Any:
        if not pointer or not pointer.value:
            raise UIAutomationError("COM interface pointer is null.")
        vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        address = vtable[index]
        prototype = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
        return prototype(address)

    def _release(self, pointer: ctypes.c_void_p | None) -> None:
        if pointer and pointer.value:
            try:
                self._method(pointer, 2, ctypes.c_ulong)(pointer)
            except Exception:
                pass

    def _create_automation(self) -> ctypes.c_void_p:
        clsid = self._guid_buffer(CLSID_CUIAUTOMATION)
        iid = self._guid_buffer(IID_IUIAUTOMATION)
        pointer = ctypes.c_void_p()
        hr = int(
            self._ole32.CoCreateInstance(
                ctypes.byref(clsid),
                None,
                CLSCTX_INPROC_SERVER,
                ctypes.byref(iid),
                ctypes.byref(pointer),
            )
        )
        if self._u32(hr) != S_OK or not pointer.value:
            raise UIAutomationError(
                f"Could not create CUIAutomation: HRESULT 0x{self._u32(hr):08X}."
            )
        return pointer

    def _element_from_handle(self, automation: ctypes.c_void_p, hwnd: int) -> ctypes.c_void_p:
        pointer = ctypes.c_void_p()
        # IUIAutomation::ElementFromHandle is vtable method 6 (IUnknown + 3).
        method = self._method(
            automation,
            6,
            HRESULT,
            HWND,
            ctypes.POINTER(ctypes.c_void_p),
        )
        hr = int(method(automation, HWND(int(hwnd)), ctypes.byref(pointer)))
        if self._u32(hr) != S_OK or not pointer.value:
            raise UIAutomationError(
                f"UI Automation could not open HWND {int(hwnd)}: HRESULT 0x{self._u32(hr):08X}."
            )
        return pointer

    def _control_view_walker(self, automation: ctypes.c_void_p) -> ctypes.c_void_p:
        pointer = ctypes.c_void_p()
        # IUIAutomation::get_ControlViewWalker is vtable method 14.
        method = self._method(
            automation,
            14,
            HRESULT,
            ctypes.POINTER(ctypes.c_void_p),
        )
        hr = int(method(automation, ctypes.byref(pointer)))
        if self._u32(hr) != S_OK or not pointer.value:
            raise UIAutomationError(
                f"Could not get ControlViewWalker: HRESULT 0x{self._u32(hr):08X}."
            )
        return pointer

    def _walker_child(self, walker: ctypes.c_void_p, element: ctypes.c_void_p) -> ctypes.c_void_p:
        pointer = ctypes.c_void_p()
        method = self._method(
            walker,
            4,
            HRESULT,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        hr = int(method(walker, element, ctypes.byref(pointer)))
        if self._u32(hr) != S_OK:
            return ctypes.c_void_p()
        return pointer

    def _walker_next(self, walker: ctypes.c_void_p, element: ctypes.c_void_p) -> ctypes.c_void_p:
        pointer = ctypes.c_void_p()
        method = self._method(
            walker,
            6,
            HRESULT,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        hr = int(method(walker, element, ctypes.byref(pointer)))
        if self._u32(hr) != S_OK:
            return ctypes.c_void_p()
        return pointer

    def _get_int(self, element: ctypes.c_void_p, index: int, default: int = 0) -> int:
        value = ctypes.c_int()
        method = self._method(element, index, HRESULT, ctypes.POINTER(ctypes.c_int))
        hr = int(method(element, ctypes.byref(value)))
        return int(value.value) if self._u32(hr) == S_OK else int(default)

    def _get_bool(self, element: ctypes.c_void_p, index: int, default: bool = False) -> bool:
        value = BOOL()
        method = self._method(element, index, HRESULT, ctypes.POINTER(BOOL))
        hr = int(method(element, ctypes.byref(value)))
        return bool(value.value) if self._u32(hr) == S_OK else bool(default)

    def _get_bstr(self, element: ctypes.c_void_p, index: int) -> str:
        value = BSTR()
        method = self._method(element, index, HRESULT, ctypes.POINTER(BSTR))
        hr = int(method(element, ctypes.byref(value)))
        if self._u32(hr) != S_OK or not value.value:
            return ""
        try:
            return ctypes.wstring_at(value.value)
        finally:
            self._oleaut32.SysFreeString(value)

    def _get_rect(self, element: ctypes.c_void_p) -> tuple[int, int, int, int]:
        value = UIARect()
        # IUIAutomationElement::get_CurrentBoundingRectangle is method 43.
        method = self._method(element, 43, HRESULT, ctypes.POINTER(UIARect))
        hr = int(method(element, ctypes.byref(value)))
        if self._u32(hr) != S_OK:
            return (0, 0, 0, 0)
        left = round(value.left)
        top = round(value.top)
        right = round(value.right)
        bottom = round(value.bottom)
        if right <= left or bottom <= top:
            return (0, 0, 0, 0)
        return (left, top, right, bottom)

    def _read_element(self, element: ctypes.c_void_p, depth: int) -> UIAElement:
        # IUIAutomationElement vtable indices are documented in UIAutomationClient.idl.
        control_type_id = self._get_int(element, 21)
        return UIAElement(
            name=self._get_bstr(element, 23)[:1000],
            control_type_id=control_type_id,
            control_type=CONTROL_TYPES.get(control_type_id, f"control_{control_type_id}"),
            automation_id=self._get_bstr(element, 29)[:500],
            class_name=self._get_bstr(element, 30)[:500],
            framework_id=self._get_bstr(element, 40)[:200],
            help_text=self._get_bstr(element, 31)[:1000],
            aria_role=self._get_bstr(element, 45)[:500],
            aria_properties=self._get_bstr(element, 46)[:1000],
            rect=self._get_rect(element),
            enabled=self._get_bool(element, 28, True),
            offscreen=self._get_bool(element, 38, False),
            is_password=self._get_bool(element, 35, False),
            has_keyboard_focus=self._get_bool(element, 26, False),
            keyboard_focusable=self._get_bool(element, 27, False),
            native_window_handle=self._get_int(element, 36),
            depth=int(depth),
        )

    def list_window_elements(
        self,
        hwnd: int,
        *,
        limit: int = 120,
        max_depth: int = 12,
    ) -> list[UIAElement]:
        limit = max(1, min(500, int(limit)))
        max_depth = max(0, min(30, int(max_depth)))
        result: list[UIAElement] = []

        with self._apartment():
            automation = self._create_automation()
            root = ctypes.c_void_p()
            walker = ctypes.c_void_p()
            try:
                root = self._element_from_handle(automation, int(hwnd))
                walker = self._control_view_walker(automation)

                def visit(element: ctypes.c_void_p, depth: int) -> None:
                    if len(result) >= limit:
                        return
                    try:
                        result.append(self._read_element(element, depth))
                    except Exception:
                        pass
                    if depth >= max_depth or len(result) >= limit:
                        return
                    child = self._walker_child(walker, element)
                    while child and child.value and len(result) < limit:
                        visit(child, depth + 1)
                        next_element = self._walker_next(walker, child)
                        self._release(child)
                        child = next_element

                visit(root, 0)
            finally:
                self._release(walker)
                self._release(root)
                self._release(automation)

        return result


def uia_status() -> dict[str, Any]:
    try:
        adapter = NativeUIAutomation()
        with adapter._apartment():
            pointer = adapter._create_automation()
            adapter._release(pointer)
        return {
            "enabled": True,
            "backend": "Windows UIAutomationCore COM",
            "third_party_dependency": False,
            "read_only": True,
        }
    except Exception as exc:
        return {
            "enabled": False,
            "backend": "Windows UIAutomationCore COM",
            "third_party_dependency": False,
            "read_only": True,
            "error": str(exc),
        }
