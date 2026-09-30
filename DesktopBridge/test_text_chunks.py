import asyncio
import ctypes
import unittest
from unittest.mock import patch

from desktop_bridge import DesktopBridge, DesktopBridgeError
from server import server
from text_chunks import LOGICAL_TEXT_MAX_CHARS, UI_TEXT_CHUNK_CHARS, plan_text_chunks
from test_desktop_bridge import FakeUIABridge


class TextChunkTests(unittest.TestCase):
    def test_lengths_and_exact_reconstruction(self):
        for length in (1, 2000, 2001, 4096, 4097, 8193, 16385, 65536,
                       LOGICAL_TEXT_MAX_CHARS):
            with self.subTest(length=length):
                sample = "alpha 中文 😀\r\nline\n\n```python\nprint('ok')\n``` "
                source = (sample * (length // len(sample) + 1))[:length]
                chunks = plan_text_chunks(source)
                self.assertEqual("".join(chunks), source)
                self.assertTrue(all(0 < len(chunk) <= UI_TEXT_CHUNK_CHARS for chunk in chunks))
        with self.assertRaisesRegex(ValueError, f"{LOGICAL_TEXT_MAX_CHARS + 1} characters"):
            plan_text_chunks("x" * (LOGICAL_TEXT_MAX_CHARS + 1))

    def test_unicode_crlf_and_surrogate_boundaries(self):
        cases = ["ASCII", "中文", "中文 English 😀", "😀" * 5000,
                 "line\r\n" * 1000, "# Markdown\n\n```js\nconst x = '😀';\n```\n" * 250,
                 "x" * 4095 + "\ud83d\ude00" + "z" * 4096,
                 "x" * 4095 + "\r\n" + "z" * 4096]
        for source in cases:
            with self.subTest(prefix=repr(source[:20])):
                chunks = plan_text_chunks(source)
                self.assertEqual("".join(chunks), source)
                for left, right in zip(chunks, chunks[1:]):
                    self.assertFalse(left.endswith("\r") and right.startswith("\n"))
                    self.assertFalse(0xD800 <= ord(left[-1]) <= 0xDBFF and
                                     0xDC00 <= ord(right[0]) <= 0xDFFF)

    def test_sendinput_units_and_one_operation(self):
        seen_units = []
        calls = []

        class FakeUser32:
            def SendInput(self, count, events, size):
                calls.append(count)
                for i in range(count):
                    if not events[i].ki.dwFlags & 0x0002:
                        seen_units.append(events[i].ki.wScan)
                return count

        source = ("中文😀\r\ncode block\n" * 260) + "\ud83d\ude00"
        bridge = DesktopBridge()
        checks = []
        with patch.object(ctypes.windll, "user32", FakeUser32()), patch("desktop_bridge.time.sleep"):
            result = bridge.type_text(source, _before_chunk=lambda: checks.append(True))
        expected = source.encode("utf-16-le", "surrogatepass")
        expected_units = [int.from_bytes(expected[i:i + 2], "little") for i in range(0, len(expected), 2)]
        self.assertEqual(seen_units, expected_units)
        self.assertEqual(len(checks), result["chunk_count"])
        self.assertEqual(result["characters"], len(source))
        self.assertLessEqual(max(calls), 32)
        trace = bridge.operation_trace(result["operation_id"])
        self.assertEqual(trace["summary"]["action_result_count"], 1)
        self.assertEqual(trace["action_results"][0]["input_metadata"]["chunk_count"], result["chunk_count"])
        self.assertNotIn(source[:40], repr(trace))

    def test_partial_sendinput_fails_without_retry(self):
        class FailingUser32:
            def __init__(self):
                self.calls = 0

            def SendInput(self, count, _events, _size):
                self.calls += 1
                return count - 1

        fake = FailingUser32()
        with patch.object(ctypes.windll, "user32", fake):
            with self.assertRaisesRegex(DesktopBridgeError, "partial and was not retried"):
                DesktopBridge().type_text("x" * 5000)
        self.assertEqual(fake.calls, 1)

    def test_uia_long_input_stops_on_focus_loss_without_resending(self):
        class CapturingUser32:
            def __init__(self):
                self.units = 0

            def SendInput(self, count, _events, _size):
                self.units += count // 2
                return count

        fake = CapturingUser32()

        class FocusChangingBridge(FakeUIABridge):
            def type_text(self, text, *, _before_chunk=None):
                return DesktopBridge.type_text(self, text, _before_chunk=_before_chunk)

            def list_uia_elements(self, hwnd=None, limit=120, max_depth=12):
                elements, truncated = super().list_uia_elements(hwnd, limit, max_depth)
                if fake.units:
                    elements = [dict(item, has_keyboard_focus=False) if item.get('control_type') == 'edit'
                                else item for item in elements]
                return elements, truncated

        bridge = FocusChangingBridge()
        with patch.object(ctypes.windll, "user32", fake), patch("desktop_bridge.time.sleep"):
            with self.assertRaisesRegex(DesktopBridgeError, "lost keyboard focus"):
                bridge.type_active_window_uia_text("x" * 5000, "Notepad", name="Address and search bar")
        self.assertEqual(fake.units, UI_TEXT_CHUNK_CHARS)
        self.assertEqual([event[0] for event in bridge.events], ["click"])
        untouched = FakeUIABridge()
        with self.assertRaisesRegex(DesktopBridgeError, "logical maximum"):
            untouched.type_active_window_uia_text("x" * (LOGICAL_TEXT_MAX_CHARS + 1), "Notepad", name="Address and search bar")
        self.assertEqual(untouched.events, [])

    def test_exported_schema_matches_runtime(self):
        tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
        for name in ("type_desktop_text", "type_active_window_text",
                     "type_active_window_uia_text", "type_active_window_uia_text_verified"):
            self.assertEqual(tools[name].input_schema["properties"]["text"]["maxLength"],
                             LOGICAL_TEXT_MAX_CHARS)
        with self.assertRaisesRegex(DesktopBridgeError, "logical maximum"):
            DesktopBridge().type_text("x" * (LOGICAL_TEXT_MAX_CHARS + 1))


if __name__ == "__main__":
    unittest.main()
