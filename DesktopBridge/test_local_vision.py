from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from local_vision import LocalVisionAdapter, LocalVisionConfig, LocalVisionError, local_vision_status


class LocalVisionTests(unittest.TestCase):
    def test_config_load_and_localhost_restriction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "desktopbridge_vision.json").write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "provider": "ollama",
                        "model": "test-model",
                        "base_url": "http://127.0.0.1:11434",
                    }
                ),
                encoding="utf-8",
            )
            config = LocalVisionConfig.load(root)
            self.assertIsNotNone(config)
            self.assertEqual(config.provider, "ollama")
            status = local_vision_status(root)
            self.assertTrue(status["enabled"])
            self.assertEqual(status["model"], "test-model")

        with self.assertRaises(LocalVisionError):
            LocalVisionConfig.from_mapping(
                {
                    "provider": "ollama",
                    "model": "test",
                    "base_url": "https://example.com",
                }
            )

    def test_ollama_result_is_scaled_and_action_targets_are_filtered(self):
        captured = {}

        def transport(url, payload, timeout):
            captured["url"] = url
            captured["payload"] = payload
            captured["timeout"] = timeout
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Browser with a search field.",
                            "screen_type": "browser",
                            "texts": ["Search"],
                            "targets": [
                                {
                                    "label": "button",
                                    "x": 100,
                                    "y": 50,
                                    "confidence": 0.99,
                                    "kind": "button",
                                },
                                {
                                    "label": "Search",
                                    "x": 300,
                                    "y": 150,
                                    "confidence": 0.95,
                                    "kind": "text_input",
                                },
                            ],
                            "warnings": [],
                        }
                    )
                }
            }

        config = LocalVisionConfig.from_mapping(
            {
                "provider": "ollama",
                "model": "test-model",
                "base_url": "http://127.0.0.1:11434",
                "max_image_edge": 600,
                "min_action_confidence": 0.85,
            }
        )
        adapter = LocalVisionAdapter(config, transport=transport)
        image = Image.new("RGB", (1200, 600), "white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")

        result = adapter.analyze_png(
            buffer.getvalue(),
            width=1200,
            height=600,
            ui_hint={"window_title": "Example - Chrome", "controls": []},
        )

        self.assertTrue(result["parse_ok"])
        self.assertEqual(result["vision_input_size"], [600, 300])
        self.assertEqual(result["coordinate_space"], [1200, 600])
        self.assertTrue(captured["url"].endswith("/api/chat"))
        self.assertEqual(captured["payload"]["model"], "test-model")
        self.assertEqual(len(result["candidate_targets"]), 2)
        self.assertEqual(len(result["actionable_targets"]), 1)
        target = result["actionable_targets"][0]
        self.assertEqual(target["label"], "Search")
        self.assertEqual((target["x"], target["y"]), (600, 300))
        self.assertAlmostEqual(target["x_ratio"], 600 / 1199, places=5)
        self.assertAlmostEqual(target["y_ratio"], 300 / 599, places=5)
        self.assertTrue(target["requires_verification"])

    def test_parse_failure_retries_once_and_can_recover(self):
        calls = {"count": 0}

        def transport(_url, _payload, _timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                return {"message": {"content": "not-json"}}
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Recovered",
                            "screen_type": "app",
                            "texts": ["OK"],
                            "targets": [],
                            "warnings": [],
                        }
                    )
                }
            }

        config = LocalVisionConfig.from_mapping(
            {
                "provider": "ollama",
                "model": "test-model",
                "base_url": "http://localhost:11434",
            }
        )
        adapter = LocalVisionAdapter(config, transport=transport)
        image = Image.new("RGB", (800, 400), "white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        result = adapter.analyze_png(buffer.getvalue(), width=800, height=400)
        self.assertTrue(result["parse_ok"])
        self.assertTrue(result["retry_used"])
        self.assertEqual(calls["count"], 2)
        self.assertEqual(result["summary"], "Recovered")

    def test_invalid_model_json_is_returned_as_parse_failure(self):
        config = LocalVisionConfig.from_mapping(
            {
                "provider": "ollama",
                "model": "test-model",
                "base_url": "http://localhost:11434",
            }
        )
        adapter = LocalVisionAdapter(
            config,
            transport=lambda _url, _payload, _timeout: {"message": {"content": "not-json"}},
        )
        image = Image.new("RGB", (800, 400), "white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        result = adapter.analyze_png(buffer.getvalue(), width=800, height=400)
        self.assertFalse(result["parse_ok"])
        self.assertIn("not-json", result["raw_text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
