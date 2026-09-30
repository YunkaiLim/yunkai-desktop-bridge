from __future__ import annotations

import base64
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from PIL import Image as PILImage


class LocalVisionError(RuntimeError):
    pass


JsonTransport = Callable[[str, dict[str, Any], float], dict[str, Any]]
ACTIONABLE_KINDS = {
    "button",
    "icon",
    "menu",
    "tab",
    "dialog_action",
    "text_input",
    "link",
    "checkbox",
    "radio",
    "list_item",
    "shortcut",
}
GENERIC_TARGET_LABELS = {
    "button",
    "icon",
    "target",
    "unknown",
    "control",
    "item",
    "window",
}
VISION_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "screen_type": {
            "type": "string",
            "enum": ["app", "browser", "game", "dialog", "terminal", "unknown"],
        },
        "texts": {
            "type": "array",
            "maxItems": 16,
            "items": {"type": "string"},
        },
        "targets": {
            "type": "array",
            "maxItems": 10,
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "x": {"type": "integer"},
                    "y": {"type": "integer"},
                    "confidence": {"type": "number"},
                    "kind": {
                        "type": "string",
                        "enum": [
                            "button",
                            "icon",
                            "menu",
                            "tab",
                            "dialog_action",
                            "text_input",
                            "link",
                            "checkbox",
                            "radio",
                            "list_item",
                            "shortcut",
                            "other_ui",
                        ],
                    },
                },
                "required": ["label", "x", "y", "confidence", "kind"],
                "additionalProperties": False,
            },
        },
        "warnings": {
            "type": "array",
            "maxItems": 6,
            "items": {"type": "string"},
        },
    },
    "required": ["summary", "screen_type", "texts", "targets", "warnings"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class LocalVisionConfig:
    provider: str
    model: str
    base_url: str
    timeout_seconds: float = 30.0
    max_image_edge: int = 960
    min_action_confidence: float = 0.85
    context_window: int = 4096
    max_output_tokens: int = 512

    @staticmethod
    def _validate_local_url(value: str) -> str:
        parsed = urllib.parse.urlparse(value.strip())
        if parsed.scheme not in {"http", "https"}:
            raise LocalVisionError("Local vision URL must use http:// or https://.")
        host = (parsed.hostname or "").lower()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise LocalVisionError("Desktop Local Vision may connect only to localhost/127.0.0.1/::1.")
        if parsed.username or parsed.password:
            raise LocalVisionError("Do not put credentials in the Local Vision URL.")
        return value.rstrip("/")

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "LocalVisionConfig":
        provider = str(raw.get("provider", "")).strip().lower()
        model = str(raw.get("model", "")).strip()
        base_url = str(raw.get("base_url", "")).strip()
        timeout = float(raw.get("timeout_seconds", 30.0))
        max_image_edge = int(raw.get("max_image_edge", 960))
        min_action_confidence = float(raw.get("min_action_confidence", 0.85))
        context_window = int(raw.get("context_window", 4096))
        max_output_tokens = int(raw.get("max_output_tokens", 512))
        if provider not in {"ollama", "lmstudio"}:
            raise LocalVisionError("Local Vision provider must be 'ollama' or 'lmstudio'.")
        if not model or len(model) > 200:
            raise LocalVisionError("Local Vision model must be 1-200 characters.")
        if not base_url:
            base_url = "http://127.0.0.1:11434" if provider == "ollama" else "http://127.0.0.1:1234"
        if timeout < 1 or timeout > 120:
            raise LocalVisionError("Local Vision timeout_seconds must be between 1 and 120.")
        if max_image_edge < 512 or max_image_edge > 4096:
            raise LocalVisionError("Local Vision max_image_edge must be between 512 and 4096.")
        if min_action_confidence < 0.5 or min_action_confidence > 1.0:
            raise LocalVisionError("Local Vision min_action_confidence must be between 0.5 and 1.0.")
        if context_window < 2048 or context_window > 32768:
            raise LocalVisionError("Local Vision context_window must be between 2048 and 32768.")
        if max_output_tokens < 64 or max_output_tokens > 2048:
            raise LocalVisionError("Local Vision max_output_tokens must be between 64 and 2048.")
        return cls(
            provider=provider,
            model=model,
            base_url=cls._validate_local_url(base_url),
            timeout_seconds=timeout,
            max_image_edge=max_image_edge,
            min_action_confidence=min_action_confidence,
            context_window=context_window,
            max_output_tokens=max_output_tokens,
        )

    @classmethod
    def load(cls, project_root: Path | None = None) -> "LocalVisionConfig | None":
        provider = os.environ.get("DESKTOP_LOCAL_VISION_PROVIDER", "").strip()
        model = os.environ.get("DESKTOP_LOCAL_VISION_MODEL", "").strip()
        base_url = os.environ.get("DESKTOP_LOCAL_VISION_URL", "").strip()
        timeout = os.environ.get("DESKTOP_LOCAL_VISION_TIMEOUT", "").strip()
        if provider or model or base_url or timeout:
            raw: dict[str, Any] = {"provider": provider, "model": model, "base_url": base_url}
            if timeout:
                raw["timeout_seconds"] = timeout
            return cls.from_mapping(raw)

        root = project_root or Path(__file__).resolve().parent
        config_path = root / "desktopbridge_vision.json"
        if not config_path.exists():
            return None
        try:
            raw_json = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalVisionError(f"Could not read {config_path.name}: {exc}") from exc
        if not isinstance(raw_json, dict):
            raise LocalVisionError(f"{config_path.name} must contain a JSON object.")
        if raw_json.get("enabled") is False:
            return None
        return cls.from_mapping(raw_json)


class LocalVisionAdapter:
    def __init__(self, config: LocalVisionConfig, transport: JsonTransport | None = None):
        self.config = config
        self._transport = transport or self._post_json

    @staticmethod
    def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise LocalVisionError(f"Local Vision HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LocalVisionError(f"Could not reach local vision server: {exc}") from exc
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise LocalVisionError("Local vision server returned non-JSON HTTP content.") from exc
        if not isinstance(parsed, dict):
            raise LocalVisionError("Local vision server returned an unexpected JSON shape.")
        return parsed

    def _prepare_image(self, png_bytes: bytes, *, width: int, height: int) -> tuple[bytes, int, int]:
        max_edge = self.config.max_image_edge
        if max(width, height) <= max_edge:
            return png_bytes, width, height
        scale = max_edge / max(width, height)
        target_width = max(1, round(width * scale))
        target_height = max(1, round(height * scale))
        try:
            with PILImage.open(io.BytesIO(png_bytes)) as image:
                image = image.convert("RGB")
                image = image.resize((target_width, target_height), PILImage.Resampling.LANCZOS)
                buffer = io.BytesIO()
                image.save(buffer, format="PNG", optimize=True)
                return buffer.getvalue(), target_width, target_height
        except Exception:
            return png_bytes, width, height

    @staticmethod
    def _prompt(width: int, height: int, ui_hint: dict[str, Any] | None = None) -> str:
        hint = ""
        if ui_hint:
            compact = {
                "window_title": ui_hint.get("window_title", ""),
                "uia_elements": [
                    {
                        "name": item.get("name", ""),
                        "control_type": item.get("control_type", ""),
                        "rect": item.get("rect", []),
                        "enabled": bool(item.get("enabled", True)),
                        "actionable": bool(item.get("actionable")),
                    }
                    for item in ui_hint.get("uia_elements", [])[:20]
                    if isinstance(item, dict)
                ],
                "controls": [
                    {
                        "text": item.get("text", ""),
                        "class_name": item.get("class_name", ""),
                        "role": item.get("role", ""),
                        "enabled": bool(item.get("enabled", True)),
                    }
                    for item in ui_hint.get("controls", [])[:20]
                    if isinstance(item, dict)
                ],
            }
            hint = "\nWindows semantic hint (UIA/Win32; may be incomplete):\n" + json.dumps(compact, ensure_ascii=False)
        return (
            "Analyze this Windows active-window screenshot as a UI perception module. "
            "Do not decide or execute actions. Return JSON only. "
            f"The screenshot coordinate space is {width}x{height}. Use pixel x/y coordinates in that exact space. "
            "Schema: {"
            '"summary": string, '
            '"screen_type": "app|browser|game|dialog|terminal|unknown", '
            '"texts": [string], '
            '"targets": [{"label": string, "x": integer, "y": integer, '
            '"confidence": number, "kind": string}], '
            '"warnings": [string]}. '
            "Keep texts <= 16 and targets <= 10. Targets must be real visible UI controls only. "
            "Prefer explicit buttons, text fields, tabs, menus, links, checkboxes, list items, dialog actions, and toolbar icons. "
            "Do not return wallpaper, avatars, photos, decorative illustrations, or page content as clickable controls unless the UI clearly shows they are interactive. "
            "When a control has visible text, label MUST copy that text instead of generic labels such as button/icon. "
            "For text inputs, use kind=text_input and place x/y near the center of the editable area. "
            "For browser pages, distinguish webpage links/buttons from decorative text. "
            "For games, return only explicit UI controls/prompts, never characters or scenery. "
            "kind must be one of: button, icon, menu, tab, dialog_action, text_input, link, checkbox, radio, list_item, shortcut, other_ui. "
            "If coordinates are uncertain, lower confidence instead of guessing."
            + hint
        )

    @staticmethod
    def _extract_json_object(text: str) -> tuple[dict[str, Any] | None, str]:
        raw = text.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)
        first = raw.find("{")
        last = raw.rfind("}")
        candidate = raw[first : last + 1] if first >= 0 and last > first else raw
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            return None, text
        return (parsed if isinstance(parsed, dict) else None), text

    @staticmethod
    def _normalize_result(parsed: dict[str, Any], width: int, height: int) -> dict[str, Any]:
        summary = str(parsed.get("summary", ""))[:2000]
        screen_type = str(parsed.get("screen_type", "unknown")).lower()
        if screen_type not in {"app", "browser", "game", "dialog", "terminal", "unknown"}:
            screen_type = "unknown"
        texts = [str(item)[:300] for item in parsed.get("texts", []) if isinstance(item, (str, int, float))][:20]
        warnings = [str(item)[:500] for item in parsed.get("warnings", []) if isinstance(item, (str, int, float))][:20]
        targets: list[dict[str, Any]] = []
        for item in parsed.get("targets", []):
            if not isinstance(item, dict):
                continue
            try:
                x = int(item.get("x"))
                y = int(item.get("y"))
                confidence = float(item.get("confidence", 0.0))
            except (TypeError, ValueError):
                continue
            if not (0 <= x < width and 0 <= y < height):
                continue
            kind = str(item.get("kind", "")).strip().lower()[:100]
            targets.append(
                {
                    "label": str(item.get("label", ""))[:300],
                    "x": x,
                    "y": y,
                    "x_ratio": round(x / max(1, width - 1), 6),
                    "y_ratio": round(y / max(1, height - 1), 6),
                    "confidence": max(0.0, min(1.0, confidence)),
                    "kind": kind,
                }
            )
            if len(targets) >= 15:
                break
        return {
            "summary": summary,
            "screen_type": screen_type,
            "texts": texts,
            "targets": targets,
            "warnings": warnings,
        }

    def _request_model_text(self, image_b64: str, prompt: str) -> str:
        if self.config.provider == "ollama":
            url = self.config.base_url + "/api/chat"
            payload = {
                "model": self.config.model,
                "stream": False,
                "format": VISION_JSON_SCHEMA,
                "messages": [{"role": "user", "content": prompt, "images": [image_b64]}],
                "options": {
                    "temperature": 0,
                    "num_ctx": self.config.context_window,
                    "num_predict": self.config.max_output_tokens,
                },
            }
            response = self._transport(url, payload, self.config.timeout_seconds)
            message = response.get("message", {})
            text = message.get("content", "") if isinstance(message, dict) else ""
        else:
            url = self.config.base_url + "/v1/chat/completions"
            payload = {
                "model": self.config.model,
                "temperature": 0,
                "max_tokens": self.config.max_output_tokens,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": "data:image/png;base64," + image_b64}},
                        ],
                    }
                ],
            }
            response = self._transport(url, payload, self.config.timeout_seconds)
            choices = response.get("choices", [])
            first = choices[0] if isinstance(choices, list) and choices else {}
            message = first.get("message", {}) if isinstance(first, dict) else {}
            text = message.get("content", "") if isinstance(message, dict) else ""
        if not isinstance(text, str) or not text.strip():
            raise LocalVisionError("Local vision model returned no text content.")
        return text

    def analyze_png(
        self,
        png_bytes: bytes,
        *,
        width: int,
        height: int,
        ui_hint: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        vision_png, vision_width, vision_height = self._prepare_image(png_bytes, width=width, height=height)
        image_b64 = base64.b64encode(vision_png).decode("ascii")
        prompt = self._prompt(vision_width, vision_height, ui_hint)

        text = self._request_model_text(image_b64, prompt)
        parsed, raw_text = self._extract_json_object(text)
        retry_used = False
        if parsed is None:
            retry_used = True
            repair_prompt = (
                prompt
                + "\nIMPORTANT: Return exactly one valid JSON object matching the schema. "
                "No markdown fence, no commentary, no prose before or after the JSON."
            )
            retry_text = self._request_model_text(image_b64, repair_prompt)
            parsed, retry_raw = self._extract_json_object(retry_text)
            if parsed is None:
                return {
                    "provider": self.config.provider,
                    "model": self.config.model,
                    "parse_ok": False,
                    "retry_used": True,
                    "raw_text": (raw_text + "\n--- retry ---\n" + retry_raw)[:6000],
                }
        normalized = self._normalize_result(parsed, vision_width, vision_height)
        if vision_width != width or vision_height != height:
            scale_x = width / vision_width
            scale_y = height / vision_height
            for target in normalized["targets"]:
                target["x"] = max(0, min(width - 1, round(target["x"] * scale_x)))
                target["y"] = max(0, min(height - 1, round(target["y"] * scale_y)))
                target["x_ratio"] = round(target["x"] / max(1, width - 1), 6)
                target["y_ratio"] = round(target["y"] / max(1, height - 1), 6)

        candidate_targets = [
            target
            for target in normalized["targets"]
            if target["kind"] in ACTIONABLE_KINDS and target["confidence"] >= self.config.min_action_confidence
        ]
        actionable_targets = []
        for target in candidate_targets:
            label = target["label"].strip()
            if not label or label.casefold() in GENERIC_TARGET_LABELS:
                continue
            actionable_targets.append({**target, "requires_verification": True})

        return {
            "provider": self.config.provider,
            "model": self.config.model,
            "parse_ok": True,
            "retry_used": retry_used,
            "vision_input_size": [vision_width, vision_height],
            "coordinate_space": [width, height],
            "min_action_confidence": self.config.min_action_confidence,
            "candidate_targets": candidate_targets,
            "actionable_targets": actionable_targets,
            **normalized,
        }


def local_vision_status(project_root: Path | None = None) -> dict[str, Any]:
    try:
        config = LocalVisionConfig.load(project_root)
    except LocalVisionError as exc:
        return {"enabled": False, "configured": True, "error": str(exc)}
    if config is None:
        return {"enabled": False, "configured": False, "supported_providers": ["ollama", "lmstudio"]}
    return {
        "enabled": True,
        "configured": True,
        "provider": config.provider,
        "model": config.model,
        "base_url": config.base_url,
        "timeout_seconds": config.timeout_seconds,
        "max_image_edge": config.max_image_edge,
        "min_action_confidence": config.min_action_confidence,
        "context_window": config.context_window,
        "max_output_tokens": config.max_output_tokens,
    }
