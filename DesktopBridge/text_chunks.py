"""Bounded planning for one logical desktop text entry operation.

Python counts Unicode code points here. Windows injection converts each chunk to
UTF-16 units later; a chunk boundary never bisects an explicit surrogate pair.
"""

LOGICAL_TEXT_MAX_CHARS = 131_072
UI_TEXT_CHUNK_CHARS = 4_096
SENDINPUT_BATCH_UTF16_UNITS = 16
SENDINPUT_BATCH_PAUSE_SECONDS = 0.005


def plan_text_chunks(text: str) -> tuple[str, ...]:
    if not isinstance(text, str):
        raise ValueError("Desktop text input requires a string.")
    count = len(text)
    if count == 0:
        raise ValueError("Desktop text input requires at least one character; chunking was not attempted.")
    if count > LOGICAL_TEXT_MAX_CHARS:
        raise ValueError(
            f"Desktop text input received {count} characters; logical maximum is "
            f"{LOGICAL_TEXT_MAX_CHARS}; chunking was not attempted."
        )

    chunks: list[str] = []
    start = 0
    while start < count:
        end = min(start + UI_TEXT_CHUNK_CHARS, count)
        if end < count:
            # Prefer a nearby paragraph/newline/space without creating tiny chunks.
            floor = start + UI_TEXT_CHUNK_CHARS * 3 // 4
            for separator in ("\n\n", "\n", " ", "\t"):
                found = text.rfind(separator, floor, end)
                if found >= floor:
                    end = found + len(separator)
                    break
            # Preserve CRLF and explicitly represented UTF-16 surrogate pairs.
            if text[end - 1] == "\r" and text[end] == "\n":
                end -= 1
            elif 0xD800 <= ord(text[end - 1]) <= 0xDBFF and 0xDC00 <= ord(text[end]) <= 0xDFFF:
                end -= 1
        chunks.append(text[start:end])
        start = end
    return tuple(chunks)
