"""Labeled panel loader."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PanelEntry:
    lang: str
    target: str
    label: str  # "ct" | "leaky" | "unknown"
    rationale: str


def load_panel(path: Path) -> list[PanelEntry]:
    data = json.loads(path.read_text())
    out: list[PanelEntry] = []
    for lang, entries in data.items():
        if lang.startswith("_"):
            continue
        for e in entries:
            out.append(
                PanelEntry(
                    lang=lang, target=e["target"], label=e["label"], rationale=e["rationale"]
                )
            )
    return out
