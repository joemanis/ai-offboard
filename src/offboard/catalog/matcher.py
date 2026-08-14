"""Match detected principals/apps to the AI-app catalog.

A simple substring matcher over catalog entries keeps v1 honest and makes new
entries a one-PR contribution (see CONTRIBUTING.md).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_CATALOG_PATH = Path(__file__).parent / "apps.json"


@dataclass
class CatalogEntry:
    name: str
    dlp_tier: str
    notes: str


def load_catalog(path: Path = _CATALOG_PATH) -> list[dict[str, Any]]:
    with open(path) as fh:
        return json.load(fh).get("apps", [])


def match_app(name: str, apps: list[dict[str, Any]] | None = None) -> CatalogEntry | None:
    """Return the best matched catalog entry for a principal/app name.

    Matches if any `matches` substring appears case-insensitively in `name`.
    Returns the highest-tier match; None if unmatched.
    """
    apps = apps if apps is not None else load_catalog()
    best: dict[str, Any] | None = None
    for entry in apps:
        if any(m.lower() in name.lower() for m in entry["matches"]) and (
            best is None
            or _tier_rank(entry["dlp_tier"]) > _tier_rank(best["dlp_tier"])
        ):
            best = entry
    if best is None:
        return None
    return CatalogEntry(name=best["name"], dlp_tier=best["dlp_tier"], notes=best["notes"])


def _tier_rank(tier: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(tier, 0)
