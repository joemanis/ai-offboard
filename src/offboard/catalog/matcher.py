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
    Scoring: longest (most specific) substring match wins, with DLP tier as
    tiebreaker. This prevents e.g. "GitHub Copilot" from being swallowed by
    the generic "copilot" entry.
    """
    apps = apps if apps is not None else load_catalog()
    best: dict[str, Any] | None = None
    best_len = 0
    for entry in apps:
        for m in entry["matches"]:
            if m.lower() not in name.lower():
                continue
            mlen = len(m)
            same_len_higher_tier = (
                best is not None
                and mlen == best_len
                and _tier_rank(entry["dlp_tier"]) > _tier_rank(best["dlp_tier"])
            )
            if mlen > best_len or same_len_higher_tier:
                best = entry
                best_len = mlen
                break
    if best is None:
        return None
    return CatalogEntry(name=best["name"], dlp_tier=best["dlp_tier"], notes=best["notes"])


def _tier_rank(tier: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(tier, 0)
