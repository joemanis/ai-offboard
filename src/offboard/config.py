"""Configuration loading and .env handling for ai-offboard.

The setup wizard (`offboard setup`) writes these values to a .env file; the
CLI reads them from the environment (either real env vars or the .env). The
scan connector never receives secrets any other way.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass
class Config:
    client_id: str
    client_secret: str
    tenant_id: str
    authority: str = "https://login.microsoftonline.com/common"
    public_client_id: str = ""

    @property
    def is_complete(self) -> bool:
        return bool(self.client_id and self.client_secret and self.tenant_id)

    @property
    def device_code_ready(self) -> bool:
        return bool(self.public_client_id)


_ENV_MAP = {
    "client_id": "OFFBOARD_CLIENT_ID",
    "client_secret": "OFFBOARD_CLIENT_SECRET",
    "tenant_id": "OFFBOARD_TENANT_ID",
    "authority": "OFFBOARD_AUTHORITY",
    "public_client_id": "OFFBOARD_PUBLIC_CLIENT_ID",
}


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Load config from environment (real env or .env file already sourced).
    Falls back to missing values as empty strings so the wizard can detect gaps.
    """
    source: Mapping[str, str] = env if env is not None else os.environ
    return Config(
        client_id=source.get(_ENV_MAP["client_id"], ""),
        client_secret=source.get(_ENV_MAP["client_secret"], ""),
        tenant_id=source.get(_ENV_MAP["tenant_id"], ""),
        authority=source.get(_ENV_MAP["authority"], "https://login.microsoftonline.com/common"),
        public_client_id=source.get(_ENV_MAP["public_client_id"], ""),
    )


def parse_env_file(path: str) -> dict[str, str]:
    """Parse a simple KEY=VALUE .env file into a dict. Ignores comments/blank."""
    out: dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def write_env_file(path: str, config: Config) -> None:
    """Write the config back to a .env file (restoring unknown existing keys)."""
    existing = parse_env_file(path)
    existing.update({v: getattr(config, k) for k, v in _ENV_MAP.items()})
    with open(path, "w", newline="\n") as fh:
        fh.writelines(f"{key}={value}\n" for key, value in existing.items())


def default_env_path() -> str:
    """Where the setup wizard writes config by default (repo root .env)."""
    # Resolve from the package's repo root upward so it works from any cwd.
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(here))), ".env")