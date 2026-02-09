from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AuthorizationRecord:
    agent_id: str
    provider: str
    account_id: str | None
    scopes: list[str]
    access_token: str
    refresh_token: str | None
    token_type: str | None
    expires_at: datetime | None
    metadata: dict[str, Any]
    kek_version: str


@dataclass(frozen=True)
class PasswordRecord:
    agent_id: str
    name: str
    username: str | None
    password: str
    url: str | None
    metadata: dict[str, Any]
    kek_version: str
