from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from key_store.models import AuthorizationRecord, PasswordRecord
from key_store.store import KeyStore

mcp = FastMCP("SquidKeys")
_store: KeyStore | None = None


def _get_store() -> KeyStore:
    global _store
    if _store is None:
        db_path = os.getenv("KEY_STORE_DB_PATH", "./keystore.duckdb")
        _store = KeyStore(db_path=db_path)
    return _store


@mcp.tool(description="Store or update an authorization token record")
def save_authorization(
    agent_id: str,
    provider: str,
    access_token: str,
    account_id: str | None = None,
    refresh_token: str | None = None,
    token_type: str | None = None,
    scopes: list[str] | None = None,
    expires_at_iso: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str = "mcp",
) -> dict[str, Any]:
    expires_at = _parse_datetime(expires_at_iso)
    store = _get_store()
    store.save_authorization(
        agent_id=agent_id,
        provider=provider,
        account_id=account_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type=token_type,
        scopes=scopes,
        expires_at=expires_at,
        metadata=metadata,
        actor=actor,
    )
    record = store.get_authorization(
        agent_id=agent_id,
        provider=provider,
        account_id=account_id,
        actor=actor,
    )
    return _auth_to_dict(record) if record else {"saved": True}


@mcp.tool(description="Fetch a stored authorization token record")
def get_authorization(
    agent_id: str,
    provider: str,
    account_id: str | None = None,
    actor: str = "mcp",
) -> dict[str, Any] | None:
    record = _get_store().get_authorization(
        agent_id=agent_id,
        provider=provider,
        account_id=account_id,
        actor=actor,
    )
    return _auth_to_dict(record) if record else None


@mcp.tool(description="Delete an authorization token record")
def delete_authorization(
    agent_id: str,
    provider: str,
    account_id: str | None = None,
    actor: str = "mcp",
) -> dict[str, bool]:
    deleted = _get_store().delete_authorization(
        agent_id=agent_id,
        provider=provider,
        account_id=account_id,
        actor=actor,
    )
    return {"deleted": deleted}


@mcp.tool(description="Store or update a password secret")
def save_password(
    agent_id: str,
    name: str,
    password: str,
    username: str | None = None,
    url: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str = "mcp",
) -> dict[str, Any]:
    store = _get_store()
    store.save_password(
        agent_id=agent_id,
        name=name,
        password=password,
        username=username,
        url=url,
        metadata=metadata,
        actor=actor,
    )
    record = store.get_password(agent_id=agent_id, name=name, actor=actor)
    return _password_to_dict(record) if record else {"saved": True}


@mcp.tool(description="Fetch a stored password secret")
def get_password(agent_id: str, name: str, actor: str = "mcp") -> dict[str, Any] | None:
    record = _get_store().get_password(agent_id=agent_id, name=name, actor=actor)
    return _password_to_dict(record) if record else None


@mcp.tool(description="Delete a stored password secret")
def delete_password(agent_id: str, name: str, actor: str = "mcp") -> dict[str, bool]:
    deleted = _get_store().delete_password(agent_id=agent_id, name=name, actor=actor)
    return {"deleted": deleted}


@mcp.tool(description="Show loaded and active KEK versions")
def key_status() -> dict[str, Any]:
    return _get_store().key_status()


@mcp.tool(description="Re-wrap all records to the target or active KEK version")
def rewrap_all_records(target_kek_version: str | None = None, actor: str = "mcp") -> dict[str, Any]:
    return _get_store().rewrap_all_records(target_kek_version=target_kek_version, actor=actor)


def main() -> None:
    mcp.run(transport=os.getenv("KEY_STORE_MCP_TRANSPORT", "stdio"))


def _auth_to_dict(record: AuthorizationRecord) -> dict[str, Any]:
    return {
        "agent_id": record.agent_id,
        "provider": record.provider,
        "account_id": record.account_id,
        "scopes": record.scopes,
        "access_token": record.access_token,
        "refresh_token": record.refresh_token,
        "token_type": record.token_type,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "metadata": record.metadata,
        "kek_version": record.kek_version,
    }


def _password_to_dict(record: PasswordRecord) -> dict[str, Any]:
    return {
        "agent_id": record.agent_id,
        "name": record.name,
        "username": record.username,
        "password": record.password,
        "url": record.url,
        "metadata": record.metadata,
        "kek_version": record.kek_version,
    }


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


if __name__ == "__main__":
    main()
