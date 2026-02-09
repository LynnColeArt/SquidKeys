from __future__ import annotations

from datetime import UTC, datetime

import pytest

from key_store import KeyStore, KeyStoreConfigError


def _keks() -> dict[str, str]:
    return {
        "v1": KeyStore.generate_key(),
        "v2": KeyStore.generate_key(),
    }


def test_requires_key_configuration(tmp_path):
    db_path = tmp_path / "no-key.duckdb"
    with pytest.raises(KeyStoreConfigError):
        KeyStore(db_path)


def test_authorization_round_trip(tmp_path):
    db_path = tmp_path / "auth.duckdb"
    store = KeyStore(db_path, keks_b64=_keks(), active_kek_version="v1")
    expires = datetime(2026, 2, 9, 10, 0, tzinfo=UTC)

    store.save_authorization(
        agent_id="agent-a",
        provider="discord",
        account_id="user-123",
        scopes=["identify", "guilds"],
        access_token="access-abc",
        refresh_token="refresh-xyz",
        token_type="Bearer",
        expires_at=expires,
        metadata={"workspace": "primary"},
    )

    record = store.get_authorization(
        agent_id="agent-a",
        provider="discord",
        account_id="user-123",
    )

    assert record is not None
    assert record.access_token == "access-abc"
    assert record.refresh_token == "refresh-xyz"
    assert record.scopes == ["identify", "guilds"]
    assert record.expires_at == expires
    assert record.metadata == {"workspace": "primary"}
    assert record.kek_version == "v1"

    assert store.delete_authorization(
        agent_id="agent-a",
        provider="discord",
        account_id="user-123",
    )
    assert store.get_authorization(
        agent_id="agent-a",
        provider="discord",
        account_id="user-123",
    ) is None

    store.close()


def test_password_round_trip(tmp_path):
    db_path = tmp_path / "pwd.duckdb"
    store = KeyStore(db_path, keks_b64=_keks(), active_kek_version="v1")

    store.save_password(
        agent_id="agent-a",
        name="openai-api",
        username="svc-agent",
        password="super-secret",
        url="https://api.example.com",
        metadata={"team": "ops"},
    )

    record = store.get_password(agent_id="agent-a", name="openai-api")

    assert record is not None
    assert record.username == "svc-agent"
    assert record.password == "super-secret"
    assert record.url == "https://api.example.com"
    assert record.metadata == {"team": "ops"}
    assert record.kek_version == "v1"

    assert store.delete_password(agent_id="agent-a", name="openai-api")
    assert store.get_password(agent_id="agent-a", name="openai-api") is None

    store.close()


def test_values_are_encrypted_at_rest(tmp_path):
    db_path = tmp_path / "encrypted.duckdb"
    store = KeyStore(db_path, keks_b64=_keks(), active_kek_version="v1")

    store.save_password(agent_id="agent-z", name="db", password="plain-visible-check")
    store.save_authorization(
        agent_id="agent-z",
        provider="app",
        access_token="visible-access-token",
    )
    store.close()

    raw = db_path.read_bytes()
    assert b"plain-visible-check" not in raw
    assert b"visible-access-token" not in raw


def test_rewrap_records(tmp_path):
    db_path = tmp_path / "rewrap.duckdb"
    keys = _keks()
    store = KeyStore(db_path, keks_b64=keys, active_kek_version="v1")

    store.save_password(agent_id="agent-r", name="db", password="rotate-me")
    store.save_authorization(agent_id="agent-r", provider="discord", access_token="rotate-token")

    result = store.rewrap_all_records(target_kek_version="v2")
    assert result["target_kek_version"] == "v2"
    assert result["authorizations_rewrapped"] == 1
    assert result["passwords_rewrapped"] == 1

    pwd = store.get_password(agent_id="agent-r", name="db")
    auth = store.get_authorization(agent_id="agent-r", provider="discord")
    assert pwd is not None and pwd.kek_version == "v2"
    assert auth is not None and auth.kek_version == "v2"

    store.close()
