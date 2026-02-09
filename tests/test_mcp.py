from __future__ import annotations

from key_store import mcp_server
from key_store.store import KeyStore


def test_mcp_tool_functions(tmp_path):
    db_path = tmp_path / "mcp.duckdb"
    store = KeyStore(
        db_path=db_path,
        keks_b64={"v1": KeyStore.generate_key()},
        active_kek_version="v1",
    )
    mcp_server._store = store

    save_pwd = mcp_server.save_password(
        agent_id="agent-1",
        name="service",
        password="mcp-secret",
    )
    assert save_pwd["password"] == "mcp-secret"

    get_pwd = mcp_server.get_password(agent_id="agent-1", name="service")
    assert get_pwd is not None
    assert get_pwd["password"] == "mcp-secret"

    save_auth = mcp_server.save_authorization(
        agent_id="agent-1",
        provider="discord",
        access_token="mcp-token",
    )
    assert save_auth["access_token"] == "mcp-token"

    get_auth = mcp_server.get_authorization(agent_id="agent-1", provider="discord")
    assert get_auth is not None
    assert get_auth["access_token"] == "mcp-token"

    status = mcp_server.key_status()
    assert status["active_kek_version"] == "v1"

    assert mcp_server.delete_password(agent_id="agent-1", name="service")["deleted"] is True
    assert mcp_server.delete_authorization(agent_id="agent-1", provider="discord")["deleted"] is True

    store.close()
    mcp_server._store = None
