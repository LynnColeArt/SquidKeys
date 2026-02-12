# SquidKeys

DuckDB-backed encrypted credential storage for single-user, multi-agent systems.

SquidKeys exposes the same storage engine through:

- FastAPI (`squidkeys-api`)
- MCP server (`squidkeys-mcp`)

It stores two record types:

- Authorizations (Discord/app OAuth tokens)
- Password secrets

## Security model

- Per-record DEK (`32 bytes`) encrypts secret fields with `AES-256-GCM`.
- DEK is wrapped by a versioned KEK (`AES-256-GCM`).
- AAD binds encryption to `agent_id + record_type + record_identity`.
- KEKs are never stored in DuckDB.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## Configure keys

Generate a key in Python:

```python
from key_store import KeyStore
print(KeyStore.generate_key())
```

Set KEKs and active version:

```bash
export KEY_STORE_KEKS_JSON='{"v1":"<base64-32-byte-key>"}'
export KEY_STORE_ACTIVE_KEK_VERSION='v1'
export KEY_STORE_DB_PATH='./keystore.duckdb'
export KEY_STORE_BEARER_TOKEN='<shared-api-token>'
```

Legacy fallback: if `KEY_STORE_KEKS_JSON` is not set, `KEY_STORE_MASTER_KEY` is used as `v1`.

## Run FastAPI

```bash
squidkeys-api
```

Default bind: `127.0.0.1:8080`.
If `KEY_STORE_BEARER_TOKEN` is set, all `/v1/*` routes require
`Authorization: Bearer <token>`.

Key routes:

- `PUT /v1/authorizations`
- `GET /v1/authorizations/{agent_id}/{provider}`
- `DELETE /v1/authorizations/{agent_id}/{provider}`
- `PUT /v1/passwords`
- `GET /v1/passwords/{agent_id}/{name}`
- `DELETE /v1/passwords/{agent_id}/{name}`
- `GET /v1/keys/status`
- `POST /v1/keys/rewrap`

## Run MCP server

```bash
squidkeys-mcp
```

Default transport: `stdio`.

Available tools:

- `save_authorization`
- `get_authorization`
- `delete_authorization`
- `save_password`
- `get_password`
- `delete_password`
- `key_status`
- `rewrap_all_records`

## YAML interface map

Interface-to-storage mapping is documented in:

- `docs/interface-map.yaml`

## Tests

```bash
pytest
```

## License

GPL-3.0-only. See `LICENSE`.
