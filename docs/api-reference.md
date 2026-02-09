# API Reference

## FastAPI

Base URL: `http://127.0.0.1:8080`

Authentication:

- If `KEY_STORE_BEARER_TOKEN` is unset, `/v1/*` routes are open.
- If set, send `Authorization: Bearer <token>` on all `/v1/*` requests.

### Health

- `GET /health`
- Response: `{"status":"ok"}`

### Authorizations

- `PUT /v1/authorizations`
- Body:

```json
{
  "agent_id": "agent-1",
  "provider": "discord",
  "access_token": "token",
  "account_id": "user-1",
  "refresh_token": "refresh",
  "token_type": "Bearer",
  "scopes": ["identify"],
  "expires_at": "2026-02-09T10:00:00+00:00",
  "metadata": {"env": "prod"},
  "actor": "api"
}
```

- `GET /v1/authorizations/{agent_id}/{provider}?account_id=<optional>&actor=<optional>`
- `DELETE /v1/authorizations/{agent_id}/{provider}?account_id=<optional>&actor=<optional>`

### Passwords

- `PUT /v1/passwords`
- Body:

```json
{
  "agent_id": "agent-1",
  "name": "github",
  "password": "secret",
  "username": "svc-user",
  "url": "https://github.com",
  "metadata": {"team": "ops"},
  "actor": "api"
}
```

- `GET /v1/passwords/{agent_id}/{name}?actor=<optional>`
- `DELETE /v1/passwords/{agent_id}/{name}?actor=<optional>`

### Keys

- `GET /v1/keys/status`
- `POST /v1/keys/rewrap`
- Body:

```json
{
  "target_kek_version": "v2",
  "actor": "api"
}
```

## MCP Tools

Server entrypoint: `squidkeys-mcp`

Default transport: `stdio`

### Tool: `save_authorization`

Inputs:

- `agent_id` (str)
- `provider` (str)
- `access_token` (str)
- `account_id` (str, optional)
- `refresh_token` (str, optional)
- `token_type` (str, optional)
- `scopes` (list[str], optional)
- `expires_at_iso` (ISO datetime, optional)
- `metadata` (dict, optional)
- `actor` (str, optional)

### Tool: `get_authorization`

Inputs: `agent_id`, `provider`, `account_id?`, `actor?`

### Tool: `delete_authorization`

Inputs: `agent_id`, `provider`, `account_id?`, `actor?`

### Tool: `save_password`

Inputs: `agent_id`, `name`, `password`, `username?`, `url?`, `metadata?`, `actor?`

### Tool: `get_password`

Inputs: `agent_id`, `name`, `actor?`

### Tool: `delete_password`

Inputs: `agent_id`, `name`, `actor?`

### Tool: `key_status`

Inputs: none

### Tool: `rewrap_all_records`

Inputs: `target_kek_version?`, `actor?`

## Related Docs

- `README.md`
- `docs/interface-map.yaml`
