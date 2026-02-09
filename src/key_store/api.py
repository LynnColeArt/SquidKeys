from __future__ import annotations

import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from key_store.models import AuthorizationRecord, PasswordRecord
from key_store.store import KeyStore, KeyStoreConfigError


class AuthorizationUpsertRequest(BaseModel):
    agent_id: str
    provider: str
    access_token: str
    account_id: str | None = None
    refresh_token: str | None = None
    token_type: str | None = None
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    actor: str = "api"


class PasswordUpsertRequest(BaseModel):
    agent_id: str
    name: str
    password: str
    username: str | None = None
    url: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    actor: str = "api"


class RewrapRequest(BaseModel):
    target_kek_version: str | None = None
    actor: str = "api"


class DeleteResponse(BaseModel):
    deleted: bool


class AuthorizationResponse(BaseModel):
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


class PasswordResponse(BaseModel):
    agent_id: str
    name: str
    username: str | None
    password: str
    url: str | None
    metadata: dict[str, Any]
    kek_version: str


class KeyStatusResponse(BaseModel):
    active_kek_version: str
    loaded_kek_versions: list[str]
    registered_kek_versions: list[dict[str, Any]]


class RewrapResponse(BaseModel):
    target_kek_version: str
    authorizations_rewrapped: int
    passwords_rewrapped: int


def create_app(store: KeyStore | None = None) -> FastAPI:
    owns_store = store is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if owns_store:
            db_path = os.getenv("KEY_STORE_DB_PATH", "./keystore.duckdb")
            app.state.store = KeyStore(db_path=db_path)

        yield

        if owns_store:
            app.state.store.close()

    app = FastAPI(title="SquidKeys", version="0.2.0", lifespan=lifespan)
    if store is not None:
        app.state.store = store

    def get_store(request: Request) -> KeyStore:
        return request.app.state.store

    def require_bearer(authorization: str | None = Header(default=None)) -> None:
        expected = os.getenv("KEY_STORE_BEARER_TOKEN")
        if not expected:
            return

        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        presented = authorization[7:]
        if not secrets.compare_digest(presented, expected):
            raise HTTPException(
                status_code=401,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.put(
        "/v1/authorizations",
        response_model=AuthorizationResponse,
        dependencies=[Depends(require_bearer)],
    )
    def save_authorization(
        payload: AuthorizationUpsertRequest,
        key_store: KeyStore = Depends(get_store),
    ) -> AuthorizationResponse:
        try:
            key_store.save_authorization(
                agent_id=payload.agent_id,
                provider=payload.provider,
                account_id=payload.account_id,
                access_token=payload.access_token,
                refresh_token=payload.refresh_token,
                token_type=payload.token_type,
                scopes=payload.scopes,
                expires_at=payload.expires_at,
                metadata=payload.metadata,
                actor=payload.actor,
            )
            record = key_store.get_authorization(
                agent_id=payload.agent_id,
                provider=payload.provider,
                account_id=payload.account_id,
                actor=payload.actor,
            )
            if record is None:
                raise HTTPException(status_code=500, detail="record not found after save")
            return _auth_to_response(record)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except KeyStoreConfigError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get(
        "/v1/authorizations/{agent_id}/{provider}",
        response_model=AuthorizationResponse,
        dependencies=[Depends(require_bearer)],
    )
    def get_authorization(
        agent_id: str,
        provider: str,
        account_id: str | None = Query(default=None),
        actor: str = Query(default="api"),
        key_store: KeyStore = Depends(get_store),
    ) -> AuthorizationResponse:
        try:
            record = key_store.get_authorization(
                agent_id=agent_id,
                provider=provider,
                account_id=account_id,
                actor=actor,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if record is None:
            raise HTTPException(status_code=404, detail="authorization not found")
        return _auth_to_response(record)

    @app.delete(
        "/v1/authorizations/{agent_id}/{provider}",
        response_model=DeleteResponse,
        dependencies=[Depends(require_bearer)],
    )
    def delete_authorization(
        agent_id: str,
        provider: str,
        account_id: str | None = Query(default=None),
        actor: str = Query(default="api"),
        key_store: KeyStore = Depends(get_store),
    ) -> DeleteResponse:
        try:
            deleted = key_store.delete_authorization(
                agent_id=agent_id,
                provider=provider,
                account_id=account_id,
                actor=actor,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return DeleteResponse(deleted=deleted)

    @app.put(
        "/v1/passwords",
        response_model=PasswordResponse,
        dependencies=[Depends(require_bearer)],
    )
    def save_password(
        payload: PasswordUpsertRequest,
        key_store: KeyStore = Depends(get_store),
    ) -> PasswordResponse:
        try:
            key_store.save_password(
                agent_id=payload.agent_id,
                name=payload.name,
                password=payload.password,
                username=payload.username,
                url=payload.url,
                metadata=payload.metadata,
                actor=payload.actor,
            )
            record = key_store.get_password(
                agent_id=payload.agent_id,
                name=payload.name,
                actor=payload.actor,
            )
            if record is None:
                raise HTTPException(status_code=500, detail="record not found after save")
            return _password_to_response(record)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except KeyStoreConfigError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get(
        "/v1/passwords/{agent_id}/{name}",
        response_model=PasswordResponse,
        dependencies=[Depends(require_bearer)],
    )
    def get_password(
        agent_id: str,
        name: str,
        actor: str = Query(default="api"),
        key_store: KeyStore = Depends(get_store),
    ) -> PasswordResponse:
        try:
            record = key_store.get_password(agent_id=agent_id, name=name, actor=actor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if record is None:
            raise HTTPException(status_code=404, detail="password not found")
        return _password_to_response(record)

    @app.delete(
        "/v1/passwords/{agent_id}/{name}",
        response_model=DeleteResponse,
        dependencies=[Depends(require_bearer)],
    )
    def delete_password(
        agent_id: str,
        name: str,
        actor: str = Query(default="api"),
        key_store: KeyStore = Depends(get_store),
    ) -> DeleteResponse:
        try:
            deleted = key_store.delete_password(agent_id=agent_id, name=name, actor=actor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return DeleteResponse(deleted=deleted)

    @app.get(
        "/v1/keys/status",
        response_model=KeyStatusResponse,
        dependencies=[Depends(require_bearer)],
    )
    def key_status(key_store: KeyStore = Depends(get_store)) -> KeyStatusResponse:
        status = key_store.key_status()
        return KeyStatusResponse(**status)

    @app.post(
        "/v1/keys/rewrap",
        response_model=RewrapResponse,
        dependencies=[Depends(require_bearer)],
    )
    def rewrap(payload: RewrapRequest, key_store: KeyStore = Depends(get_store)) -> RewrapResponse:
        try:
            result = key_store.rewrap_all_records(
                target_kek_version=payload.target_kek_version,
                actor=payload.actor,
            )
            return RewrapResponse(**result)
        except KeyStoreConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


def _auth_to_response(record: AuthorizationRecord) -> AuthorizationResponse:
    return AuthorizationResponse(
        agent_id=record.agent_id,
        provider=record.provider,
        account_id=record.account_id,
        scopes=record.scopes,
        access_token=record.access_token,
        refresh_token=record.refresh_token,
        token_type=record.token_type,
        expires_at=record.expires_at,
        metadata=record.metadata,
        kek_version=record.kek_version,
    )


def _password_to_response(record: PasswordRecord) -> PasswordResponse:
    return PasswordResponse(
        agent_id=record.agent_id,
        name=record.name,
        username=record.username,
        password=record.password,
        url=record.url,
        metadata=record.metadata,
        kek_version=record.kek_version,
    )
