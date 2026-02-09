from __future__ import annotations

import base64
import json
import os
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from key_store.models import AuthorizationRecord, PasswordRecord


class KeyStoreError(Exception):
    """Base error for key store failures."""


class KeyStoreConfigError(KeyStoreError):
    """Raised when secure configuration is missing or invalid."""


class KeyStore:
    """Encrypted credential storage for agent authorizations and passwords."""

    KEKS_ENV = "KEY_STORE_KEKS_JSON"
    ACTIVE_KEK_VERSION_ENV = "KEY_STORE_ACTIVE_KEK_VERSION"
    LEGACY_MASTER_KEY_ENV = "KEY_STORE_MASTER_KEY"

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        keks_b64: dict[str, str] | None = None,
        active_kek_version: str | None = None,
    ) -> None:
        self._db_path = str(Path(db_path))
        self._lock = threading.RLock()
        self._conn = duckdb.connect(self._db_path)

        self._keks, self._active_kek_version = self._load_keks(keks_b64, active_kek_version)

        self._initialize()
        self._sync_key_versions()

    @staticmethod
    def generate_key() -> str:
        """Generate a URL-safe base64 encoded 256-bit key."""
        return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

    @staticmethod
    def generate_master_key() -> str:
        """Backward-compatible alias for generate_key()."""
        return KeyStore.generate_key()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def key_status(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT kek_version, is_active, created_at
                FROM key_versions
                ORDER BY kek_version
                """
            ).fetchall()

        return {
            "active_kek_version": self._active_kek_version,
            "loaded_kek_versions": sorted(self._keks.keys()),
            "registered_kek_versions": [
                {
                    "kek_version": row[0],
                    "is_active": bool(row[1]),
                    "created_at": datetime.fromtimestamp(row[2], tz=UTC),
                }
                for row in rows
            ],
        }

    def save_authorization(
        self,
        *,
        agent_id: str,
        provider: str,
        access_token: str,
        account_id: str | None = None,
        refresh_token: str | None = None,
        token_type: str | None = None,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> None:
        self._validate_non_empty(agent_id, "agent_id")
        self._validate_non_empty(provider, "provider")
        self._validate_non_empty(access_token, "access_token")

        account_id_key = self._account_id_key(account_id)
        dek = os.urandom(32)

        wrapped_dek_nonce, wrapped_dek = self._wrap_dek(
            dek,
            kek_version=self._active_kek_version,
            record_type="auth",
            agent_id=agent_id,
            record_identity=f"{provider}|{account_id_key}",
        )

        access_nonce, access_ciphertext = self._encrypt_with_dek(
            dek,
            access_token,
            self._aad("auth", agent_id, provider, account_id_key, "access"),
        )

        refresh_nonce = None
        refresh_ciphertext = None
        if refresh_token is not None:
            refresh_nonce, refresh_ciphertext = self._encrypt_with_dek(
                dek,
                refresh_token,
                self._aad("auth", agent_id, provider, account_id_key, "refresh"),
            )

        now = int(time.time())

        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT INTO auth_secrets (
                        agent_id,
                        provider,
                        account_id,
                        account_id_key,
                        scopes,
                        access_nonce,
                        access_ciphertext,
                        refresh_nonce,
                        refresh_ciphertext,
                        token_type,
                        expires_at,
                        metadata,
                        wrapped_dek_nonce,
                        wrapped_dek,
                        kek_version,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (agent_id, provider, account_id_key) DO UPDATE SET
                        account_id = excluded.account_id,
                        scopes = excluded.scopes,
                        access_nonce = excluded.access_nonce,
                        access_ciphertext = excluded.access_ciphertext,
                        refresh_nonce = excluded.refresh_nonce,
                        refresh_ciphertext = excluded.refresh_ciphertext,
                        token_type = excluded.token_type,
                        expires_at = excluded.expires_at,
                        metadata = excluded.metadata,
                        wrapped_dek_nonce = excluded.wrapped_dek_nonce,
                        wrapped_dek = excluded.wrapped_dek,
                        kek_version = excluded.kek_version,
                        updated_at = excluded.updated_at
                    """,
                    [
                        agent_id,
                        provider,
                        account_id,
                        account_id_key,
                        json.dumps(scopes or []),
                        access_nonce,
                        access_ciphertext,
                        refresh_nonce,
                        refresh_ciphertext,
                        token_type,
                        int(expires_at.timestamp()) if expires_at else None,
                        json.dumps(metadata or {}, separators=(",", ":")),
                        wrapped_dek_nonce,
                        wrapped_dek,
                        self._active_kek_version,
                        now,
                        now,
                    ],
                )
            self._audit(
                operation="save",
                record_type="authorization",
                actor=actor,
                status="ok",
                agent_id=agent_id,
                provider=provider,
                account_id_key=account_id_key,
            )
        except Exception as exc:
            self._audit(
                operation="save",
                record_type="authorization",
                actor=actor,
                status="error",
                agent_id=agent_id,
                provider=provider,
                account_id_key=account_id_key,
                error=str(exc),
            )
            raise

    def get_authorization(
        self,
        *,
        agent_id: str,
        provider: str,
        account_id: str | None = None,
        actor: str = "system",
    ) -> AuthorizationRecord | None:
        self._validate_non_empty(agent_id, "agent_id")
        self._validate_non_empty(provider, "provider")

        account_id_key = self._account_id_key(account_id)

        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    account_id,
                    scopes,
                    access_nonce,
                    access_ciphertext,
                    refresh_nonce,
                    refresh_ciphertext,
                    token_type,
                    expires_at,
                    metadata,
                    wrapped_dek_nonce,
                    wrapped_dek,
                    kek_version
                FROM auth_secrets
                WHERE agent_id = ? AND provider = ? AND account_id_key = ?
                """,
                [agent_id, provider, account_id_key],
            ).fetchone()

        if row is None:
            self._audit(
                operation="get",
                record_type="authorization",
                actor=actor,
                status="miss",
                agent_id=agent_id,
                provider=provider,
                account_id_key=account_id_key,
            )
            return None

        try:
            dek = self._unwrap_dek(
                wrapped_dek_nonce=row[9],
                wrapped_dek=row[10],
                kek_version=row[11],
                record_type="auth",
                agent_id=agent_id,
                record_identity=f"{provider}|{account_id_key}",
            )

            access_token = self._decrypt_with_dek(
                dek,
                nonce=row[2],
                ciphertext=row[3],
                aad=self._aad("auth", agent_id, provider, account_id_key, "access"),
            )

            refresh_token = None
            if row[4] is not None and row[5] is not None:
                refresh_token = self._decrypt_with_dek(
                    dek,
                    nonce=row[4],
                    ciphertext=row[5],
                    aad=self._aad("auth", agent_id, provider, account_id_key, "refresh"),
                )

            expires_at = datetime.fromtimestamp(row[7], tz=UTC) if row[7] is not None else None

            record = AuthorizationRecord(
                agent_id=agent_id,
                provider=provider,
                account_id=row[0],
                scopes=json.loads(row[1]),
                access_token=access_token,
                refresh_token=refresh_token,
                token_type=row[6],
                expires_at=expires_at,
                metadata=json.loads(row[8]),
                kek_version=row[11],
            )

            self._audit(
                operation="get",
                record_type="authorization",
                actor=actor,
                status="ok",
                agent_id=agent_id,
                provider=provider,
                account_id_key=account_id_key,
            )
            return record
        except Exception as exc:
            self._audit(
                operation="get",
                record_type="authorization",
                actor=actor,
                status="error",
                agent_id=agent_id,
                provider=provider,
                account_id_key=account_id_key,
                error=str(exc),
            )
            raise

    def delete_authorization(
        self,
        *,
        agent_id: str,
        provider: str,
        account_id: str | None = None,
        actor: str = "system",
    ) -> bool:
        self._validate_non_empty(agent_id, "agent_id")
        self._validate_non_empty(provider, "provider")

        account_id_key = self._account_id_key(account_id)

        with self._lock:
            deleted = (
                self._conn.execute(
                    """
                    DELETE FROM auth_secrets
                    WHERE agent_id = ? AND provider = ? AND account_id_key = ?
                    RETURNING 1
                    """,
                    [agent_id, provider, account_id_key],
                ).fetchone()
                is not None
            )

        self._audit(
            operation="delete",
            record_type="authorization",
            actor=actor,
            status="ok" if deleted else "miss",
            agent_id=agent_id,
            provider=provider,
            account_id_key=account_id_key,
        )
        return deleted

    def save_password(
        self,
        *,
        agent_id: str,
        name: str,
        password: str,
        username: str | None = None,
        url: str | None = None,
        metadata: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> None:
        self._validate_non_empty(agent_id, "agent_id")
        self._validate_non_empty(name, "name")
        self._validate_non_empty(password, "password")

        dek = os.urandom(32)
        wrapped_dek_nonce, wrapped_dek = self._wrap_dek(
            dek,
            kek_version=self._active_kek_version,
            record_type="pwd",
            agent_id=agent_id,
            record_identity=name,
        )

        password_nonce, password_ciphertext = self._encrypt_with_dek(
            dek,
            password,
            self._aad("pwd", agent_id, name, "password"),
        )

        now = int(time.time())

        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT INTO password_secrets (
                        agent_id,
                        name,
                        username,
                        url,
                        metadata,
                        wrapped_dek_nonce,
                        wrapped_dek,
                        password_nonce,
                        password_ciphertext,
                        kek_version,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (agent_id, name) DO UPDATE SET
                        username = excluded.username,
                        url = excluded.url,
                        metadata = excluded.metadata,
                        wrapped_dek_nonce = excluded.wrapped_dek_nonce,
                        wrapped_dek = excluded.wrapped_dek,
                        password_nonce = excluded.password_nonce,
                        password_ciphertext = excluded.password_ciphertext,
                        kek_version = excluded.kek_version,
                        updated_at = excluded.updated_at
                    """,
                    [
                        agent_id,
                        name,
                        username,
                        url,
                        json.dumps(metadata or {}, separators=(",", ":")),
                        wrapped_dek_nonce,
                        wrapped_dek,
                        password_nonce,
                        password_ciphertext,
                        self._active_kek_version,
                        now,
                        now,
                    ],
                )
            self._audit(
                operation="save",
                record_type="password",
                actor=actor,
                status="ok",
                agent_id=agent_id,
                name=name,
            )
        except Exception as exc:
            self._audit(
                operation="save",
                record_type="password",
                actor=actor,
                status="error",
                agent_id=agent_id,
                name=name,
                error=str(exc),
            )
            raise

    def get_password(self, *, agent_id: str, name: str, actor: str = "system") -> PasswordRecord | None:
        self._validate_non_empty(agent_id, "agent_id")
        self._validate_non_empty(name, "name")

        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    username,
                    url,
                    metadata,
                    wrapped_dek_nonce,
                    wrapped_dek,
                    password_nonce,
                    password_ciphertext,
                    kek_version
                FROM password_secrets
                WHERE agent_id = ? AND name = ?
                """,
                [agent_id, name],
            ).fetchone()

        if row is None:
            self._audit(
                operation="get",
                record_type="password",
                actor=actor,
                status="miss",
                agent_id=agent_id,
                name=name,
            )
            return None

        try:
            dek = self._unwrap_dek(
                wrapped_dek_nonce=row[3],
                wrapped_dek=row[4],
                kek_version=row[7],
                record_type="pwd",
                agent_id=agent_id,
                record_identity=name,
            )
            password = self._decrypt_with_dek(
                dek,
                nonce=row[5],
                ciphertext=row[6],
                aad=self._aad("pwd", agent_id, name, "password"),
            )

            record = PasswordRecord(
                agent_id=agent_id,
                name=name,
                username=row[0],
                password=password,
                url=row[1],
                metadata=json.loads(row[2]),
                kek_version=row[7],
            )

            self._audit(
                operation="get",
                record_type="password",
                actor=actor,
                status="ok",
                agent_id=agent_id,
                name=name,
            )
            return record
        except Exception as exc:
            self._audit(
                operation="get",
                record_type="password",
                actor=actor,
                status="error",
                agent_id=agent_id,
                name=name,
                error=str(exc),
            )
            raise

    def delete_password(self, *, agent_id: str, name: str, actor: str = "system") -> bool:
        self._validate_non_empty(agent_id, "agent_id")
        self._validate_non_empty(name, "name")

        with self._lock:
            deleted = (
                self._conn.execute(
                    """
                    DELETE FROM password_secrets
                    WHERE agent_id = ? AND name = ?
                    RETURNING 1
                    """,
                    [agent_id, name],
                ).fetchone()
                is not None
            )

        self._audit(
            operation="delete",
            record_type="password",
            actor=actor,
            status="ok" if deleted else "miss",
            agent_id=agent_id,
            name=name,
        )
        return deleted

    def rewrap_all_records(self, target_kek_version: str | None = None, actor: str = "system") -> dict[str, int]:
        """Re-wrap all DEKs using the target (or active) KEK version."""
        target = target_kek_version or self._active_kek_version
        if target not in self._keks:
            raise KeyStoreConfigError(f"Unknown target_kek_version: {target}")

        auth_rewrapped = 0
        pwd_rewrapped = 0

        with self._lock:
            auth_rows = self._conn.execute(
                """
                SELECT agent_id, provider, account_id_key, wrapped_dek_nonce, wrapped_dek, kek_version
                FROM auth_secrets
                WHERE kek_version <> ?
                """,
                [target],
            ).fetchall()

            for row in auth_rows:
                agent_id, provider, account_id_key, wrapped_nonce, wrapped_dek, old_version = row
                dek = self._unwrap_dek(
                    wrapped_dek_nonce=wrapped_nonce,
                    wrapped_dek=wrapped_dek,
                    kek_version=old_version,
                    record_type="auth",
                    agent_id=agent_id,
                    record_identity=f"{provider}|{account_id_key}",
                )
                new_nonce, new_wrapped = self._wrap_dek(
                    dek,
                    kek_version=target,
                    record_type="auth",
                    agent_id=agent_id,
                    record_identity=f"{provider}|{account_id_key}",
                )
                self._conn.execute(
                    """
                    UPDATE auth_secrets
                    SET wrapped_dek_nonce = ?, wrapped_dek = ?, kek_version = ?, updated_at = ?
                    WHERE agent_id = ? AND provider = ? AND account_id_key = ?
                    """,
                    [new_nonce, new_wrapped, target, int(time.time()), agent_id, provider, account_id_key],
                )
                auth_rewrapped += 1

            pwd_rows = self._conn.execute(
                """
                SELECT agent_id, name, wrapped_dek_nonce, wrapped_dek, kek_version
                FROM password_secrets
                WHERE kek_version <> ?
                """,
                [target],
            ).fetchall()

            for row in pwd_rows:
                agent_id, name, wrapped_nonce, wrapped_dek, old_version = row
                dek = self._unwrap_dek(
                    wrapped_dek_nonce=wrapped_nonce,
                    wrapped_dek=wrapped_dek,
                    kek_version=old_version,
                    record_type="pwd",
                    agent_id=agent_id,
                    record_identity=name,
                )
                new_nonce, new_wrapped = self._wrap_dek(
                    dek,
                    kek_version=target,
                    record_type="pwd",
                    agent_id=agent_id,
                    record_identity=name,
                )
                self._conn.execute(
                    """
                    UPDATE password_secrets
                    SET wrapped_dek_nonce = ?, wrapped_dek = ?, kek_version = ?, updated_at = ?
                    WHERE agent_id = ? AND name = ?
                    """,
                    [new_nonce, new_wrapped, target, int(time.time()), agent_id, name],
                )
                pwd_rewrapped += 1

            self._active_kek_version = target
            self._sync_key_versions()

        self._audit(
            operation="rewrap",
            record_type="all",
            actor=actor,
            status="ok",
            error=None,
        )

        return {
            "target_kek_version": target,
            "authorizations_rewrapped": auth_rewrapped,
            "passwords_rewrapped": pwd_rewrapped,
        }

    def _initialize(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_secrets (
                    agent_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    account_id TEXT,
                    account_id_key TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    access_nonce BLOB NOT NULL,
                    access_ciphertext BLOB NOT NULL,
                    refresh_nonce BLOB,
                    refresh_ciphertext BLOB,
                    token_type TEXT,
                    expires_at BIGINT,
                    metadata TEXT NOT NULL,
                    wrapped_dek_nonce BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    kek_version TEXT NOT NULL,
                    created_at BIGINT NOT NULL,
                    updated_at BIGINT NOT NULL,
                    UNIQUE(agent_id, provider, account_id_key)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS password_secrets (
                    agent_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    username TEXT,
                    url TEXT,
                    metadata TEXT NOT NULL,
                    wrapped_dek_nonce BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    password_nonce BLOB NOT NULL,
                    password_ciphertext BLOB NOT NULL,
                    kek_version TEXT NOT NULL,
                    created_at BIGINT NOT NULL,
                    updated_at BIGINT NOT NULL,
                    UNIQUE(agent_id, name)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS key_versions (
                    kek_version TEXT PRIMARY KEY,
                    is_active BOOLEAN NOT NULL,
                    created_at BIGINT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    status TEXT NOT NULL,
                    agent_id TEXT,
                    provider TEXT,
                    account_id_key TEXT,
                    name TEXT,
                    error TEXT,
                    created_at BIGINT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_auth_lookup
                ON auth_secrets (agent_id, provider, account_id_key)
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pwd_lookup
                ON password_secrets (agent_id, name)
                """
            )

    def _sync_key_versions(self) -> None:
        now = int(time.time())
        with self._lock:
            for version in self._keks:
                self._conn.execute(
                    """
                    INSERT INTO key_versions (kek_version, is_active, created_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT (kek_version) DO UPDATE SET
                        is_active = excluded.is_active
                    """,
                    [version, version == self._active_kek_version, now],
                )

            self._conn.execute(
                """
                UPDATE key_versions
                SET is_active = FALSE
                WHERE kek_version <> ?
                """,
                [self._active_kek_version],
            )

    def _audit(
        self,
        *,
        operation: str,
        record_type: str,
        actor: str,
        status: str,
        agent_id: str | None = None,
        provider: str | None = None,
        account_id_key: str | None = None,
        name: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_log (
                    event_id,
                    operation,
                    record_type,
                    actor,
                    status,
                    agent_id,
                    provider,
                    account_id_key,
                    name,
                    error,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    str(uuid.uuid4()),
                    operation,
                    record_type,
                    actor,
                    status,
                    agent_id,
                    provider,
                    account_id_key,
                    name,
                    error,
                    int(time.time()),
                ],
            )

    @classmethod
    def _load_keks(
        cls,
        override_keks_b64: dict[str, str] | None,
        override_active_version: str | None,
    ) -> tuple[dict[str, bytes], str]:
        if override_keks_b64:
            keks_raw = override_keks_b64
        else:
            env_json = os.getenv(cls.KEKS_ENV)
            if env_json:
                try:
                    parsed = json.loads(env_json)
                except Exception as exc:
                    raise KeyStoreConfigError(f"{cls.KEKS_ENV} is not valid JSON") from exc

                if not isinstance(parsed, dict) or not parsed:
                    raise KeyStoreConfigError(f"{cls.KEKS_ENV} must be a non-empty JSON object")
                keks_raw = {str(k): str(v) for k, v in parsed.items()}
            else:
                legacy_key = os.getenv(cls.LEGACY_MASTER_KEY_ENV)
                if not legacy_key:
                    raise KeyStoreConfigError(
                        f"Set {cls.KEKS_ENV} (JSON map) or legacy {cls.LEGACY_MASTER_KEY_ENV}."
                    )
                keks_raw = {"v1": legacy_key}

        keks = {version: cls._decode_key(key_b64, version) for version, key_b64 in keks_raw.items()}

        active_version = override_active_version or os.getenv(cls.ACTIVE_KEK_VERSION_ENV)
        if not active_version:
            active_version = sorted(keks.keys())[-1]

        if active_version not in keks:
            raise KeyStoreConfigError(
                f"Active KEK version '{active_version}' is not available in configured keys"
            )

        return keks, active_version

    @staticmethod
    def _decode_key(key_b64: str, version: str) -> bytes:
        try:
            key = base64.urlsafe_b64decode(key_b64)
        except Exception as exc:
            raise KeyStoreConfigError(f"KEK '{version}' is not valid URL-safe base64") from exc

        if len(key) != 32:
            raise KeyStoreConfigError(f"KEK '{version}' must decode to 32 bytes")
        return key

    @staticmethod
    def _aad(*parts: str) -> bytes:
        return "|".join(parts).encode("utf-8")

    @staticmethod
    def _account_id_key(account_id: str | None) -> str:
        if account_id is None:
            return ""
        value = account_id.strip()
        return value

    def _wrap_dek(
        self,
        dek: bytes,
        *,
        kek_version: str,
        record_type: str,
        agent_id: str,
        record_identity: str,
    ) -> tuple[bytes, bytes]:
        kek = self._keks[kek_version]
        nonce = os.urandom(12)
        aad = self._aad("wrap", record_type, agent_id, record_identity, kek_version)
        wrapped = AESGCM(kek).encrypt(nonce, dek, aad)
        return nonce, wrapped

    def _unwrap_dek(
        self,
        *,
        wrapped_dek_nonce: bytes,
        wrapped_dek: bytes,
        kek_version: str,
        record_type: str,
        agent_id: str,
        record_identity: str,
    ) -> bytes:
        kek = self._keks.get(kek_version)
        if kek is None:
            raise KeyStoreConfigError(
                f"Cannot decrypt record wrapped with KEK '{kek_version}' because that key is not loaded"
            )
        aad = self._aad("wrap", record_type, agent_id, record_identity, kek_version)
        return AESGCM(kek).decrypt(wrapped_dek_nonce, wrapped_dek, aad)

    @staticmethod
    def _encrypt_with_dek(dek: bytes, plaintext: str, aad: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
        return nonce, ciphertext

    @staticmethod
    def _decrypt_with_dek(dek: bytes, *, nonce: bytes, ciphertext: bytes, aad: bytes) -> str:
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, aad)
        return plaintext.decode("utf-8")

    @staticmethod
    def _validate_non_empty(value: str, name: str) -> None:
        if not value or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
