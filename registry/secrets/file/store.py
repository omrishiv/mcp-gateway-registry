"""FernetFileStore -- dev-only SecretStore backed by per-principal JSON files.

One file per principal at ``{base}/{enc(auth_method)}_{enc(user_id)}.json``
holding a ``{map_key(provider, server_path): StoredToken}`` map, with the whole
serialized map Fernet-encrypted via the existing ``credential_encryption``
(PBKDF2-from-SECRET_KEY) utility.

GATED: this backend keeps per-user refresh tokens in a local file and MUST NOT
reach production. ``factory.py`` refuses it when a production marker is set, and
emits a startup WARNING whenever it is selected. Files are created ``0o600``
inside a ``0o700`` directory; we do not rely on umask.

The principal prefix uses ``/`` -> ``_`` collapsing only for the FILENAME
(filesystems disallow ``/`` in a name); the logical key still goes through the
shared ``keys`` helpers so the on-the-wire map keys match the other backends
byte-for-byte (asserted by the cross-store round-trip test).
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from registry.egress_auth.schemas import StoredToken
from registry.secrets import keys
from registry.secrets.interfaces import SecretStoreBase, SecretStoreError
from registry.utils.credential_encryption import decrypt_credential, encrypt_credential

logger = logging.getLogger(__name__)

_DIR_MODE = 0o700
_FILE_MODE = 0o600


class FernetFileStore(SecretStoreBase):
    """Per-principal Fernet-encrypted JSON files. Dev only."""

    def __init__(self, base_dir: str | Path) -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)
        self._enforce_dir_mode()
        # Serialize read-modify-write per process so two concurrent puts to the
        # same principal file don't clobber. (Single-host only -- dev backend.)
        self._lock = asyncio.Lock()
        logger.warning(
            "FernetFileStore (dev-fernet) is active: per-user egress tokens are stored "
            "in local files under %s. This backend MUST NOT be used in production.",
            self._base,
        )

    def _enforce_dir_mode(self) -> None:
        try:
            current = self._base.stat().st_mode & 0o777
            if current != _DIR_MODE:
                logger.warning(
                    "egress_secrets dir %s has mode %o; tightening to %o",
                    self._base,
                    current,
                    _DIR_MODE,
                )
                os.chmod(self._base, _DIR_MODE)
        except OSError as exc:
            logger.error("Could not enforce mode on %s: %s", self._base, exc)

    def _principal_file(self, auth_method: str, user_id: str) -> Path:
        # Filenames can't contain "/", so join the two already-encoded segments
        # with "_" purely for the on-disk name. The logical principal/map keys
        # are unchanged.
        principal = keys.user_principal(auth_method, user_id).replace("/", "_")
        return self._base / f"{principal}.json"

    def _read_map(self, path: Path) -> dict[str, dict]:
        if not path.exists():
            return {}
        try:
            ciphertext = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SecretStoreError(f"Could not read egress secret file: {exc}") from exc
        if not ciphertext.strip():
            return {}
        plaintext = decrypt_credential(ciphertext)
        if plaintext is None:
            # SECRET_KEY changed or corruption -- fail closed, do not silently
            # treat as empty (that would mask a real problem and re-consent loop).
            raise SecretStoreError(
                f"Could not decrypt egress secret file {path.name} (SECRET_KEY may have changed)."
            )
        return json.loads(plaintext)

    def _write_map(self, path: Path, data: dict[str, dict]) -> None:
        ciphertext = encrypt_credential(json.dumps(data))
        # Write to a temp file with restrictive perms then atomically replace.
        tmp = path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(ciphertext)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise SecretStoreError(f"Could not write egress secret file: {exc}") from exc
        os.replace(tmp, path)
        os.chmod(path, _FILE_MODE)

    async def put_token(
        self,
        auth_method: str,
        user_id: str,
        provider: str,
        server_path: str,
        token: StoredToken,
    ) -> None:
        path = self._principal_file(auth_method, user_id)
        key = keys.map_key(provider, server_path)
        async with self._lock:
            data = self._read_map(path)
            data[key] = token.model_dump()
            self._write_map(path, data)

    async def get_token(
        self,
        auth_method: str,
        user_id: str,
        provider: str,
        server_path: str,
    ) -> StoredToken | None:
        path = self._principal_file(auth_method, user_id)
        key = keys.map_key(provider, server_path)
        async with self._lock:
            data = self._read_map(path)
        raw = data.get(key)
        return StoredToken(**raw) if raw is not None else None

    async def delete_token(
        self,
        auth_method: str,
        user_id: str,
        provider: str,
        server_path: str,
    ) -> None:
        path = self._principal_file(auth_method, user_id)
        key = keys.map_key(provider, server_path)
        async with self._lock:
            data = self._read_map(path)
            if key in data:
                del data[key]
                if data:
                    self._write_map(path, data)
                else:
                    path.unlink(missing_ok=True)

    async def list_for_user(
        self,
        auth_method: str,
        user_id: str,
    ) -> list[tuple[str, str, StoredToken]]:
        path = self._principal_file(auth_method, user_id)
        async with self._lock:
            data = self._read_map(path)
        out: list[tuple[str, str, StoredToken]] = []
        for key, raw in data.items():
            provider_enc, _, server_enc = key.partition(keys.MAP_KEY_DELIMITER)
            # The map key holds ENCODED segments; decode for the caller-facing view.
            from urllib.parse import unquote

            out.append((unquote(provider_enc), unquote(server_enc), StoredToken(**raw)))
        return out
