# Copyright (c) 2026 Vincent Mucchielli
# SPDX-License-Identifier: BUSL-1.1
"""Per-user API-key minting via the bootstrap module (cloud ADR-C008/C009).

The impersonation tier's gateway-side half: drive the in-Odoo ``mcp_guard_bootstrap``
module — as the dedicated **service principal**, with the shared **module secret** — to
mint a native per-user Odoo API key for an SSO-proven uid. The minted key is a normal
``SecretStr`` the gateway hands to the *sessionless* RPC path, so there is no web session
and therefore no collision with the user's own browser session (ADR-C005).

One service-principal connection drives every mint. Keys are cached per uid and re-minted
before expiry. Secrets are held in memory only (Rule 1 #7), never logged, never persisted.

This module is part of the separately-licensed paid add-on; the MIT core is untouched and
consumes only the resulting ``api_key`` :class:`~odoo_mcp_guard.server.identity.UserSession`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from odoo_mcp_guard.config import ProfileConfig
from odoo_mcp_guard.errors import OdooMcpGuardError
from odoo_mcp_guard.odoo.api import OdooClient
from odoo_mcp_guard.odoo.detect import connect_client
from pydantic import SecretStr

logger = logging.getLogger(__name__)

#: The bootstrap module's gated facade model (its public methods live here).
REGISTRY_MODEL = "mcp_guard.allowed_user"

#: Seconds in a day (keys are minted with a day-granular TTL).
_DAY = 86400.0

ClientFactory = Callable[[ProfileConfig], Awaitable[OdooClient]]
Clock = Callable[[], float]


class MintError(OdooMcpGuardError):
    """The bootstrap module refused or failed to mint/revoke a per-user key.

    Carries no secret. The gateway fails closed (Rule 1 #8): the user's call is denied.
    """


@dataclass(frozen=True)
class MintConfig:
    """What the gateway needs to drive the bootstrap module as the service principal.

    ``profile`` is the dedicated service account's OWN connection (its own API key);
    ``module_secret`` is the ``mcp_guard.module_secret`` shared with the module.
    """

    profile: ProfileConfig
    module_secret: SecretStr
    ttl_days: int = 30
    #: Re-mint this long before the key's TTL elapses (never hand out a soon-dead key).
    rotate_margin_seconds: float = _DAY


@dataclass
class _Cached:
    key: SecretStr
    expires_at: float


class MintingKeyProvider:
    """Mints + caches per-user Odoo API keys via the bootstrap module.

    Example:
        >>> # provider = MintingKeyProvider(MintConfig(profile=svc, module_secret=sec))
        >>> # key = await provider.get_key(uid)   # mints on first use, caches, re-mints
    """

    def __init__(
        self,
        config: MintConfig,
        *,
        client_factory: ClientFactory = connect_client,
        clock: Clock = time.monotonic,
    ) -> None:
        self._config = config
        self._client_factory = client_factory
        self._clock = clock
        self._client: OdooClient | None = None
        self._cache: dict[int, _Cached] = {}
        self._lock = asyncio.Lock()

    async def get_key(self, uid: int) -> SecretStr:
        """A currently-valid per-user key: mint on first use, re-mint before expiry."""
        async with self._lock:
            cached = self._cache.get(uid)
            if cached is not None and self._clock() < cached.expires_at:
                return cached.key
            key = await self._mint(uid)
            lifetime = max(0.0, self._config.ttl_days * _DAY - self._config.rotate_margin_seconds)
            self._cache[uid] = _Cached(key=key, expires_at=self._clock() + lifetime)
            return key

    def forget(self, uid: int) -> None:
        """Drop a cached key — call when a request fails auth with it, so the next call re-mints."""
        self._cache.pop(uid, None)

    async def revoke(self, uid: int, key_id: int) -> bool:
        """Revoke one of the user's keys by id (rotation / cleanup). Returns True if removed."""
        client = await self._conn()
        result = await client.call(
            REGISTRY_MODEL,
            "revoke_user_apikey",
            [],
            {
                "target_uid": uid,
                "module_secret": self._auth_token("revoke_user_apikey", uid),
                "key_id": key_id,
            },
        )
        self.forget(uid)
        return bool(result)

    async def check(self) -> dict[str, Any]:
        """Non-destructively verify the impersonation trust chain (Health/Test MCP).

        Connects as the service principal and calls the module's gated, READ-ONLY
        ``is_mcp_authorized`` (uid 0 — never mints). Success proves: the bootstrap module is
        installed, the service principal is in its group, and the module secret / token is
        accepted. Returns ``{ok, detail}`` — the error is short and carries no secret."""
        try:
            client = await self._conn()
            await client.call(
                REGISTRY_MODEL,
                "is_mcp_authorized",
                [],
                {"target_uid": 0, "module_secret": self._auth_token("is_mcp_authorized", 0)},
            )
        except Exception as exc:
            detail = str(exc).splitlines()[0][:200] if str(exc) else exc.__class__.__name__
            return {"ok": False, "detail": detail}
        return {
            "ok": True,
            "detail": "bootstrap module reachable; service principal + module secret accepted",
        }

    async def list_audit(self, since_id: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        """The module's provisioning-audit rows (mint/revoke/refused) since ``since_id``, for the
        console to mirror. Read-only; never returns a secret."""
        client = await self._conn()
        result = await client.call(
            REGISTRY_MODEL,
            "list_provisioning_audit",
            [],
            {
                "module_secret": self._auth_token("list_provisioning_audit", 0),
                "since_id": since_id,
                "limit": limit,
            },
        )
        return list(result) if isinstance(result, list) else []

    async def list_meta(self, uid: int) -> list[dict[str, Any]]:
        """Metadata (never the secret) for the user's keys, to reconcile / drive rotation."""
        client = await self._conn()
        result = await client.call(
            REGISTRY_MODEL,
            "list_user_apikey_meta",
            [],
            {
                "target_uid": uid,
                "module_secret": self._auth_token("list_user_apikey_meta", uid),
            },
        )
        return list(result) if isinstance(result, list) else []

    # -- internals -----------------------------------------------------------

    def _secret(self) -> str:
        return self._config.module_secret.get_secret_value()

    def _auth_token(self, method: str, uid: int) -> str:
        """A per-call HMAC token (S3): ``v1.<ts>.<nonce>.<mac>`` binding this uid + method +
        a fresh timestamp. Sent instead of the raw module secret so the long-lived secret
        never transits the channel and a captured token cannot be repurposed."""
        ts = int(time.time())
        nonce = secrets.token_urlsafe(9)
        message = f"{ts}.{nonce}.{int(uid)}.{method}"
        mac = hmac.new(
            self._secret().encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"v1.{ts}.{nonce}.{mac}"

    async def _conn(self) -> OdooClient:
        if self._client is None:
            self._client = await self._client_factory(self._config.profile)
        return self._client

    async def _mint(self, uid: int) -> SecretStr:
        client = await self._conn()
        # Pass every argument by NAME: JSON/2 (Odoo 19) rejects positional args, and named
        # args work over XML-RPC too, so this one shape is portable across both transports.
        result = await client.call(
            REGISTRY_MODEL,
            "mint_user_apikey",
            [],
            {
                "target_uid": uid,
                "module_secret": self._auth_token("mint_user_apikey", uid),
                "ttl_days": self._config.ttl_days,
            },
        )
        if not isinstance(result, str) or not result:
            raise MintError(f"bootstrap module returned no key for uid {uid}")
        return SecretStr(result)


def _env_flag(name: str) -> bool:
    """A truthy env flag (1/true/yes/on), case-insensitive."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


#: Hosts on which a plaintext ``http://`` mint channel is tolerated (dev / same host).
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _is_local_host(host: str | None) -> bool:
    """A host whose traffic never crosses the public internet — loopback, mDNS/OrbStack
    (.local / .orb.local) or an RFC-1918 private IPv4."""
    h = (host or "").lower()
    if h in _LOOPBACK_HOSTS:
        return True
    if h.endswith(".orb.local") or h.endswith(".local"):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        a, b = int(parts[0]), int(parts[1])
        return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
    return False


def is_secure_mint_url(url: str) -> bool:
    """True if the service→Odoo channel is safe to send the module secret over.

    The mint call carries the module secret and returns per-user keys in clear, so a
    plaintext ``http://`` channel to a PUBLIC host would leak the whole impersonation trust
    chain to a passive observer (Rule 1 #7/#9). HTTPS is required for public hosts; plaintext
    ``http`` is allowed only to a local/private host (loopback, .orb.local/.local, RFC-1918)
    for local development.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url.strip())
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and _is_local_host(parsed.hostname)


def make_key_provider(profile: ProfileConfig) -> MintingKeyProvider | None:
    """Build the per-user key provider from env, or ``None`` if minting mode is off.

    This is the core's impersonation-minting seam (ADR-C007): the MIT core calls it (via a
    lazy import) and, when it returns a provider, runs EVERY per-user client — SSO, native
    password, or api-key login — with a freshly minted sessionless key.

    Enable with ``ODOO_GUARD_GATEWAY_MINT=1`` plus a dedicated service account
    (``ODOO_GUARD_GATEWAY_MINT_SERVICE_LOGIN`` + ``_SERVICE_API_KEY`` — the account in the
    bootstrap module's service-principal group) and the module secret
    (``ODOO_GUARD_GATEWAY_MINT_MODULE_SECRET``). The service account reuses the tenant's own
    Odoo URL/db/protocol (``profile``). All three are secrets the cloud orchestrator injects
    per tenant — never logged. Incomplete config disables minting (logged, not fatal).
    """
    if not _env_flag("ODOO_GUARD_GATEWAY_MINT"):
        return None
    login = os.environ.get("ODOO_GUARD_GATEWAY_MINT_SERVICE_LOGIN", "").strip()
    api_key = os.environ.get("ODOO_GUARD_GATEWAY_MINT_SERVICE_API_KEY", "").strip()
    secret = os.environ.get("ODOO_GUARD_GATEWAY_MINT_MODULE_SECRET", "").strip()
    if not (login and api_key and secret):
        logger.warning(
            "gateway: ODOO_GUARD_GATEWAY_MINT is set but the service login / API key / "
            "module secret is incomplete; per-user impersonation minting is disabled."
        )
        return None
    if not is_secure_mint_url(profile.url):
        logger.error(
            "gateway: ODOO_GUARD_GATEWAY_MINT is set but the Odoo URL is a non-loopback "
            "http:// endpoint; the module secret and minted keys would traverse plaintext. "
            "Per-user impersonation minting is DISABLED — use https:// (Rule 1 #7/#9)."
        )
        return None
    ttl_raw = os.environ.get("ODOO_GUARD_GATEWAY_MINT_TTL_DAYS", "").strip()
    svc_profile = profile.model_copy(
        update={"username": login, "api_key": SecretStr(api_key), "password": None}
    )
    config = MintConfig(
        profile=svc_profile,
        module_secret=SecretStr(secret),
        **({"ttl_days": int(ttl_raw)} if ttl_raw.isdigit() and int(ttl_raw) > 0 else {}),
    )
    return MintingKeyProvider(config)
