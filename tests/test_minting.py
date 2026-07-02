# Copyright (c) 2026 Vincent Mucchielli
# SPDX-License-Identifier: BUSL-1.1
"""Per-user key minting via the bootstrap module (ADR-C008/C009): cache, rotation, gating."""

from __future__ import annotations

from typing import Any

import pytest
from odoo_mcp_guard.config import ProfileConfig
from odoo_mcp_guard.odoo.api import OdooClient
from pydantic import SecretStr

from _fixtures import FakeClient, make_profile_config
from odoo_mcp_gateway.minting import (
    MintConfig,
    MintError,
    MintingKeyProvider,
    is_secure_mint_url,
    make_key_provider,
)


class _Clock:
    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


class _MintClient(FakeClient):
    """FakeClient (full OdooClient protocol) whose ``call`` drives the bootstrap module."""

    def __init__(self, keys: list[str] | None = None) -> None:
        super().__init__()
        self._keys = keys if keys is not None else ["key-1", "key-2", "key-3"]
        self._i = 0
        self.connects = 0
        self.revoke_result: Any = True
        self.meta_result: Any = [{"id": 5, "name": "mcp-guard", "scope": "rpc"}]

    async def connect(self) -> None:
        self.connects += 1

    async def call(
        self,
        model: str,
        method: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> Any:
        self.mutations.append(("call", model, (method, args, kwargs)))
        if method == "mint_user_apikey":
            key = self._keys[min(self._i, len(self._keys) - 1)]
            self._i += 1
            return key
        if method == "revoke_user_apikey":
            return self.revoke_result
        if method == "list_user_apikey_meta":
            return self.meta_result
        return None

    def calls(self, method: str) -> list[tuple[str, list[Any] | None, dict[str, Any] | None]]:
        return [m[2] for m in self.mutations if m[0] == "call" and m[2][0] == method]


def _provider(
    client: _MintClient, *, clock: _Clock | None = None, **cfg: Any
) -> MintingKeyProvider:
    config = MintConfig(
        profile=make_profile_config("svc"), module_secret=SecretStr("S3CR3T"), **cfg
    )

    async def factory(profile: ProfileConfig) -> OdooClient:
        await client.connect()  # connect_client returns an already-connected client
        return client

    return MintingKeyProvider(
        config, client_factory=factory, clock=clock or (lambda: 0.0)
    )


def _verify_token(token: str, secret: str, uid: int, method: str) -> bool:
    """Mirror of the module's verifier — proves the gateway emits a valid S3 auth token."""
    import hashlib
    import hmac

    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        return False
    _v, ts, nonce, mac = parts
    message = f"{ts}.{nonce}.{int(uid)}.{method}"
    want = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, want)


async def test_mints_on_first_use_with_token_and_ttl() -> None:
    c = _MintClient()
    provider = _provider(c, ttl_days=14)
    key = await provider.get_key(42)
    assert key.get_secret_value() == "key-1"
    method, args, kwargs = c.calls("mint_user_apikey")[0]
    assert method == "mint_user_apikey"
    assert args == []  # everything passed by NAME (positional args 401 on json/2 / Odoo 19)
    assert kwargs["target_uid"] == 42
    assert kwargs["ttl_days"] == 14
    # S3: the raw secret never rides the wire — a per-call, uid+method-bound token does.
    assert "S3CR3T" not in kwargs["module_secret"]
    assert _verify_token(kwargs["module_secret"], "S3CR3T", 42, "mint_user_apikey")


async def test_token_is_bound_to_uid_and_method() -> None:
    c = _MintClient()
    provider = _provider(c)
    await provider.get_key(42)
    token = c.calls("mint_user_apikey")[0][2]["module_secret"]
    # The token must NOT verify for a different uid or a different method.
    assert not _verify_token(token, "S3CR3T", 99, "mint_user_apikey")
    assert not _verify_token(token, "S3CR3T", 42, "revoke_user_apikey")


async def test_caches_within_ttl_and_reuses_one_connection() -> None:
    c = _MintClient()
    clk = _Clock()
    provider = _provider(c, clock=clk, ttl_days=30)
    k1 = await provider.get_key(42)
    clk.t += 60  # well within the TTL
    k2 = await provider.get_key(42)
    assert k1.get_secret_value() == k2.get_secret_value() == "key-1"
    assert len(c.calls("mint_user_apikey")) == 1
    assert c.connects == 1  # the service-principal connection is opened once and reused


async def test_remints_before_expiry_window() -> None:
    c = _MintClient()
    clk = _Clock()
    provider = _provider(c, clock=clk, ttl_days=1, rotate_margin_seconds=0.0)
    assert (await provider.get_key(42)).get_secret_value() == "key-1"
    clk.t += 86400.0 + 1  # past the TTL
    assert (await provider.get_key(42)).get_secret_value() == "key-2"


async def test_rotate_margin_remints_early() -> None:
    c = _MintClient()
    clk = _Clock()
    # ttl 2 days, margin 2 days -> effective lifetime 0 -> always re-mint
    provider = _provider(c, clock=clk, ttl_days=2, rotate_margin_seconds=2 * 86400.0)
    await provider.get_key(42)
    clk.t += 1
    await provider.get_key(42)
    assert len(c.calls("mint_user_apikey")) == 2


async def test_distinct_users_get_distinct_keys() -> None:
    c = _MintClient()
    provider = _provider(c)
    k_a = await provider.get_key(1)
    k_b = await provider.get_key(2)
    assert k_a.get_secret_value() != k_b.get_secret_value()
    assert len(c.calls("mint_user_apikey")) == 2


async def test_forget_forces_remint() -> None:
    c = _MintClient()
    provider = _provider(c)
    await provider.get_key(42)
    provider.forget(42)
    await provider.get_key(42)
    assert len(c.calls("mint_user_apikey")) == 2


async def test_mint_error_when_module_returns_no_key() -> None:
    provider = _provider(_MintClient(keys=[""]))
    with pytest.raises(MintError):
        await provider.get_key(42)


async def test_revoke_and_list_pass_uid_and_bound_token() -> None:
    c = _MintClient()
    provider = _provider(c)
    assert await provider.revoke(42, 5) is True
    assert await provider.list_meta(42) == [{"id": 5, "name": "mcp-guard", "scope": "rpc"}]
    revoke_kwargs = c.calls("revoke_user_apikey")[0][2]
    assert revoke_kwargs["target_uid"] == 42
    assert revoke_kwargs["key_id"] == 5
    assert _verify_token(revoke_kwargs["module_secret"], "S3CR3T", 42, "revoke_user_apikey")
    list_kwargs = c.calls("list_user_apikey_meta")[0][2]
    assert list_kwargs["target_uid"] == 42
    assert _verify_token(list_kwargs["module_secret"], "S3CR3T", 42, "list_user_apikey_meta")


# -- make_key_provider: the core's impersonation-minting seam, built from env -----------


def test_make_key_provider_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ODOO_GUARD_GATEWAY_MINT", raising=False)
    assert make_key_provider(make_profile_config()) is None


def test_make_key_provider_disabled_when_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT", "1")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_SERVICE_LOGIN", "svc@x.com")
    monkeypatch.delenv("ODOO_GUARD_GATEWAY_MINT_SERVICE_API_KEY", raising=False)
    monkeypatch.delenv("ODOO_GUARD_GATEWAY_MINT_MODULE_SECRET", raising=False)
    assert make_key_provider(make_profile_config()) is None  # missing key/secret -> stays off


@pytest.mark.parametrize(
    ("url", "secure"),
    [
        ("https://odoo.example.com", True),
        ("https://odoo.example.com/", True),
        ("http://localhost:8069", True),
        ("http://127.0.0.1:8069", True),
        ("http://[::1]:8069", True),
        ("http://odoo.example.com", False),  # plaintext to a remote host — leaks the secret
        ("http://192.168.1.20:8069", False),
    ],
)
def test_is_secure_mint_url(url: str, secure: bool) -> None:
    assert is_secure_mint_url(url) is secure


def _configure_mint_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT", "1")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_SERVICE_LOGIN", "svc@x.com")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_SERVICE_API_KEY", "svc-key-123")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_MODULE_SECRET", "the-module-secret")


def test_make_key_provider_refuses_plaintext_remote_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_mint_env(monkeypatch)
    profile = make_profile_config()
    insecure = profile.model_copy(update={"url": "http://odoo.example.com"})
    assert make_key_provider(insecure) is None  # S2: never mint over plaintext to a remote host


def test_make_key_provider_allows_loopback_http_for_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_mint_env(monkeypatch)
    profile = make_profile_config()
    local = profile.model_copy(update={"url": "http://localhost:8069"})
    assert isinstance(make_key_provider(local), MintingKeyProvider)


def test_make_key_provider_builds_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT", "1")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_SERVICE_LOGIN", "svc@x.com")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_SERVICE_API_KEY", "svc-key-123")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_MODULE_SECRET", "the-module-secret")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MINT_TTL_DAYS", "14")
    provider = make_key_provider(make_profile_config())
    assert isinstance(provider, MintingKeyProvider)
    # the dedicated service account reuses the tenant URL/db but its OWN login + key
    assert provider._config.profile.username == "svc@x.com"
    assert provider._config.profile.api_key is not None
    assert provider._config.ttl_days == 14
    assert provider._config.module_secret.get_secret_value() == "the-module-secret"
