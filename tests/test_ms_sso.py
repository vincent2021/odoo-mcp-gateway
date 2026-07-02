# Copyright (c) 2026 Vincent Mucchielli
# SPDX-License-Identifier: BUSL-1.1
"""Microsoft SSO login (ADR-018): button, relay flow, signed state, pool dispatch."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from odoo_mcp_guard.config import ProfileConfig
from odoo_mcp_guard.errors import OdooAuthError
from odoo_mcp_guard.odoo.api import OdooClient
from odoo_mcp_guard.server.gateway import users as users_mod
from odoo_mcp_guard.server.gateway.auth import GatewayAuthApp
from odoo_mcp_guard.server.gateway.users import UserClientPool
from odoo_mcp_guard.server.gateway.vault import InMemoryVault
from odoo_mcp_guard.server.identity import UserIdentity

from _fixtures import (
    FakeClient,
    make_base,
    make_config,
    make_profile_config,
    make_session,
    obtain_code,
    obtain_tokens,
    pkce_pair,
    register,
    stub_validator,
)
from odoo_mcp_gateway import microsoft as ms_mod
from odoo_mcp_gateway.microsoft import (
    MicrosoftLoginProvider,
    MicrosoftSso,
    OAuthProviderInfo,
    _parse_login_providers,
    make_microsoft_sso,
)

MS_TOKEN_SENTINEL = "ms-access-t0ken-SENTINEL"
SESSION_COOKIE_SENTINEL = "odoo-session-c00kie-SENTINEL"
MS_BUTTON = "Se connecter avec Microsoft"

PROVIDER = OAuthProviderInfo(
    auth_endpoint="https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize",
    client_id="azure-app-client-id-123",
    provider_id=4,
    db="prod-db",
    scope="openid profile email",
)


async def stub_discover() -> OAuthProviderInfo | None:
    return PROVIDER


async def stub_discover_none() -> OAuthProviderInfo | None:
    return None


async def stub_exchange(
    access_token: str, provider: OAuthProviderInfo
) -> tuple[str, UserIdentity] | None:
    if access_token == MS_TOKEN_SENTINEL and provider is PROVIDER:
        identity = UserIdentity(login="sso@x.com", uid=42, display_name="SSO User")
        return SESSION_COOKIE_SENTINEL, identity
    return None


def make_sso_app(
    vault: InMemoryVault,
    *,
    discover: Any = stub_discover,
    exchange: Any = stub_exchange,
) -> GatewayAuthApp:
    return GatewayAuthApp(
        make_config(),
        vault,
        stub_validator,
        odoo_url="https://odoo.example.com",
        odoo_db="prod-db",
        providers=[MicrosoftLoginProvider(MicrosoftSso(discover=discover, exchange=exchange))],
    )


@pytest.fixture
def vault() -> InMemoryVault:
    return InMemoryVault()


@pytest.fixture
async def client(vault: InMemoryVault) -> Any:
    transport = httpx.ASGITransport(app=make_sso_app(vault))
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
        yield http


def authorize_params(client_id: str, challenge: str) -> dict[str, str]:
    return {
        "client_id": client_id,
        "redirect_uri": "http://127.0.0.1:49152/callback",
        "response_type": "code",
        "state": "xyz-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


async def start_ms_login(
    client: httpx.AsyncClient, client_id: str, challenge: str
) -> tuple[str, dict[str, list[str]]]:
    """GET /oauth/microsoft/start; return (signed state, microsoft query)."""
    response = await client.get(
        "/oauth/microsoft/start", params=authorize_params(client_id, challenge)
    )
    assert response.status_code == 302
    location = response.headers["location"]
    query = parse_qs(urlsplit(location).query)
    return query["state"][0], query


async def complete_ms_login(
    client: httpx.AsyncClient, state: str, token: str = MS_TOKEN_SENTINEL
) -> httpx.Response:
    return await client.post(
        "/oauth/microsoft/complete", data={"access_token": token, "state": state}
    )


def interstitial_target(html_body: str) -> str:
    """Extract the navigation URL from the SSO meta-refresh interstitial.

    The SSO path returns ``content="0;url=<escaped redirect_uri?code=...>"``
    (a top-level navigation, not a form-action-blocked 302).
    """
    import html as _html
    import re

    match = re.search(r'content="0;url=([^"]+)"', html_body)
    assert match, f"no meta-refresh url in interstitial: {html_body!r}"
    return _html.unescape(match.group(1))


# -- button visibility -----------------------------------------------------------


async def test_button_appears_iff_provider_discovered(vault: InMemoryVault) -> None:
    for discover, expected in ((stub_discover, True), (stub_discover_none, False)):
        app = make_sso_app(vault, discover=discover)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
            client_id = await register(http)
            page = await http.get("/authorize", params=authorize_params(client_id, pkce_pair()[1]))
            assert page.status_code == 200
            assert (MS_BUTTON in page.text) is expected
            assert ("/oauth/microsoft/start" in page.text) is expected


async def test_no_sso_configured_keeps_legacy_behavior(vault: InMemoryVault) -> None:
    app = GatewayAuthApp(make_config(), vault, stub_validator)  # no providers
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
        client_id = await register(http)
        page = await http.get("/authorize", params=authorize_params(client_id, pkce_pair()[1]))
        assert MS_BUTTON not in page.text
        start = await http.get(
            "/oauth/microsoft/start", params=authorize_params(client_id, pkce_pair()[1])
        )
        assert start.status_code == 404


# -- /start redirect shape ---------------------------------------------------------


async def test_start_redirects_to_microsoft_with_exact_params(
    client: httpx.AsyncClient,
) -> None:
    client_id = await register(client)
    response = await client.get(
        "/oauth/microsoft/start", params=authorize_params(client_id, pkce_pair()[1])
    )
    assert response.status_code == 302
    location = response.headers["location"]
    parts = urlsplit(location)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == PROVIDER.auth_endpoint
    query = parse_qs(parts.query)
    assert query["client_id"] == [PROVIDER.client_id]  # Odoo's own Azure app
    assert query["response_type"] == ["token"]
    assert query["redirect_uri"] == ["http://gateway/oauth/microsoft/callback"]
    assert query["scope"] == [PROVIDER.scope]
    state = query["state"][0]
    nonce, _, signature = state.partition(".")
    assert nonce and signature, "state must be HMAC-signed (nonce.sig)"
    assert state != "xyz-state"  # the MCP client's state is NOT forwarded raw


async def test_start_revalidates_authorize_params(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/oauth/microsoft/start",
        params=authorize_params("unknown-client", pkce_pair()[1]),
    )
    assert response.status_code == 400
    assert "location" not in response.headers


# -- callback relay page -----------------------------------------------------------


async def test_callback_page_relays_fragment_with_csp(client: httpx.AsyncClient) -> None:
    response = await client.get("/oauth/microsoft/callback")
    assert response.status_code == 200
    assert "location.hash" in response.text  # the fragment is read client-side
    assert "/oauth/microsoft/complete" in response.text  # relative = issuer origin
    assert 'method = "post"' in response.text
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'unsafe-inline'" in csp
    assert "form-action 'self'" in csp
    assert response.headers["cache-control"] == "no-store"


# -- full flow ----------------------------------------------------------------------


async def test_full_sso_flow_yields_odoo_session(
    client: httpx.AsyncClient, vault: InMemoryVault, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    client_id = await register(client)
    verifier, challenge = pkce_pair()

    state, _ = await start_ms_login(client, client_id, challenge)
    finish = await complete_ms_login(client, state)
    # SSO completes via a meta-refresh interstitial (200), not a 302: the
    # callback page's `form-action 'self'` CSP would block a cross-origin
    # redirect, hanging the browser on "Connexion en cours".
    assert finish.status_code == 200
    redirect = urlsplit(interstitial_target(finish.text))
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == (
        "http://127.0.0.1:49152/callback"
    )
    query = parse_qs(redirect.query)
    assert query["state"] == ["xyz-state"]  # the MCP client's own state, restored
    code = query["code"][0]

    tokens = await obtain_tokens(client, client_id, code, verifier)
    session = vault.get(tokens["access_token"])
    assert session is not None
    assert session.auth_method == "odoo_session"
    assert session.credential.get_secret_value() == SESSION_COOKIE_SENTINEL
    assert session.identity == UserIdentity(login="sso@x.com", uid=42, display_name="SSO User")

    # Rule 1 #7: neither the Microsoft token nor the session cookie in any log.
    for record in caplog.records:
        line = record.getMessage()
        assert MS_TOKEN_SENTINEL not in line
        assert SESSION_COOKIE_SENTINEL not in line




async def test_sso_complete_uses_metarefresh_not_blocked_302(
    client: httpx.AsyncClient,
) -> None:
    """Regression: the SSO complete must NOT emit a cross-origin 302 (blocked by
    the callback page's `form-action 'self'` CSP). It returns a 200 meta-refresh
    interstitial that navigates to the client redirect_uri instead."""
    client_id = await register(client)
    state, _ = await start_ms_login(client, client_id, pkce_pair()[1])
    finish = await complete_ms_login(client, state)
    assert finish.status_code == 200
    assert "location" not in finish.headers  # no redirect header to be blocked
    assert 'http-equiv="refresh"' in finish.text
    target = interstitial_target(finish.text)
    assert target.startswith("http://127.0.0.1:49152/callback?")
    assert "code=" in target


async def test_protected_resource_metadata_rfc9728(client: httpx.AsyncClient) -> None:
    """RFC 9728: the protected-resource endpoint lets MCP clients discover the
    authorization server from the /mcp endpoint."""
    from odoo_mcp_guard.server.gateway.auth import AUTH_PATHS

    assert "/.well-known/oauth-protected-resource" in AUTH_PATHS
    response = await client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    body = response.json()
    assert body["resource"].endswith("/mcp")
    assert body["authorization_servers"]  # non-empty list of AS issuers
    assert response.headers["cache-control"] == "no-store"


async def test_password_path_unchanged_by_sso(
    client: httpx.AsyncClient, vault: InMemoryVault
) -> None:
    client_id = await register(client)
    verifier, challenge = pkce_pair()
    code = await obtain_code(client, client_id, challenge)
    tokens = await obtain_tokens(client, client_id, code, verifier)
    session = vault.get(tokens["access_token"])
    assert session is not None and session.auth_method == "password"


# -- signed state: tamper / expiry / replay ------------------------------------------


async def test_tampered_state_rejected(client: httpx.AsyncClient) -> None:
    client_id = await register(client)
    state, _ = await start_ms_login(client, client_id, pkce_pair()[1])
    nonce, _, signature = state.partition(".")
    tampered = f"{nonce}.{'0' * len(signature)}"
    response = await complete_ms_login(client, tampered)
    assert response.status_code == 400
    assert "Connexion Microsoft refusée" in response.text
    # The probe burned the pending entry: the genuine state is dead too.
    retry = await complete_ms_login(client, state)
    assert retry.status_code == 400


async def test_expired_state_rejected(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    client_id = await register(client)
    monkeypatch.setattr(ms_mod, "MS_STATE_TTL_SECONDS", -1.0)
    state, _ = await start_ms_login(client, client_id, pkce_pair()[1])
    response = await complete_ms_login(client, state)
    assert response.status_code == 400


async def test_replayed_state_rejected(client: httpx.AsyncClient) -> None:
    client_id = await register(client)
    state, _ = await start_ms_login(client, client_id, pkce_pair()[1])
    assert (await complete_ms_login(client, state)).status_code == 200  # meta-refresh
    replay = await complete_ms_login(client, state)
    assert replay.status_code == 400
    assert "Connexion Microsoft refusée" in replay.text


async def test_unknown_state_rejected(client: httpx.AsyncClient) -> None:
    response = await complete_ms_login(client, "bogus.deadbeef")
    assert response.status_code == 400


# -- exchange failure: neutral, token never echoed -------------------------------------


async def test_exchange_failure_is_neutral_and_never_echoes_token(
    vault: InMemoryVault, caplog: pytest.LogCaptureFixture
) -> None:
    async def failing_exchange(
        access_token: str, provider: OAuthProviderInfo
    ) -> tuple[str, UserIdentity] | None:
        return None

    caplog.set_level(logging.DEBUG)
    app = make_sso_app(vault, exchange=failing_exchange)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
        client_id = await register(http)
        state, _ = await start_ms_login(http, client_id, pkce_pair()[1])
        response = await complete_ms_login(http, state)
    assert response.status_code == 401
    assert "Connexion Microsoft refusée" in response.text
    assert MS_TOKEN_SENTINEL not in response.text
    assert "location" not in response.headers
    for record in caplog.records:
        assert MS_TOKEN_SENTINEL not in record.getMessage()


async def test_exchange_exception_fails_closed(vault: InMemoryVault) -> None:
    async def exploding_exchange(
        access_token: str, provider: OAuthProviderInfo
    ) -> tuple[str, UserIdentity] | None:
        raise RuntimeError(f"boom {access_token}")  # must never reach the browser

    app = make_sso_app(vault, exchange=exploding_exchange)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
        client_id = await register(http)
        state, _ = await start_ms_login(http, client_id, pkce_pair()[1])
        response = await complete_ms_login(http, state)
    assert response.status_code == 401
    assert MS_TOKEN_SENTINEL not in response.text
    assert "boom" not in response.text


# -- AUTH_PATHS routing (host-allowlist coverage extends to the new endpoints) ---------


def test_sso_endpoints_are_auth_paths(vault: InMemoryVault) -> None:
    # The provider's routes contribute to the app's ACTUAL auth-path set, which
    # the dispatcher/host-allowlist use (not the static core AUTH_PATHS tuple).
    from odoo_mcp_guard.server.gateway.auth import AUTH_PATHS

    app = make_sso_app(vault)
    assert "/oauth/microsoft/start" in app.auth_paths
    assert "/oauth/microsoft/callback" in app.auth_paths
    assert "/oauth/microsoft/complete" in app.auth_paths
    # The MS paths are NOT in the static core tuple: they come from the provider.
    assert "/oauth/microsoft/start" not in AUTH_PATHS


async def test_host_allowlist_applies_to_sso_endpoints(vault: InMemoryVault) -> None:
    app = GatewayAuthApp(
        make_config(),
        vault,
        stub_validator,
        providers=[
            MicrosoftLoginProvider(MicrosoftSso(discover=stub_discover, exchange=stub_exchange))
        ],
        allowed_hosts=frozenset({"gateway"}),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as http:
        ok = await http.get("/oauth/microsoft/callback")
        assert ok.status_code == 200
        rebound = await http.get("/oauth/microsoft/callback", headers={"Host": "evil.example"})
        assert rebound.status_code == 421


# -- provider discovery: parser + env overrides ----------------------------------------


_MS_HREF = (
    "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize"
    "?response_type=token&amp;client_id=azure-app-client-id-123"
    "&amp;redirect_uri=https%3A%2F%2Fodoo.pramex.com%2Fauth_oauth%2Fsignin"
    "&amp;scope=openid+profile+email"
    "&amp;state=%7B%22d%22%3A+%22prod-db%22%2C+%22p%22%3A+4%2C+%22r%22%3A+%22%252Fweb%22%7D"
)

ODOO_LOGIN_HTML = f"""
<form action="/web/login" method="post"><input name="login"></form>
<a href="{_MS_HREF}" class="btn">
  Se connecter avec Microsoft</a>
<a href="/web/signup">Sign up</a>
"""


def test_parse_login_providers_extracts_microsoft_provider() -> None:
    provider = _parse_login_providers(ODOO_LOGIN_HTML, default_db="fallback-db")
    assert provider is not None
    assert provider.auth_endpoint == (
        "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize"
    )
    assert provider.client_id == "azure-app-client-id-123"
    assert provider.provider_id == 4
    assert provider.db == "prod-db"
    assert provider.scope == "openid profile email"


def test_parse_login_providers_none_when_absent() -> None:
    assert _parse_login_providers("<html><body>plain login</body></html>", "db") is None


async def test_env_overrides_bypass_login_page_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ODOO_GUARD_GATEWAY_MS_AUTH_URL", "https://login.microsoftonline.com/t/authorize"
    )
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MS_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("ODOO_GUARD_GATEWAY_MS_PROVIDER_ID", "9")
    sso = make_microsoft_sso(make_profile_config())  # no HTTP call must be needed
    provider = await sso.discover()
    assert provider == OAuthProviderInfo(
        auth_endpoint="https://login.microsoftonline.com/t/authorize",
        client_id="env-client-id",
        provider_id=9,
        db="testdb",
    )


async def test_exchange_captures_rotated_session_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live-bug regression: Odoo rotates session_id between the signin 303 and
    get_session_info. The exchange must return the LIVE (rotated) cookie, not
    the stale one from the 303 (which dies within seconds)."""
    from odoo_mcp_guard.odoo import transport as transport_mod

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth_oauth/signin":
            return httpx.Response(
                303,
                headers={
                    "location": "https://odoo.example.com/web",
                    "set-cookie": "session_id=stale-signin-cookie; Path=/",
                },
            )
        assert request.url.path == "/web/session/get_session_info"
        return httpx.Response(
            200,
            headers={"set-cookie": "session_id=live-rotated-cookie; Path=/"},
            json={
                "jsonrpc": "2.0",
                "result": {"uid": 42, "username": "sso@x.com", "name": "SSO User"},
            },
        )

    monkeypatch.setattr(
        transport_mod,
        "make_http_client",
        lambda *a, **k: httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    sso = make_microsoft_sso(make_profile_config())
    result = await sso.exchange(MS_TOKEN_SENTINEL, PROVIDER)
    assert result is not None
    cookie, identity = result
    assert cookie == "live-rotated-cookie"  # NOT the stale signin-303 cookie
    assert identity.uid == 42


# -- pool dispatch: odoo_session builds a session client --------------------------------


class _ExpiringFakeClient(FakeClient):
    """search_read raises an auth error once the session is marked expired."""

    def __init__(self, label: str = "session") -> None:
        super().__init__(label)
        self.expired = False

    async def search_read(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        if self.expired:
            raise OdooAuthError("Odoo web session expired; please log in again.")
        return await super().search_read(*args, **kwargs)


@pytest.fixture
def session_clients(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, str, _ExpiringFakeClient]]:
    """Stub the (real, concurrent-agent-owned) make_session_client helper."""
    built: list[tuple[Any, str, _ExpiringFakeClient]] = []

    def fake_maker(profile: ProfileConfig, cookie: str, **kwargs: Any) -> OdooClient:
        client = _ExpiringFakeClient(label=f"session:{profile.name}")
        built.append((profile, cookie, client))
        return client

    monkeypatch.setattr(users_mod, "make_session_client", fake_maker)
    return built


def test_real_session_client_helper_importable() -> None:
    """The pool codes against the concurrent agent's helper: keep it honest."""
    from odoo_mcp_guard.odoo.detect import make_session_client as real_helper

    assert callable(real_helper)


async def test_pool_builds_session_client_for_odoo_session(
    tmp_path: Path,
    session_clients: list[tuple[Any, str, _ExpiringFakeClient]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def never_connect(profile: ProfileConfig) -> OdooClient:
        raise AssertionError("odoo_session must not go through connect_client")

    monkeypatch.setattr(users_mod, "connect_client", never_connect)
    base = make_base(tmp_path)
    pool = UserClientPool()
    session = make_session(
        uid=42,
        login="sso@x.com",
        credential=SESSION_COOKIE_SENTINEL,
        auth_method="odoo_session",
    )
    runtime = await pool.get(make_profile_config(), base, session)
    assert len(session_clients) == 1
    profile, cookie, _client = session_clients[0]
    assert cookie == SESSION_COOKIE_SENTINEL  # the vaulted cookie, nothing else
    assert profile.name == "default"
    rows = await runtime.client.search_read("res.partner", [])
    assert rows  # calls flow through to the underlying session client
    assert SESSION_COOKIE_SENTINEL not in repr(runtime.client)


async def test_expired_session_evicts_pool_entry(
    tmp_path: Path, session_clients: list[tuple[Any, str, _ExpiringFakeClient]]
) -> None:
    base = make_base(tmp_path)
    pool = UserClientPool()
    cfg = make_profile_config()
    session = make_session(
        uid=42, login="sso@x.com", credential="cookie-1", auth_method="odoo_session"
    )
    runtime = await pool.get(cfg, base, session)
    _, _, inner = session_clients[0]
    inner.expired = True

    with pytest.raises(OdooAuthError):  # the structured error still propagates
        await runtime.client.search_read("res.partner", [])
    assert inner.closed is True  # evicted entry's client is closed

    # Next login (fresh cookie) gets a FRESH client, not the poisoned entry.
    again = await pool.get(cfg, base, session)
    assert again is not runtime
    assert len(session_clients) == 2
