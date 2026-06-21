# Copyright (c) 2026 Vincent Mucchielli
# SPDX-License-Identifier: BUSL-1.1
"""Microsoft SSO login provider (ADR-018).

Pluggable :class:`~odoo_mcp_guard.server.gateway.auth.LoginProvider` for the
gateway: a "Se connecter avec Microsoft" button, the fragment-relay callback
flow, an HMAC-signed single-use relay state, and the discovery/exchange against
Odoo's own ``auth_oauth`` web flow. The OAuth+password core in
:mod:`odoo_mcp_guard.server.gateway.auth` stays generic and never imports this
module; this module calls back into the public
:class:`~odoo_mcp_guard.server.gateway.auth.GatewayAuthApp` surface to resume
the parked
PKCE flow once it has proven an identity.

Security posture (Rule 1): the Microsoft token never reaches a log line or an
error body; every SSO failure (tamper, expiry, replay, unknown state, exchange
error) returns one neutral message. The relay state is HMAC-signed with a
per-process secret that never touches disk.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit

import httpx
from odoo_mcp_guard.config import ProfileConfig
from odoo_mcp_guard.errors import OdooMcpGuardError
from odoo_mcp_guard.odoo import transport
from odoo_mcp_guard.server.gateway.auth import (
    _AUTHORIZE_PARAM_NAMES,
    _RATE_LIMIT_ERROR,
    LoginButton,
    LoginProvider,
    _error_page,
)
from odoo_mcp_guard.server.identity import UserIdentity, UserSession
from pydantic import SecretStr
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

if TYPE_CHECKING:
    from odoo_mcp_guard.server.gateway.auth import GatewayAuthApp

logger = logging.getLogger(__name__)

#: Microsoft-SSO relay state: single-use, HMAC-signed (confirm.py house
#: style), short-lived — the Microsoft round trip takes seconds, not minutes.
MS_STATE_TTL_SECONDS = 300.0

#: One neutral SSO failure message: never the Microsoft token, never the
#: Odoo response, never a hint distinguishing the failure modes (Rule 1 #7).
_MS_NEUTRAL_ERROR = "Connexion Microsoft refusée."
#: CSP for the fragment-relay page: inline script only, POST to us only.
_MS_CALLBACK_CSP = "default-src 'none'; script-src 'unsafe-inline'; form-action 'self'"


@dataclass(frozen=True)
class OAuthProviderInfo:
    """One Odoo `auth_oauth` provider, as discovered from the login page.

    These are the exact values Odoo itself sends to Microsoft: same Azure AD
    app (``client_id``), same authorize endpoint — only the ``redirect_uri``
    differs (ours), which the Azure admin must have added to the AD app.
    """

    auth_endpoint: str
    client_id: str
    provider_id: int
    db: str
    scope: str = ""


#: Lazy provider discovery (None = no SSO button). Injectable for tests.
DiscoverSsoProvider = Callable[[], Awaitable["OAuthProviderInfo | None"]]

#: Exchange a Microsoft access token for an Odoo web session: returns the
#: ``session_id`` cookie value + the proven identity, or ``None`` on ANY
#: failure (indistinguishable by design, like ValidateCredential).
ExchangeSsoToken = Callable[
    [str, "OAuthProviderInfo"], Awaitable["tuple[str, UserIdentity] | None"]
]


@dataclass(frozen=True)
class MicrosoftSso:
    """The two injectable callables that make up the SSO integration."""

    discover: DiscoverSsoProvider
    exchange: ExchangeSsoToken


@dataclass
class _PendingMsLogin:
    """A pending /authorize request parked while the browser visits Microsoft."""

    params: dict[str, str]
    expires_at: float


class MicrosoftLoginProvider:
    """Microsoft SSO as a :class:`~odoo_mcp_guard.server.gateway.auth.LoginProvider`.

    Holds the per-instance SSO state (the injectable callables, the lazy
    provider-discovery cache, the per-process relay-state secret, and the
    pending-login store) that used to live directly on ``GatewayAuthApp``.
    """

    def __init__(self, sso: MicrosoftSso) -> None:
        self._sso = sso
        self._app: GatewayAuthApp | None = None
        self._provider_cache: OAuthProviderInfo | None = None
        self._provider_probed = False
        self._provider_lock = asyncio.Lock()
        #: Per-process random secret signing the SSO relay state (never on disk).
        self._state_secret = secrets.token_bytes(32)
        self._pending: dict[str, _PendingMsLogin] = {}

    # -- LoginProvider protocol ----------------------------------------------

    def bind(self, app: GatewayAuthApp) -> None:
        self._app = app

    async def login_button(self, params: dict[str, str]) -> LoginButton | None:
        """Return the Microsoft button iff a provider is discovered."""
        if await self._provider() is None:
            return None
        return LoginButton("Se connecter avec Microsoft", self._login_url(params))

    def routes(self) -> list[Route]:
        return [
            Route("/oauth/microsoft/start", self._start, methods=["GET"]),
            Route("/oauth/microsoft/callback", self._callback, methods=["GET"]),
            Route("/oauth/microsoft/complete", self._complete, methods=["POST"]),
        ]

    # -- bound-app accessors -------------------------------------------------

    @property
    def _bound(self) -> GatewayAuthApp:
        assert self._app is not None, "MicrosoftLoginProvider used before bind()"
        return self._app

    def _login_url(self, params: dict[str, str]) -> str:
        """The /oauth/microsoft/start link carrying the pending authorize params."""
        keep = {name: params[name] for name in _AUTHORIZE_PARAM_NAMES if params.get(name)}
        return f"/oauth/microsoft/start?{urlencode(keep)}"

    # -- provider discovery --------------------------------------------------

    async def _provider(self) -> OAuthProviderInfo | None:
        """Discover the Odoo `auth_oauth` provider, lazily, exactly once."""
        async with self._provider_lock:
            if not self._provider_probed:
                try:
                    self._provider_cache = await self._sso.discover()
                except Exception as exc:  # discovery is best-effort: no button
                    logger.warning("gateway: SSO provider discovery failed: %s", type(exc).__name__)
                    self._provider_cache = None
                self._provider_probed = True
        return self._provider_cache

    # -- signed relay state --------------------------------------------------

    def _sign_state(self, nonce: str, params: dict[str, str], expires_at: float) -> str:
        canonical = json.dumps(params, sort_keys=True)
        message = f"{canonical}|{nonce}|{expires_at:.0f}".encode()
        return hmac.new(self._state_secret, message, hashlib.sha256).hexdigest()[:32]

    def _issue_state(self, params: dict[str, str]) -> str:
        """Park the authorize request; return the signed state for Microsoft."""
        self._gc_pending()
        nonce = secrets.token_urlsafe(12)
        expires_at = time.monotonic() + MS_STATE_TTL_SECONDS
        self._pending[nonce] = _PendingMsLogin(params=params, expires_at=expires_at)
        return f"{nonce}.{self._sign_state(nonce, params, expires_at)}"

    def _redeem_state(self, state: str) -> dict[str, str] | None:
        """Validate and consume a relay state (single-use, TTL, HMAC).

        Tampered, expired, replayed and unknown states are all rejected the
        same way; a probe with a bad signature burns the pending entry.
        """
        self._gc_pending()
        nonce, _, signature = state.partition(".")
        entry = self._pending.pop(nonce, None)  # single use, burned on probe
        if entry is None:
            return None
        expected = self._sign_state(nonce, entry.params, entry.expires_at)
        if not hmac.compare_digest(signature.encode("utf-8"), expected.encode("ascii")):
            return None
        if time.monotonic() > entry.expires_at:
            return None
        return entry.params

    def _gc_pending(self) -> None:
        now = time.monotonic()
        for nonce in [n for n, e in self._pending.items() if now > e.expires_at]:
            del self._pending[nonce]

    # -- route handlers ------------------------------------------------------

    async def _start(self, request: Request) -> Response:
        """Redirect the browser to the SAME Microsoft authorize URL Odoo uses,
        with OUR callback as redirect_uri and a signed relay state."""
        provider = await self._provider()
        if provider is None:
            return HTMLResponse(
                _error_page("la connexion Microsoft n'est pas configurée"),
                status_code=404,
            )
        params = dict(request.query_params.items())
        problem = self._bound.check_authorize_params(params)
        if problem is not None:
            return HTMLResponse(_error_page(problem), status_code=400)
        issuer = self._bound.config.issuer_url.rstrip("/")
        query: dict[str, str] = {
            "client_id": provider.client_id,
            "response_type": "token",
            "redirect_uri": f"{issuer}/oauth/microsoft/callback",
            "state": self._issue_state(params),
        }
        if provider.scope:
            query["scope"] = provider.scope
        separator = "&" if "?" in provider.auth_endpoint else "?"
        return RedirectResponse(
            f"{provider.auth_endpoint}{separator}{urlencode(query)}",
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )

    async def _callback(self, request: Request) -> Response:
        """Serve the static fragment-relay page.

        Microsoft puts the access token in the URL FRAGMENT, which never
        reaches us; this self-contained page reads ``location.hash`` and
        form-POSTs token + state to ``/oauth/microsoft/complete`` (relative
        action + ``form-action 'self'`` CSP: the token can only ever travel
        to the issuer origin).
        """
        return HTMLResponse(
            _MS_CALLBACK_PAGE,
            headers={
                "Content-Security-Policy": _MS_CALLBACK_CSP,
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            },
        )

    async def _complete(self, request: Request) -> Response:
        """Exchange the relayed Microsoft token for an Odoo web session and
        resume the parked PKCE authorization."""
        client_ip = request.client.host if request.client else "unknown"
        if not self._bound.allow_login_attempt(client_ip):
            return HTMLResponse(_error_page(_RATE_LIMIT_ERROR), status_code=429)
        form = await request.form()
        access_token = str(form.get("access_token") or "")
        state = str(form.get("state") or "")
        params = self._redeem_state(state)
        provider = await self._provider()
        # Re-validate the parked params: never trust a stale snapshot.
        if (
            provider is None
            or params is None
            or not access_token
            or self._bound.check_authorize_params(params) is not None
        ):
            return HTMLResponse(_error_page(_MS_NEUTRAL_ERROR), status_code=400)
        result: tuple[str, UserIdentity] | None = None
        try:
            result = await self._sso.exchange(access_token, provider)
        except Exception as exc:  # fail closed, leak nothing (Rule 1 #7/#8)
            logger.warning("gateway: SSO token exchange errored: %s", type(exc).__name__)
            result = None
        if result is None:
            return HTMLResponse(_error_page(_MS_NEUTRAL_ERROR), status_code=401)
        session_cookie, identity = result
        session = UserSession(
            identity=identity,
            credential=SecretStr(session_cookie),
            auth_method="odoo_session",
        )
        return self._bound.finish_login(params, session, html_redirect=True)


# -- Login-page assertion: the provider satisfies the LoginProvider protocol ----

_: type[LoginProvider] = MicrosoftLoginProvider


#: Fragment-relay page (ADR-018). Deliberately unstyled: the CSP is
#: ``default-src 'none'`` (no styles, no images, no fetch) plus inline script
#: and ``form-action 'self'`` only. The token is scrubbed from the address
#: bar before the POST and is never echoed back by the server.
_MS_CALLBACK_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>Connexion Microsoft — odoo-mcp-guard</title></head>
<body>
<noscript>JavaScript est requis pour terminer la connexion Microsoft.</noscript>
<p id="msg">Connexion en cours&hellip;</p>
<script>
(function () {
  "use strict";
  var fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  var token = fragment.get("access_token") || "";
  var state = fragment.get("state") || "";
  try { history.replaceState(null, "", window.location.pathname); } catch (e) {}
  if (!token || !state) {
    document.getElementById("msg").textContent = "Connexion Microsoft refusée.";
    return;
  }
  var form = document.createElement("form");
  form.method = "post";
  form.action = "/oauth/microsoft/complete";
  [["access_token", token], ["state", state]].forEach(function (pair) {
    var field = document.createElement("input");
    field.type = "hidden";
    field.name = pair[0];
    field.value = pair[1];
    form.appendChild(field);
  });
  document.body.appendChild(form);
  form.submit();
})();
</script>
</body>
</html>
"""


# -- Real Microsoft SSO discovery + exchange against Odoo (ADR-018) -------------

_HREF_RE = re.compile(r'href="([^"]+)"')


def _parse_login_providers(page: str, default_db: str) -> OAuthProviderInfo | None:
    """Extract the `auth_oauth` provider Odoo's own login page links to.

    Odoo renders one ``<a href="{auth_endpoint}?response_type=token&client_id=
    ...&redirect_uri={odoo}/auth_oauth/signin&state={JSON}">`` per enabled
    provider; the state JSON carries the provider id (``p``) and db (``d``).
    Prefers a Microsoft endpoint when several providers are enabled.

    Example:
        >>> _parse_login_providers('<a href="https://login.microsoftonline.com/t/'
        ...     'oauth2/v2.0/authorize?client_id=abc&amp;response_type=token&amp;'
        ...     'redirect_uri=https%3A%2F%2Fx%2Fauth_oauth%2Fsignin&amp;'
        ...     'state=%7B%22p%22%3A+4%2C+%22d%22%3A+%22db%22%7D">x</a>',
        ...     "fallback").client_id
        'abc'
    """
    candidates: list[OAuthProviderInfo] = []
    for raw_href in _HREF_RE.findall(page):
        href = html.unescape(raw_href)
        parts = urlsplit(href)
        query = dict(parse_qsl(parts.query))
        if "client_id" not in query or "auth_oauth/signin" not in query.get("redirect_uri", ""):
            continue
        try:
            state: Any = json.loads(query.get("state", ""))
        except ValueError:
            state = {}
        if not isinstance(state, dict) or "p" not in state:
            continue
        try:
            provider_id = int(state["p"])
        except (TypeError, ValueError):
            continue
        candidates.append(
            OAuthProviderInfo(
                auth_endpoint=f"{parts.scheme}://{parts.netloc}{parts.path}",
                client_id=str(query["client_id"]),
                provider_id=provider_id,
                db=str(state.get("d") or default_db),
                scope=str(query.get("scope", "")),
            )
        )
    for candidate in candidates:
        if "microsoft" in candidate.auth_endpoint.lower():
            return candidate
    return candidates[0] if candidates else None


def make_microsoft_sso(profile: ProfileConfig) -> MicrosoftSso:
    """Build the production Microsoft-SSO callables for one profile.

    Discovery fetches ``{odoo}/web/login`` once (lazy + cached by the provider)
    and parses the provider button; env overrides
    ``ODOO_GUARD_GATEWAY_MS_AUTH_URL`` + ``_MS_CLIENT_ID`` + ``_MS_PROVIDER_ID``
    (and optional ``_MS_SCOPE``) bypass parsing for instances whose login page
    can't be parsed.

    The exchange replays Odoo's own browser flow — GET
    ``/auth_oauth/signin?access_token=...&state=...`` WITHOUT following the
    redirect, capturing the ``session_id`` cookie on the 303 to ``/web``,
    then resolving the identity via ``/web/session/get_session_info``. This
    is Odoo's web flow, not a documented API (fragility noted in ADR-018).

    Example:
        >>> # sso = make_microsoft_sso(profile)
    """

    async def discover() -> OAuthProviderInfo | None:
        env_url = os.environ.get("ODOO_GUARD_GATEWAY_MS_AUTH_URL", "").strip()
        env_client = os.environ.get("ODOO_GUARD_GATEWAY_MS_CLIENT_ID", "").strip()
        env_provider = os.environ.get("ODOO_GUARD_GATEWAY_MS_PROVIDER_ID", "").strip()
        if env_url and env_client and env_provider:
            return OAuthProviderInfo(
                auth_endpoint=env_url,
                client_id=env_client,
                provider_id=int(env_provider),
                db=profile.db,
                scope=os.environ.get("ODOO_GUARD_GATEWAY_MS_SCOPE", "").strip(),
            )
        http = transport.make_http_client(ca_bundle=profile.ca_bundle)
        try:
            response = await http.get(f"{profile.url}/web/login")
            if response.status_code != 200:
                return None
            return _parse_login_providers(response.text, profile.db)
        finally:
            await http.aclose()

    async def exchange(
        access_token: str, provider: OAuthProviderInfo
    ) -> tuple[str, UserIdentity] | None:
        http = transport.make_http_client(ca_bundle=profile.ca_bundle)
        try:
            # The same state JSON Odoo's own login page sends to Microsoft.
            state = json.dumps(
                {
                    "d": provider.db,
                    "p": provider.provider_id,
                    "r": quote_plus(f"{profile.url}/web"),
                }
            )
            signin = await http.get(
                f"{profile.url}/auth_oauth/signin",
                params={"access_token": access_token, "state": state},
                follow_redirects=False,
            )
            location = signin.headers.get("location", "")
            session_cookie = signin.cookies.get("session_id")
            if (
                signin.status_code not in (302, 303)
                or not session_cookie
                or "/web/login" in location  # Odoo bounced us back: oauth_error
                or "oauth_error" in location
            ):
                logger.info("gateway: Odoo rejected a Microsoft SSO sign-in.")
                return None
            info = await http.post(
                f"{profile.url}/web/session/get_session_info",
                json={"jsonrpc": "2.0", "method": "call", "params": {}},
                headers={"Cookie": f"session_id={session_cookie}"},
            )
            # Odoo rotates session_id on auth transitions: the live cookie is
            # whatever the jar holds after this authenticated call, not the
            # (now superseded) one captured from the signin 303. Returning the
            # stale one yields a session that validates for seconds then dies.
            session_cookie = http.cookies.get("session_id") or session_cookie
            payload: Any = info.json()
            data = payload.get("result") if isinstance(payload, dict) else None
            if not isinstance(data, dict):
                return None
            uid = int(data.get("uid") or 0)
            login = str(data.get("username") or "")
            if uid <= 0 or not login:
                return None
            display_name = str(data.get("name") or login)
            identity = UserIdentity(login=login, uid=uid, display_name=display_name)
            return session_cookie, identity
        except (OdooMcpGuardError, httpx.HTTPError, ValueError) as exc:
            # One neutral outcome for every failure mode; the type name
            # carries no secret and the token is never part of any message.
            logger.info("gateway: Microsoft SSO exchange failed (%s)", type(exc).__name__)
            return None
        finally:
            await http.aclose()

    return MicrosoftSso(discover=discover, exchange=exchange)


def make_microsoft_provider(profile: ProfileConfig) -> MicrosoftLoginProvider | None:
    """Build a ready Microsoft login provider for one profile, or ``None``.

    Returns a bound-ready :class:`MicrosoftLoginProvider` wrapping the
    production discovery/exchange callables. (Discovery is lazy — the button
    only appears if a provider is actually discoverable at request time — so
    this always returns a provider; the ``| None`` return keeps the seam open
    for a future "SSO disabled by config" short-circuit.)

    Example:
        >>> # providers = [p for p in (make_microsoft_provider(profile),) if p]
    """
    return MicrosoftLoginProvider(make_microsoft_sso(profile))
