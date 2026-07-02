# Copyright (c) 2026 Vincent Mucchielli
# SPDX-License-Identifier: BUSL-1.1
"""Self-contained test fixtures for the Microsoft SSO add-on.

Copied (minimal set) from the core's gateway test tree so this package tests
independently of the MIT core's test sources. Only the helpers ``test_ms_sso``
actually uses are included.

Provenance:
  - ``FakeClient``, ``make_base``, ``make_profile_config``, ``make_session``
    mirror ``tests.gateway.exec_fixtures`` in the core repo.
  - ``make_config``, ``register``, ``pkce_pair``, ``obtain_code``,
    ``obtain_tokens``, ``stub_validator`` (and the redirect/credential
    sentinels + ``authorize_form``) mirror ``tests.gateway.test_auth``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from odoo_mcp_guard.audit.log import AuditLogger
from odoo_mcp_guard.config import ProfileConfig
from odoo_mcp_guard.odoo.api import AggregateSpec, ConnectionInfo, Domain, VersionInfo
from odoo_mcp_guard.policy.loader import PolicyStore
from odoo_mcp_guard.server.gateway.types import GatewayConfig
from odoo_mcp_guard.server.identity import UserIdentity, UserSession
from odoo_mcp_guard.server.runtime import ProfileRuntime
from pydantic import SecretStr

# -- credential / redirect sentinels (from test_auth) --------------------------

SENTINEL_PASSWORD = "S3ntinel-Passw0rd!"
SENTINEL_API_KEY = "S3ntinel-Api-Key-0123456789"
ALLOWLISTED_REDIRECT = "https://app.example/callback"
LOOPBACK_REDIRECT = "http://127.0.0.1:49152/callback"


async def stub_validator(login: str, secret: str) -> UserIdentity | None:
    if login == "alice" and secret in (SENTINEL_PASSWORD, SENTINEL_API_KEY):
        return UserIdentity(login="alice", uid=7, display_name="Alice Doe")
    return None


def make_config() -> GatewayConfig:
    return GatewayConfig(
        enabled=True,
        token_ttl_seconds=3600,
        issuer_url="http://gateway",
        redirect_allowlist=[ALLOWLISTED_REDIRECT],
    )


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def register(client: httpx.AsyncClient, redirect_uri: str = LOOPBACK_REDIRECT) -> str:
    response = await client.post(
        "/register", json={"redirect_uris": [redirect_uri], "client_name": "Test MCP"}
    )
    assert response.status_code == 201
    return str(response.json()["client_id"])


def authorize_form(
    client_id: str,
    challenge: str,
    *,
    redirect_uri: str = LOOPBACK_REDIRECT,
    login: str = "alice",
    password: str = SENTINEL_PASSWORD,
    api_key: str = "",
) -> dict[str, str]:
    return {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": "xyz-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "login": login,
        "password": password,
        "api_key": api_key,
    }


async def obtain_code(
    client: httpx.AsyncClient, client_id: str, challenge: str, **kwargs: str
) -> str:
    response = await client.post("/authorize", data=authorize_form(client_id, challenge, **kwargs))
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["state"] == ["xyz-state"]
    return query["code"][0]


async def obtain_tokens(
    client: httpx.AsyncClient, client_id: str, code: str, verifier: str
) -> dict[str, Any]:
    response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": LOOPBACK_REDIRECT,
        },
    )
    assert response.status_code == 200, response.text
    payload: dict[str, Any] = response.json()
    return payload


# -- execution-layer fixtures (from exec_fixtures) -----------------------------

POLICY = """\
version: 1
mode: enforce
companies:
  allowed_ids: [1]
models:
  res.partner:
    read: true
    fields_deny: [comment]
    write:
      operations: [create, update, delete]
      require_confirmation: false
limits:
  max_records_per_read: 50
  max_writes_per_session: 3
  rate_limit_per_minute: 1000
audit:
  path: ./audit.jsonl
  redact_fields: [email]
"""

FIELDS_META: dict[str, dict[str, dict[str, Any]]] = {
    "res.partner": {
        "name": {"type": "char", "required": True},
        "email": {"type": "char"},
        "comment": {"type": "text"},
        "company_id": {"type": "many2one", "relation": "res.company"},
    },
}


class FakeClient:
    """In-memory OdooClient; records every call for assertions."""

    def __init__(self, label: str = "client") -> None:
        self.label = label
        self.closed = False
        self.info = ConnectionInfo(profile="default", url="https://odoo.test", db="testdb")
        self.version = VersionInfo(series="17.0", major=17)
        self.uid = 7
        self.records: dict[str, list[dict[str, Any]]] = {
            "res.partner": [
                {
                    "id": 1,
                    "name": "Azure",
                    "email": "a@x.com",
                    "comment": "secret",
                    "company_id": [1, "C1"],
                    "display_name": "Azure",
                },
            ],
        }
        self.mutations: list[tuple[str, str, Any]] = []
        self.seen_domains: list[Domain] = []

    async def connect(self) -> None: ...

    async def close(self) -> None:
        self.closed = True

    async def search_read(
        self,
        model: str,
        domain: Domain,
        *,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
        order: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        self.seen_domains.append(domain)
        rows = self.records.get(model, [])[offset : (offset + limit) if limit else None]
        if fields:
            rows = [{"id": r["id"], **{f: r.get(f) for f in fields if f in r}} for r in rows]
        return [dict(r) for r in rows]

    async def search_count(
        self, model: str, domain: Domain, *, context: dict[str, Any] | None = None
    ) -> int:
        return len(self.records.get(model, []))

    async def read(
        self,
        model: str,
        ids: list[int],
        *,
        fields: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        rows = [r for r in self.records.get(model, []) if r["id"] in ids]
        if fields:
            rows = [{"id": r["id"], **{f: r.get(f) for f in fields if f in r}} for r in rows]
        return [dict(r) for r in rows]

    async def fields_get(
        self,
        model: str,
        *,
        attributes: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, dict[str, Any]]:
        return FIELDS_META[model]

    async def read_group(
        self,
        model: str,
        domain: Domain,
        spec: AggregateSpec,
        *,
        limit: int | None = None,
        offset: int = 0,
        order: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        self.seen_domains.append(domain)
        return [{"__count": len(self.records.get(model, []))}]

    async def create(
        self, model: str, values: dict[str, Any], *, context: dict[str, Any] | None = None
    ) -> int:
        self.mutations.append(("create", model, values))
        new_id = max((r["id"] for r in self.records.get(model, [])), default=0) + 1
        self.records.setdefault(model, []).append({"id": new_id, **values})
        return new_id

    async def create_many(
        self,
        model: str,
        vals_list: list[dict[str, Any]],
        *,
        context: dict[str, Any] | None = None,
    ) -> list[int]:
        ids: list[int] = []
        for values in vals_list:
            ids.append(await self.create(model, values, context=context))
        return ids

    async def write(
        self,
        model: str,
        ids: list[int],
        values: dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> bool:
        self.mutations.append(("write", model, (ids, values)))
        return True

    async def unlink(
        self, model: str, ids: list[int], *, context: dict[str, Any] | None = None
    ) -> bool:
        self.mutations.append(("unlink", model, ids))
        return True

    async def call(
        self,
        model: str,
        method: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
    ) -> Any:
        self.mutations.append(("call", model, (method, args, kwargs)))
        return 999


def make_profile_config(name: str = "default") -> ProfileConfig:
    return ProfileConfig(
        name=name,
        url="https://odoo.test",
        db="testdb",
        username="bot@x.com",
        api_key=SecretStr("bot-service-key"),
    )


def make_session(
    uid: int,
    login: str = "alice@x.com",
    credential: str = "user-credential",
    auth_method: str = "password",
) -> UserSession:
    return UserSession(
        identity=UserIdentity(login=login, uid=uid, display_name=login.split("@")[0]),
        credential=SecretStr(credential),
        auth_method=auth_method,
    )


def make_base(tmp_path: Path, client: FakeClient | None = None) -> ProfileRuntime:
    """A 'default' base ProfileRuntime over POLICY with a tmp audit file."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY)
    store = PolicyStore(policy_path)
    audit = AuditLogger(tmp_path / "audit.jsonl", store.current.audit.redact_fields)
    return ProfileRuntime("default", client or FakeClient("base"), store, audit)
