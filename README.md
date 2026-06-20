# odoo_mcp_sso — Team-gateway / Microsoft-SSO add-on for `odoo-mcp-guard`

This folder is a **self-contained, extractable package** (`odoo_mcp_sso`) that adds
team-gateway mode (ADR-017) and Microsoft SSO login (ADR-018) on top of the
`odoo-mcp-guard` core. Business users authenticate in their browser with their
usual Odoo login through an OAuth 2.1 authorization-code + PKCE flow (the
MCP-standard client flow); every tool call then executes against Odoo **as that
user** — Odoo ACLs, record rules, and multi-company all apply per user, the
policy file restricts on top, and audit lines are nominative.

## Design: it consumes the MIT core, UNMODIFIED

The dependency is strictly one-directional: **`odoo_mcp_sso` imports the core; the
core never imports `odoo_mcp_sso`** (enforced by an import-linter contract in the
root `pyproject.toml`: "Core never imports the SSO package"). The core stays
gateway-unaware — `build_server` resolves each request through a
`RequestContextResolver`, and this package supplies a `GatewayResolver` for
gateway mode while the core's default `SingleUserResolver` is untouched.

What this package consumes from the core (all public, unmodified):

- **`odoo_mcp_guard.server.context.RequestContextResolver`** — the per-request
  seam. `GatewayResolver` (in `odoo_mcp_sso.users`) implements it structurally.
- **`odoo_mcp_guard.server.identity`** — the identity contract
  (`UserIdentity`, `UserSession`, `CredentialVault`). These live in the **core**,
  not here, so the core can speak the contract without importing this package.
  `odoo_mcp_sso` re-exports them for its own consumers.
- **`odoo_mcp_guard.server.unconnected.UnconnectedClient`** — the fail-closed
  base-profile placeholder. Lives in the **core** (depends only on `errors` +
  `odoo.api`, no gateway logic).
- **`odoo_mcp_guard.odoo.session_client.SessionClient`** — stays in the **core by
  design**. It is a generic `OdooClient` over an Odoo web-session cookie with no
  gateway import; the core wires it via `odoo.detect.make_session_client`, and the
  SSO package consumes it through that core function (Microsoft SSO `odoo_session`
  auth method). It is NOT moved into this package.
- `odoo_mcp_guard.config` (`ProfileConfig`, `load_profile`), `odoo_mcp_guard.errors`,
  `odoo_mcp_guard.audit`, and the `odoo` client/transport layer.

## Package contents

| Module | Role |
|---|---|
| `odoo_mcp_sso/auth.py` | OAuth 2.1 AS + PKCE, `/authorize` browser login, `/token`, RFC 8414/9728 metadata, Microsoft-SSO relay (ADR-018), `make_odoo_validator`, `make_ms_sso`, `mount_gateway`, bearer/vault middleware |
| `odoo_mcp_sso/users.py` | `UserClientPool` (per-user client cache), `GatewayResolver` (the `RequestContextResolver` impl), `GatewaySessionMissingError` |
| `odoo_mcp_sso/vault.py` | `InMemoryVault` (TTL, never persisted — Rule 1 #7) |
| `odoo_mcp_sso/types.py` | `GatewayConfig` (gateway-mode wiring; identity types live in the core) |

## How it is wired today (in-tree)

This package is a **uv workspace member** of the core repo (`[tool.uv.workspace]
members = ["SSO_MICROSOFT"]` in the root `pyproject.toml`). One
`uv sync --all-packages` installs both the core and this add-on editable, so a
single `uv run python -m pytest` from the repo root collects both core and SSO
tests (`SSO_MICROSOFT/tests` is in `testpaths`).

The gateway is activated entirely from the core's `serve.py` on the `--gateway`
path via **function-local** imports of `odoo_mcp_sso` (the only allowed
core→sso edge, whitelisted in the import-linter contract):

```python
# odoo_mcp_guard/server/serve.py (gateway path only)
from odoo_mcp_sso.users import GatewayResolver, UserClientPool
from odoo_mcp_sso.vault import InMemoryVault
from odoo_mcp_sso.auth import GatewayAuthApp, make_ms_sso, make_odoo_validator, mount_gateway
from odoo_mcp_sso.types import GatewayConfig
```

## Extracting this into its own repository later

Because the dependency is one-directional and the core is consumed unmodified,
lifting this out is mechanical:

1. **Move the folder out** of the core repo into a new repository
   (`SSO_MICROSOFT/` → the new repo root; `odoo_mcp_sso/` is the package,
   `tests/` are its tests).
2. **Replace the workspace dependency with a pinned core release.** In the new
   repo's `pyproject.toml`, drop `[tool.uv.sources] odoo-mcp-guard = { workspace
   = true }` and pin a published `odoo-mcp-guard` version (PyPI release or git
   tag). Then `pip install odoo-mcp-guard` (or `uv add`).
3. **Wire `serve` in the new repo.** The core's `serve.py` keeps only its two
   self-host transports (stdio + single-credential bearer HTTP). Move the
   `--gateway` flag and the `_build_gateway_app` / `mount_gateway` wiring into the
   new repo's own entrypoint, which calls `odoo_mcp_guard.server.app.build_server(
   runtime, resolver=GatewayResolver(...))`.
4. **`SessionClient` stays in the core** — do not copy it. The new repo reaches it
   through `odoo_mcp_guard.odoo.detect.make_session_client`, exactly as it does
   in-tree.

Nothing in the core has to change to support the move: the seam, the identity
types, and `SessionClient` are already in their permanent homes.
