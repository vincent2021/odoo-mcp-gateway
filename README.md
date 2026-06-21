# odoo_mcp_gateway — Microsoft-SSO add-on (BUSL-1.1) for `odoo-mcp-guard`

This is its **own repository** (`odoo-mcp-gateway`, package `odoo_mcp_gateway`,
**BUSL-1.1**). It is the non-MIT add-on that plugs **Microsoft SSO login**
(ADR-018/019) into the team gateway. Business users sign in with their usual
Odoo identity via Microsoft, through the gateway's OAuth 2.1 + PKCE browser
flow; every tool call then runs against Odoo **as that user** (Odoo ACLs,
record rules, multi-company all apply per user; the policy file restricts on
top; audit is nominative).

## What lives where (after the open-core re-carve)

The **MIT team gateway itself** — the OAuth 2.1 authorization server, per-user
Odoo execution, vault, and identity types — lives in the **core** at
`odoo_mcp_guard.server.gateway` (and `odoo_mcp_guard.server.identity`). This
add-on contributes **only** the pluggable Microsoft `LoginProvider`.

So the open-core boundary is: OAuth AS + password/API-key broker = **MIT core**;
Microsoft SSO = **this BUSL-1.1 add-on**. See `odoo-mcp-core` ADR-019/020.

## Dependency direction

`odoo_mcp_gateway` **imports the MIT core, unmodified**; the core only
**optionally** imports this package (a function-local, `try/except ImportError`
import on the gateway path of `serve.py` — absent ⇒ password/API-key login only).
The core is consumed via a path source in dev (`../odoo-mcp-core`, editable) and
a pinned release in CI/prod.

What it consumes from the core (all public):
- `odoo_mcp_guard.server.gateway.auth.LoginProvider` / `LoginButton` — the
  pluggable-login seam this add-on implements (re-exported here for consumers).
- `odoo_mcp_guard.odoo.detect.make_session_client` (+ `SessionClient`) — the
  generic Odoo web-session client used by the `odoo_session` auth method.
- `odoo_mcp_guard.config` / `.errors` / `.audit` and the `odoo` client layer.

## Package contents

| Module | Role |
|---|---|
| `odoo_mcp_gateway/microsoft.py` | `MicrosoftLoginProvider` (the `LoginProvider` impl), `MicrosoftSso` (discovery + fragment-relay callback + exchange against Odoo's `auth_oauth`), and `make_microsoft_provider` (the factory `serve --gateway` calls). |

That's the whole package — `__init__.py` re-exports the provider plus the core's
`LoginProvider`/`LoginButton` for a coherent public surface.

## How it is wired

The core's `serve.py`, on the `--gateway` path, optionally builds the provider:

```python
# odoo_mcp_guard/server/serve.py (gateway path, wrapped in try/except)
from odoo_mcp_gateway.microsoft import make_microsoft_provider
```

If this package is installed, "Se connecter avec Microsoft" appears on the
gateway login page; if not, the gateway runs password/API-key only.

## Develop

```bash
uv sync --all-extras      # installs the core (editable, ../odoo-mcp-core) + dev deps
uv run ruff check . && uv run mypy && uv run pytest
```

The Odoo version matrix used by integration work is shared from the core:
`./scripts/odoo-matrix.sh up 19` (delegates to `../odoo-mcp-core/odoo-matrix/`).
