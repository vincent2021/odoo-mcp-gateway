# Copyright (c) 2026 Vincent Mucchielli
# SPDX-License-Identifier: BUSL-1.1
"""Microsoft SSO add-on (ADR-018/019): the non-MIT add-on for the team gateway.

The MIT team gateway (OAuth 2.1 AS + per-user Odoo execution, ADR-017) now
lives in the core at :mod:`odoo_mcp_guard.server.gateway`. This package
contributes ONLY the pluggable Microsoft SSO :class:`LoginProvider`
(:mod:`odoo_mcp_gateway.microsoft`), which consumes the core gateway's
:class:`~odoo_mcp_guard.server.gateway.auth.LoginProvider` seam: a
"Se connecter avec Microsoft" button, the fragment-relay callback flow, and
the discovery/exchange against Odoo's own ``auth_oauth`` web flow.

This package depends on the MIT core; the core only OPTIONALLY imports it (a
function-local ``try/except ImportError`` on the gateway path of ``serve.py``,
so the core runs standalone without it). This is the extracted, separately
licensed (BUSL-1.1) repository; see ``README.md``.
"""

# Convenience re-exports of the core gateway's pluggable-login seam, so the SSO
# add-on presents one coherent public surface to its own consumers.
from odoo_mcp_guard.server.gateway.auth import LoginButton, LoginProvider

from odoo_mcp_gateway.microsoft import (
    MicrosoftLoginProvider,
    MicrosoftSso,
    make_microsoft_provider,
)

__all__ = [
    "LoginButton",
    "LoginProvider",
    "MicrosoftLoginProvider",
    "MicrosoftSso",
    "make_microsoft_provider",
]
