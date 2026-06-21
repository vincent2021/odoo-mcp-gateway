#!/usr/bin/env bash
# Thin delegator to the canonical Odoo version matrix, which lives ONCE in the
# core repo (odoo-mcp-core/odoo-matrix/). This keeps a single source of truth:
# the same sibling-path convention as the `../odoo-mcp-core` dependency in
# pyproject.toml. All arguments are passed straight through.
#
#   ./scripts/odoo-matrix.sh up 19
#   ./scripts/odoo-matrix.sh test
#
# See odoo-mcp-core/odoo-matrix/README.md for the full command set.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE_LAUNCHER="$ROOT/../odoo-mcp-core/odoo-matrix/odoo-matrix.sh"
if [ ! -x "$CORE_LAUNCHER" ]; then
  echo "error: cannot find the core matrix launcher at:" >&2
  echo "  $CORE_LAUNCHER" >&2
  echo "Check out odoo-mcp-core next to this repo (the same sibling layout as the" >&2
  echo "'../odoo-mcp-core' path dependency in pyproject.toml)." >&2
  exit 1
fi
exec "$CORE_LAUNCHER" "$@"
