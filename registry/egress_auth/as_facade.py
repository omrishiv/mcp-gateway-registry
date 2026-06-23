"""Egress server-path + config helpers (shared by the egress consent routes).

These are the small pure helpers the egress consent flow needs: canonicalizing a
server path and deciding whether a server is wired for per-user OAuth egress.

HISTORY
-------
This module previously implemented a full OAuth Authorization-Server facade
(RFC 9728 PRM, RFC 8414 metadata, RFC 7591 DCR, and a single-use auth-code
store) so an IDE could discover the gateway as an AS and drive third-party
consent via an ``401 + WWW-Authenticate`` challenge. That surface was removed
when the egress consent flow switched to MCP URL-mode elicitation
(https://modelcontextprotocol.io/specification/draft/client/elicitation): the
client now performs NO OAuth itself (no discovery, no DCR, no token exchange) --
it just opens the gateway connect URL and retries. Only these path/config
helpers remain.
"""

import logging

from registry.egress_auth.providers import resolve_provider

logger = logging.getLogger(__name__)


# Standard well-known prefix for the (now-removed) per-server PRM. Retained
# because the connect route's ``_server_path_from_resource`` still defensively
# accepts a PRM document URL form when recovering a server path from a client's
# ``resource`` parameter.
PRM_WELLKNOWN_PREFIX: str = "/.well-known/oauth-protected-resource"


def _normalize_server_path(server_path: str) -> str:
    """Return the canonical leading-slash server path (e.g. ``/github``)."""
    return server_path if server_path.startswith("/") else "/" + server_path


def is_server_egress_configured(server: dict | None) -> bool:
    """True iff the server has per-user OAuth egress wired (mode + provider config)."""
    if not server:
        return False
    if server.get("egress_auth_mode") != "oauth_user":
        return False
    eo = server.get("egress_oauth")
    if not eo:
        return False
    try:
        resolve_provider(eo)
    except ValueError:
        return False
    return True
