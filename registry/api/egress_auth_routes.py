"""Egress credential vault API routes.

Phase 3 ships only the internal vend endpoint used by auth_server's mcp_proxy
hop. The public operator/end-user endpoints (configure, consent-initiate,
callback, connections, disconnect) are added in Phase 4.

Security model for POST /internal/egress-token (B2-1/B2-3/B2-4):
- validate_internal_auth gates the caller (auth_server presents a fresh
  mcp-registry-audience service token) -- bound to the internal network.
- The forwarded X-Internal-Token (the mcp-proxy token /validate minted) is
  RE-VERIFIED here (B2-3); sub + auth_method are taken from the verified claims,
  never from the request body.
- Non-per-user auth_method is rejected (B2-1) so a static-key/federation caller
  can never address a per-user vault bucket.
- claims["upstream_url"] is cross-checked against the server's registered
  proxy_pass_url union (B2-4a) so a forged X-Resolved-Upstream (minted via a
  direct /validate call) cannot vend a token to an attacker-controlled host.
"""

import logging
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from registry.auth.internal import validate_internal_auth
from registry.auth.proxied_token import verify_mcp_proxy_token
from registry.core.config import settings
from registry.egress_auth.factory import get_egress_auth_service
from registry.egress_auth.service import is_per_user_auth_method
from registry.repositories.factory import get_server_repository

logger = logging.getLogger(__name__)

router = APIRouter()


class EgressTokenRequest(BaseModel):
    """Body for POST /internal/egress-token.

    server_path identifies the registered server whose egress config + upstream
    allowlist the vend is checked against. Identity (sub/auth_method) is NOT in
    the body -- it is re-derived from the forwarded mcp-proxy token (B2-3).
    """

    server_path: str


class EgressTokenResponse(BaseModel):
    """Vend result. ``access_token`` is None on a clean miss (consent required)."""

    access_token: str | None = None
    consent_required: bool = False


def _base_url(url: str) -> str:
    """scheme://host[:port] of a URL, lowercased -- the comparison surface for B2-4.

    The mcp_proxy sub-path append is confined to the bound host, so the cross-check
    compares the BASE (scheme+host+port), not the full post-append path.
    """
    p = urlparse(url)
    return f"{(p.scheme or '').lower()}://{(p.netloc or '').lower()}"


def _registered_upstreams(server: dict) -> set[str]:
    """The legal upstream base-URL set for a server: proxy_pass_url ∪ versions[*]."""
    bases: set[str] = set()
    if server.get("proxy_pass_url"):
        bases.add(_base_url(server["proxy_pass_url"]))
    for ver in server.get("versions") or []:
        ppu = (
            ver.get("proxy_pass_url")
            if isinstance(ver, dict)
            else getattr(ver, "proxy_pass_url", None)
        )
        if ppu:
            bases.add(_base_url(ppu))
    return bases


@router.post("/internal/egress-token", response_model=EgressTokenResponse)
async def vend_egress_token(
    body: EgressTokenRequest,
    _caller: Annotated[str, Depends(validate_internal_auth)],
    x_internal_token: Annotated[str | None, Header(alias="X-Internal-Token")] = None,
) -> EgressTokenResponse:
    """Vend a per-user egress access token for the mcp_proxy hop.

    Returns 401 if the feature is off or the forwarded mcp-proxy token is
    missing/invalid; a clean miss (no connection, non-per-user caller, upstream
    mismatch, etc.) returns ``consent_required=True`` with no token.
    """
    if not settings.egress_auth_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="egress auth disabled")

    if not x_internal_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="missing X-Internal-Token")

    # B2-3: independently re-verify the mcp-proxy token; identity is the verified
    # claim, never an asserted body field.
    claims = verify_mcp_proxy_token(x_internal_token)
    sub = claims.get("sub") or ""
    auth_method = claims.get("auth_method") or ""
    token_upstream = claims.get("upstream_url") or ""

    # B2-1: only real per-user principals may vend.
    if not is_per_user_auth_method(auth_method):
        logger.info("egress vend: non-per-user auth_method %r -> consent", auth_method)
        return EgressTokenResponse(consent_required=True)

    server = await get_server_repository().get(body.server_path)
    if server is None:
        return EgressTokenResponse(consent_required=True)

    # Per-server enablement: a misconfigured/half-deleted server never vends.
    if server.get("egress_auth_mode") != "oauth_user" or not server.get("egress_oauth"):
        return EgressTokenResponse(consent_required=True)

    # B2-4a: the bound upstream MUST match a registered upstream for this server.
    # Closes the forged-X-Resolved-Upstream exfil (a direct /validate caller can
    # otherwise mint a signed token pointing at an attacker host).
    legal = _registered_upstreams(server)
    if _base_url(token_upstream) not in legal:
        logger.warning(
            "egress vend REFUSED: upstream %r not in registered set %r for %s",
            _base_url(token_upstream),
            legal,
            body.server_path,
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="upstream not registered for this server"
        )

    egress_oauth = server["egress_oauth"]
    access_token = await get_egress_auth_service().get_valid_token(
        auth_method=auth_method,
        user_id=sub,
        server_path=body.server_path,
        egress_oauth=egress_oauth,
    )
    if access_token is None:
        return EgressTokenResponse(consent_required=True)
    return EgressTokenResponse(access_token=access_token)
