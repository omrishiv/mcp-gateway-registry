"""Shared harness that drives the real nginx render over an in-memory registry.

The property tests for nginx config generation need the genuine
``NginxConfigService._render_config_impl`` path, with the production templates,
but no Mongo, IdP, DNS or nginx binary. This module supplies that: a
``RegistrySnapshot`` describing the registry contents, ``render_config`` which
renders a template with every repository and service the render touches
replaced by in-memory fakes, and ``parse_config`` / ``flatten_tree`` which turn
the rendered text into a crossplane directive tree that tests can compare.
"""

import asyncio
import os
import tempfile
from collections.abc import Iterator
from dataclasses import (
    dataclass,
    field,
)
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import (
    AsyncMock,
    patch,
)

import crossplane

from registry.core import nginx_service as nginx_module
from registry.health.service import health_service
from registry.schemas.agent_models import AgentCard
from registry.schemas.virtual_server_models import VirtualServerConfig
from registry.services.agent_service import agent_service

REPO_ROOT: Path = Path(__file__).resolve().parents[3]
HTTP_ONLY_TEMPLATE: Path = REPO_ROOT / "docker" / "nginx_rev_proxy_http_only.conf"
HTTP_AND_HTTPS_TEMPLATE: Path = REPO_ROOT / "docker" / "nginx_rev_proxy_http_and_https.conf"
TEMPLATES: tuple[Path, ...] = (HTTP_ONLY_TEMPLATE, HTTP_AND_HTTPS_TEMPLATE)

# A non-empty ROOT_PATH makes a stray {{ROOT_PATH}} expansion visible in output.
ROOT_PATH: str = "/gw"
AUTH_SERVER_URL: str = "http://auth-server:8888"
REGISTRY_URL: str = "https://registry.example.com"
ADDITIONAL_SERVER_NAMES: str = "extra.example.com"
MARKER_SECRET: str = "nginx-marker-secret-for-render-property-tests"

# AUTH_PROVIDER is neither keycloak nor pingfederate so both IdP location
# sections (and their {{*_LOCATIONS_START}} marker comments) are stripped.
RENDER_ENV: dict[str, str] = {
    "ROOT_PATH": ROOT_PATH,
    "AUTH_PROVIDER": "cognito",
    "AUTH_SERVER_URL": AUTH_SERVER_URL,
    "KEYCLOAK_URL": "http://keycloak:8080",
    "PINGFEDERATE_BASE_URL": "http://pingfederate:9032",
    "NGINX_DISABLE_API_AUTH_REQUEST": "false",
    "TRUSTED_REAL_IP_CIDRS": "",
    "NGINX_DNS_RESOLVER": "127.0.0.11",
    "NGINX_DNS_RESOLVER_TIMEOUT": "5",
}

HEALTHY: str = "healthy"


@dataclass
class RegistrySnapshot:
    """Registry contents one render sees.

    Attributes:
        server_docs: Every server document the server repository returns, keyed
            by path (active documents and linked version documents).
        enabled_servers: The ``servers`` argument of the render (path to the
            active server document).
        health: Cached health status per server path.
        virtual_servers: Enabled virtual servers.
        agents: Enabled A2A agents keyed by registry path.
        generic_resources: Rows returned by ``_fetch_generic_proxied_resources``.
    """

    server_docs: dict[str, dict[str, Any]] = field(default_factory=dict)
    enabled_servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    health: dict[str, str] = field(default_factory=dict)
    virtual_servers: list[VirtualServerConfig] = field(default_factory=list)
    agents: dict[str, AgentCard] = field(default_factory=dict)
    generic_resources: list[dict[str, Any]] = field(default_factory=list)


class _ServerRepository:
    """In-memory server repository exposing the one read the render uses."""

    def __init__(
        self,
        docs: dict[str, dict[str, Any]],
    ) -> None:
        self._docs = docs

    async def get(
        self,
        path: str,
    ) -> dict[str, Any] | None:
        return self._docs.get(path)


class _VirtualServerRepository:
    """In-memory virtual server repository exposing ``list_enabled``."""

    def __init__(
        self,
        virtual_servers: list[VirtualServerConfig],
    ) -> None:
        self._virtual_servers = virtual_servers

    async def list_enabled(self) -> list[VirtualServerConfig]:
        return list(self._virtual_servers)


def render_settings() -> SimpleNamespace:
    """Return the settings object the render reads, with fixed test values.

    Returns:
        A namespace carrying exactly the ``settings`` attributes that
        ``registry.core.nginx_service`` reads; any other attribute access
        raises, so a new dependency surfaces as an error instead of a mock.
    """
    return SimpleNamespace(
        nginx_updates_enabled=True,
        auth_server_nginx_marker_secret=MARKER_SECRET,
        auth_server_url=AUTH_SERVER_URL,
        registry_url=REGISTRY_URL,
        a2a_reverse_proxy_effective=True,
        gateway_generic_proxy_enabled=True,
        gateway_proxy_prefix="gateway",
        gateway_generic_client_max_body_size="1m",
        gateway_generic_stream_read_timeout_seconds=3600,
        mcp_proxy_timeout=30.0,
        deployment_mode="with-gateway",
    )


async def _render_async(
    template: Path,
    registry: RegistrySnapshot,
) -> str | None:
    """Render ``template`` through the real render path with fakes installed.

    Args:
        template: nginx template file to render.
        registry: Registry contents the fakes serve.

    Returns:
        The rendered config text, or None if the render failed.
    """
    service = nginx_module.NginxConfigService()
    service.nginx_template_path = template
    agents = registry.agents

    async def _get_agent_info(path: str) -> AgentCard | None:
        return agents.get(path)

    with (
        patch.object(nginx_module, "settings", render_settings()),
        patch.dict(os.environ, RENDER_ENV),
        patch.object(health_service, "server_health_status", dict(registry.health)),
        patch.object(
            service,
            "get_additional_server_names",
            AsyncMock(return_value=ADDITIONAL_SERVER_NAMES),
        ),
        patch(
            "registry.repositories.factory.get_server_repository",
            return_value=_ServerRepository(registry.server_docs),
        ),
        patch(
            "registry.repositories.factory.get_virtual_server_repository",
            return_value=_VirtualServerRepository(registry.virtual_servers),
        ),
        patch(
            "registry.api.wellknown_routes.virtual_server_needs_per_server_prm",
            AsyncMock(return_value=False),
        ),
        patch.object(
            agent_service,
            "get_enabled_agents",
            AsyncMock(return_value=list(agents)),
        ),
        patch.object(agent_service, "get_agent_info", _get_agent_info),
        patch.object(
            nginx_module.NginxConfigService,
            "_agent_backend_resolves",
            AsyncMock(return_value=True),
        ),
        patch.object(
            nginx_module,
            "_fetch_generic_proxied_resources",
            AsyncMock(return_value=list(registry.generic_resources)),
        ),
    ):
        return await service._render_config_impl(registry.enabled_servers)


def render_config(
    template: Path,
    registry: RegistrySnapshot,
) -> str:
    """Render ``template`` for ``registry`` and return the config text.

    Args:
        template: nginx template file to render.
        registry: Registry contents the fakes serve.

    Returns:
        The rendered nginx config.

    Raises:
        RuntimeError: If the render returned None (harness or template error),
            so a broken harness is never mistaken for a property failure.
    """
    rendered = asyncio.run(_render_async(template, registry))
    if rendered is None:
        raise RuntimeError(f"render of {template.name} returned None")
    return rendered


def parse_config(
    text: str,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Parse nginx config text with crossplane.

    Args:
        text: Full nginx config.

    Returns:
        ``(tree, None)`` on success, or ``(None, error)`` with crossplane's
        error messages joined.
    """
    with tempfile.TemporaryDirectory() as directory:
        config_path = Path(directory) / "nginx.conf"
        config_path.write_text(text, encoding="utf-8")
        payload = crossplane.parse(
            str(config_path),
            single=True,
            comments=True,
            check_ctx=False,
            check_args=False,
        )
    if payload["status"] != "ok":
        errors = [error["error"] for error in payload["errors"]]
        for config in payload["config"]:
            errors.extend(error["error"] for error in config["errors"])
        return None, "; ".join(errors)
    return payload["config"][0]["parsed"], None


def flatten_tree(
    tree: list[dict[str, Any]],
    prefix: tuple[int, ...] = (),
) -> list[tuple[tuple[int, ...], str, tuple[str, ...]]]:
    """Flatten a crossplane tree into ``(position, directive, args)`` rows.

    A comment becomes a ``"#"`` row whose single argument is the comment text.
    The position is the index path from the root, so two flattened trees are
    equal only if every block holds the same directives in the same order.

    Args:
        tree: crossplane ``parsed`` list.
        prefix: Index path of ``tree`` itself.

    Returns:
        Rows in document order.
    """
    rows: list[tuple[tuple[int, ...], str, tuple[str, ...]]] = []
    for index, directive in enumerate(tree):
        position = (*prefix, index)
        name = directive["directive"]
        if name == "#":
            args: tuple[str, ...] = (directive.get("comment", ""),)
        else:
            args = tuple(directive.get("args", ()))
        rows.append((position, name, args))
        if "block" in directive:
            rows.extend(flatten_tree(directive["block"], position))
    return rows


def iter_blocks(
    tree: list[dict[str, Any]],
    name: str,
) -> Iterator[dict[str, Any]]:
    """Yield every directive called ``name`` anywhere in ``tree``.

    Args:
        tree: crossplane ``parsed`` list.
        name: Directive name to match (for example ``location``).

    Yields:
        Matching directive dicts, outermost first.
    """
    for directive in tree:
        if directive["directive"] == name:
            yield directive
        if "block" in directive:
            yield from iter_blocks(directive["block"], name)
